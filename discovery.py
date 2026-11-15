import ipaddress
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable

import psutil
from scapy.arch.windows import get_windows_if_list
from scapy.all import ARP, Ether, srp
from scapy.config import conf

from SmartyPants import database_connection


COMMON_PORTS = {
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    1883: "MQTT",
    5000: "Device API",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
    9100: "JetDirect",
    32400: "Plex",
}


@dataclass(frozen=True)
class DiscoveredDevice:
    ip_address: str
    mac_address: str
    hostname: str | None = None
    manufacturer: str | None = None


@dataclass(frozen=True)
class OpenPort:
    ip_address: str
    port_number: int
    service_name: str
    banner: str | None = None
    risk_level: str = "Info"


def get_local_network() -> ipaddress.IPv4Network:
    configured_network = os.getenv("SMARTYPANTS_NETWORK")
    if configured_network:
        network = ipaddress.ip_network(configured_network, strict=False)
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("SMARTYPANTS_NETWORK must be an IPv4 network")
        return network

    default_route_address = _get_default_route_address()

    for addresses in psutil.net_if_addrs().values():
        for address in addresses:
            if address.family != socket.AF_INET:
                continue
            if not address.address or not address.netmask:
                continue

            ip_address = ipaddress.ip_address(address.address)
            if ip_address != default_route_address:
                continue

            network = ipaddress.ip_network(
                f"{address.address}/{address.netmask}", strict=False
            )
            if network.is_private:
                return network

    raise RuntimeError("Could not determine a private local IPv4 network")


def _get_default_route_address() -> ipaddress.IPv4Address:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return ipaddress.IPv4Address(sock.getsockname()[0])
    finally:
        sock.close()


def discover_devices(network: ipaddress.IPv4Network) -> list[DiscoveredDevice]:
    interface = _get_scapy_interface(network)
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    answered, _ = srp(request, iface=interface, timeout=3, verbose=False)

    return [
        DiscoveredDevice(
            ip_address=received.psrc,
            mac_address=received.hwsrc.upper(),
            hostname=_resolve_hostname(received.psrc),
            manufacturer=_resolve_manufacturer(received.hwsrc),
        )
        for _, received in answered
    ]


def _resolve_hostname(ip_address: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.gaierror, socket.herror, socket.timeout, OSError):
        return None


def _resolve_manufacturer(mac_address: str) -> str | None:
    manufacturer = conf.manufdb._get_short_manuf(mac_address)
    return manufacturer or None


def _get_scapy_interface(network: ipaddress.IPv4Network) -> str:
    for interface in get_windows_if_list():
        for address in interface.get("ips", []):
            try:
                ip_address = ipaddress.ip_address(address)
            except ValueError:
                continue

            if isinstance(ip_address, ipaddress.IPv4Address) and ip_address in network:
                return interface["name"]

    raise RuntimeError(f"Could not find a Scapy interface for {network}")


def save_devices(
    devices: Iterable[DiscoveredDevice], network: ipaddress.IPv4Network
) -> int:
    devices = list(devices)
    discovered_ips = {device.ip_address for device in devices}
    saved_count = 0

    with database_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            "SELECT device_id, ip_address FROM dbo.devices WHERE is_online = 1"
        )
        known_devices = cursor.fetchall()

        for known_device in known_devices:
            try:
                known_ip = ipaddress.ip_address(known_device.ip_address)
            except ValueError:
                continue

            if known_ip in network and known_device.ip_address not in discovered_ips:
                cursor.execute(
                    """
                    UPDATE dbo.devices
                    SET is_online = 0
                    WHERE device_id = ?
                    """,
                    known_device.device_id,
                )
                cursor.execute(
                    """
                    INSERT INTO dbo.device_observations (device_id, is_online)
                    VALUES (?, 0)
                    """,
                    known_device.device_id,
                )

        for device in devices:
            cursor.execute(
                "SELECT device_id FROM dbo.devices WHERE ip_address = ?",
                device.ip_address,
            )
            existing_device = cursor.fetchone()

            if existing_device:
                cursor.execute(
                    """
                    UPDATE dbo.devices
                    SET mac_address = ?,
                        hostname = COALESCE(?, hostname),
                        manufacturer = COALESCE(?, manufacturer),
                        last_seen = SYSUTCDATETIME(),
                        is_online = 1
                    WHERE device_id = ?
                    """,
                    device.mac_address,
                    device.hostname,
                    device.manufacturer,
                    existing_device.device_id,
                )
                device_id = existing_device.device_id
            else:
                cursor.execute(
                    """
                    INSERT INTO dbo.devices
                        (ip_address, mac_address, hostname, manufacturer)
                    OUTPUT INSERTED.device_id
                    VALUES (?, ?, ?, ?)
                    """,
                    device.ip_address,
                    device.mac_address,
                    device.hostname,
                    device.manufacturer,
                )
                device_id = cursor.fetchone().device_id
                saved_count += 1

            cursor.execute(
                """
                INSERT INTO dbo.device_observations (device_id, is_online)
                VALUES (?, 1)
                """,
                device_id,
            )

        connection.commit()

    return saved_count


def _check_port(ip_address: str, port_number: int) -> OpenPort | None:
    try:
        with socket.create_connection((ip_address, port_number), timeout=0.5) as connection:
            connection.settimeout(0.25)
            try:
                banner = connection.recv(512).decode("utf-8", errors="replace").strip()
            except (ConnectionError, OSError, socket.timeout):
                banner = None

            return OpenPort(
                ip_address=ip_address,
                port_number=port_number,
                service_name=COMMON_PORTS[port_number],
                banner=banner[:500] if banner else None,
                risk_level=_risk_level(port_number),
            )
    except (ConnectionError, OSError, socket.timeout):
        return None


def _risk_level(port_number: int) -> str:
    if port_number == 23:
        return "High"
    if port_number in {80, 1883, 5000, 8080, 9100}:
        return "Medium"
    return "Info"


def scan_open_ports(devices: Iterable[DiscoveredDevice]) -> list[OpenPort]:
    targets = [
        (device.ip_address, port_number)
        for device in devices
        for port_number in COMMON_PORTS
    ]
    open_ports: list[OpenPort] = []

    with ThreadPoolExecutor(max_workers=32) as executor:
        checks = {
            executor.submit(_check_port, ip_address, port_number): (
                ip_address,
                port_number,
            )
            for ip_address, port_number in targets
        }

        for check in as_completed(checks):
            open_port = check.result()
            if open_port is None:
                continue

            open_ports.append(open_port)

    return sorted(open_ports, key=lambda port: (port.ip_address, port.port_number))


def save_open_ports(
    open_ports: Iterable[OpenPort], devices: Iterable[DiscoveredDevice]
) -> int:
    open_ports = list(open_ports)
    devices = list(devices)

    with database_connection() as connection:
        cursor = connection.cursor()
        device_ids: dict[str, int] = {}

        for device in devices:
            cursor.execute(
                "SELECT device_id FROM dbo.devices WHERE ip_address = ?",
                device.ip_address,
            )
            saved_device = cursor.fetchone()
            if saved_device:
                device_ids[device.ip_address] = saved_device.device_id

        for device_id in device_ids.values():
            cursor.execute(
                "DELETE FROM dbo.open_ports WHERE device_id = ?",
                device_id,
            )

        for open_port in open_ports:
            device_id = device_ids.get(open_port.ip_address)
            if device_id is None:
                continue

            cursor.execute(
                """
                INSERT INTO dbo.open_ports
                    (device_id, port_number, protocol, service_name, banner, risk_level)
                VALUES (?, ?, 'TCP', ?, ?, ?)
                """,
                device_id,
                open_port.port_number,
                open_port.service_name,
                open_port.banner,
                open_port.risk_level,
            )

        connection.commit()

    return len(open_ports)


def scan_and_save() -> tuple[ipaddress.IPv4Network, int, int, int]:
    network = get_local_network()
    devices = discover_devices(network)
    new_device_count = save_devices(devices, network)
    open_ports = scan_open_ports(devices)
    save_open_ports(open_ports, devices)
    return network, len(devices), new_device_count, len(open_ports)


if __name__ == "__main__":
    discovered_network, device_count, new_device_count, open_port_count = scan_and_save()
    print(f"Scanned {discovered_network}")
    print(f"Discovered {device_count} device(s); {new_device_count} new device(s)")
    print(f"Found {open_port_count} open TCP port(s)")
