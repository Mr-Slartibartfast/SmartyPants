import argparse
from collections import defaultdict

from SmartyPants import database_connection
from discovery import scan_and_save


def get_report_rows(online_only: bool) -> list[tuple[str, str, str, str, str, str]]:
    device_filter = "WHERE d.is_online = 1" if online_only else ""
    query = f"""
        SELECT
            d.ip_address,
            d.mac_address,
            COALESCE(d.hostname, '') AS hostname,
            COALESCE(d.manufacturer, '') AS manufacturer,
            CASE WHEN d.is_online = 1 THEN 'Online' ELSE 'Offline' END AS status,
            COALESCE(
                STRING_AGG(
                    CASE
                        WHEN p.port_number IS NOT NULL THEN
                            CONCAT(
                                CONVERT(varchar(10), p.port_number),
                                '/',
                                p.service_name,
                                ' [',
                                p.risk_level,
                                ']'
                            )
                    END,
                    ', '
                ),
                ''
            ) AS open_ports
        FROM dbo.devices AS d
        LEFT JOIN dbo.open_ports AS p ON p.device_id = d.device_id
        {device_filter}
        GROUP BY
            d.ip_address,
            d.mac_address,
            d.hostname,
            d.manufacturer,
            d.is_online
        ORDER BY d.ip_address
    """

    with database_connection() as connection:
        return [tuple(row) for row in connection.cursor().execute(query).fetchall()]


def print_report(online_only: bool = False) -> None:
    rows = get_report_rows(online_only)
    if not rows:
        print("No devices found.")
        return

    headers = ("IP address", "MAC address", "Hostname", "Manufacturer", "Status", "Open ports")
    widths = [len(header) for header in headers]

    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))

    separator = "-+-".join("-" * width for width in widths)
    print(" | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print(separator)

    for row in rows:
        print(" | ".join(str(value).ljust(widths[index]) for index, value in enumerate(row)))

    print(f"\n{len(rows)} device(s) reported.")


def main() -> None:
    parser = argparse.ArgumentParser(description="SmartyPants IoT network console")
    parser.add_argument(
        "command",
        choices=("report", "scan"),
        nargs="?",
        default="report",
        help="report current inventory or run a scan before reporting",
    )
    parser.add_argument(
        "--online-only",
        action="store_true",
        help="show only devices currently marked online",
    )
    args = parser.parse_args()

    if args.command == "scan":
        network, device_count, new_device_count, open_port_count = scan_and_save()
        print(f"Scanned {network}")
        print(f"Discovered {device_count} device(s); {new_device_count} new device(s)")
        print(f"Found {open_port_count} open TCP port(s)\n")

    print_report(args.online_only)


if __name__ == "__main__":
    main()
