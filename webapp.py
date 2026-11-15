from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from SmartyPants import database_connection


app = FastAPI(title="SmartyPants", description="Local IoT network inventory")


HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SmartyPants Network Inventory</title>
    <style>
        body { font-family: Segoe UI, sans-serif; margin: 2rem; color: #202124; }
        h1 { margin-bottom: .25rem; }
        .summary { color: #5f6368; margin-bottom: 1.5rem; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #dadce0; padding: .6rem; text-align: left; }
        th { background: #f1f3f4; }
        tr.online td:first-child { border-left: 4px solid #188038; }
        tr.offline td:first-child { border-left: 4px solid #d93025; }
        .empty { color: #5f6368; }
    </style>
</head>
<body>
    <h1>SmartyPants Network Inventory</h1>
    <div class="summary">Local read-only dashboard</div>
    <div id="content" class="empty">Loading inventory...</div>
    <script>
        async function loadDevices() {
            const response = await fetch('/api/devices');
            const devices = await response.json();
            if (!devices.length) {
                document.getElementById('content').textContent = 'No devices found.';
                return;
            }
            const headers = ['IP address', 'MAC address', 'Hostname', 'Manufacturer', 'Status', 'Open ports'];
            const table = document.createElement('table');
            const head = table.createTHead().insertRow();
            headers.forEach(header => {
                const cell = document.createElement('th');
                cell.textContent = header;
                head.appendChild(cell);
            });
            const body = table.createTBody();
            devices.forEach(device => {
                const row = body.insertRow();
                row.className = device.is_online ? 'online' : 'offline';
                [device.ip_address, device.mac_address, device.hostname || '',
                 device.manufacturer || '', device.is_online ? 'Online' : 'Offline',
                 device.open_ports].forEach(value => {
                    const cell = row.insertCell();
                    cell.textContent = value;
                });
            });
            document.getElementById('content').replaceWith(table);
        }
        loadDevices().catch(() => {
            document.getElementById('content').textContent = 'Unable to load the inventory.';
        });
    </script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return HTML_PAGE


@app.get("/api/devices")
def devices() -> list[dict[str, object]]:
    with database_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT device_id, ip_address, mac_address, hostname, manufacturer, is_online
            FROM dbo.devices
            ORDER BY ip_address
            """
        )
        device_rows = cursor.fetchall()

        ports_by_device: dict[int, list[str]] = {}
        cursor.execute(
            """
            SELECT device_id, port_number, service_name, risk_level
            FROM dbo.open_ports
            ORDER BY device_id, port_number
            """
        )
        for port in cursor.fetchall():
            ports_by_device.setdefault(port.device_id, []).append(
                f"{port.port_number}/{port.service_name} [{port.risk_level}]"
            )

    return [
        {
            "ip_address": row.ip_address,
            "mac_address": row.mac_address,
            "hostname": row.hostname,
            "manufacturer": row.manufacturer,
            "is_online": bool(row.is_online),
            "open_ports": ", ".join(ports_by_device.get(row.device_id, [])),
        }
        for row in device_rows
    ]
