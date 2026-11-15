# SmartyPants

SmartyPants is a Windows-based Python application for discovering and monitoring IoT devices on a local home network.

## Current capabilities

- ARP-based local network discovery
- IP and MAC address collection
- Reverse-DNS hostname resolution
- MAC/OUI manufacturer lookup
- Online/offline tracking
- Conservative TCP scanning of common IoT ports
- SQL Server persistence
- Console inventory reports

## Requirements

- Windows
- Python 3.11 or newer
- Microsoft SQL Server or SQL Server Express
- Microsoft ODBC Driver 17 for SQL Server
- Npcap with **WinPcap API-compatible Mode** enabled
- Permission to scan and monitor the local network

## Installation

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install Python dependencies:

```powershell
python -m pip install -r requirements.txt
```

Install Npcap from [npcap.com](https://npcap.com/). During installation, enable:

```text
Install Npcap in WinPcap API-compatible Mode
```

ARP discovery may require an elevated PowerShell window.

## SQL Server configuration

The application uses Windows Authentication. Configure the SQL Server instance with environment variables before running it:

```powershell
$env:SMARTYPANTS_SQL_SERVER = 'localhost\SQLEXPRESS'
$env:SMARTYPANTS_SQL_DATABASE = 'SmartyPants'
$env:SMARTYPANTS_SQL_DRIVER = 'ODBC Driver 17 for SQL Server'
```

The database initialization script creates the `SmartyPants` database and required tables when they do not already exist:

```powershell
python .\SmartyPants.py
```

If your SQL Server instance is on another computer, replace the server value with the instance name or server address. Use a properly trusted certificate for remote deployments instead of relying on `TrustServerCertificate=yes`.

## Network configuration

The scanner normally detects the IPv4 network associated with the Windows default route. To select a specific network explicitly:

```powershell
$env:SMARTYPANTS_NETWORK = '192.168.1.0/24'
```

Only scan networks and devices that you own or are authorized to administer.

## Commands

Run a discovery scan, port scan, and report:

```powershell
python .\console.py scan
```

Display the stored inventory without scanning:

```powershell
python .\console.py report
```

Display only devices currently marked online:

```powershell
python .\console.py report --online-only
```

The scanner currently checks a limited set of common TCP ports, including HTTP, HTTPS, SSH, RTSP, MQTT, and printer services.

## Project files

```text
SmartyPants.py   SQL Server connection and schema initialization
discovery.py     Network discovery, enrichment, status tracking, and port scanning
console.py       Console commands and inventory report
requirements.txt Python dependencies
```

## Data and privacy

Device inventory, hostnames, MAC addresses, manufacturers, observations, and open-port results are stored in the configured SQL Server database. Do not commit database exports, credentials, logs, or environment files to source control.
