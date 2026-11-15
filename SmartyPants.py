import os
from contextlib import contextmanager
from typing import Iterator

import pyodbc
from dotenv import load_dotenv


load_dotenv()


SQL_SERVER = os.getenv("SMARTYPANTS_SQL_SERVER", r"localhost\SQLEXPRESS")
SQL_DATABASE = os.getenv("SMARTYPANTS_SQL_DATABASE", "SmartyPants")
SQL_DRIVER = os.getenv("SMARTYPANTS_SQL_DRIVER", "ODBC Driver 17 for SQL Server")


def _connection_string(database: str) -> str:
    return (
        f"DRIVER={{{SQL_DRIVER}}};"
        f"SERVER={SQL_SERVER};"
        f"DATABASE={database};"
        "Trusted_Connection=yes;"
        "TrustServerCertificate=yes;"
    )


def create_database_if_needed() -> None:
    with pyodbc.connect(_connection_string("master"), autocommit=True) as connection:
        connection.execute(
            f"IF DB_ID(N'{SQL_DATABASE}') IS NULL "
            f"CREATE DATABASE [{SQL_DATABASE}]"
        )


@contextmanager
def database_connection() -> Iterator[pyodbc.Connection]:
    create_database_if_needed()

    with pyodbc.connect(_connection_string(SQL_DATABASE)) as connection:
        yield connection


def initialize_database() -> None:
    schema = """
    IF OBJECT_ID(N'dbo.devices', N'U') IS NULL
    BEGIN
        CREATE TABLE dbo.devices (
            device_id INT IDENTITY(1,1) PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            mac_address VARCHAR(17) NULL,
            hostname NVARCHAR(255) NULL,
            manufacturer NVARCHAR(255) NULL,
            first_seen DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
            last_seen DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
            is_online BIT NOT NULL DEFAULT 1,
            CONSTRAINT UQ_devices_ip_address UNIQUE (ip_address)
        );
    END;

    IF OBJECT_ID(N'dbo.device_observations', N'U') IS NULL
    BEGIN
        CREATE TABLE dbo.device_observations (
            observation_id BIGINT IDENTITY(1,1) PRIMARY KEY,
            device_id INT NOT NULL,
            observed_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
            is_online BIT NOT NULL,
            latency_ms DECIMAL(10,2) NULL,
            CONSTRAINT FK_device_observations_devices
                FOREIGN KEY (device_id) REFERENCES dbo.devices(device_id)
        );
    END;

    IF OBJECT_ID(N'dbo.open_ports', N'U') IS NULL
    BEGIN
        CREATE TABLE dbo.open_ports (
            port_id BIGINT IDENTITY(1,1) PRIMARY KEY,
            device_id INT NOT NULL,
            port_number INT NOT NULL,
            protocol VARCHAR(10) NOT NULL DEFAULT 'TCP',
            service_name NVARCHAR(255) NULL,
            discovered_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
            CONSTRAINT FK_open_ports_devices
                FOREIGN KEY (device_id) REFERENCES dbo.devices(device_id),
            CONSTRAINT UQ_open_ports_device_port_protocol
                UNIQUE (device_id, port_number, protocol)
        );
    END;

    IF OBJECT_ID(N'dbo.sensors', N'U') IS NULL
    BEGIN
        CREATE TABLE dbo.sensors (
            sensor_id INT IDENTITY(1,1) PRIMARY KEY,
            device_id INT NOT NULL,
            sensor_type NVARCHAR(255) NOT NULL,
            unit_of_measurement NVARCHAR(50) NULL,
            value DECIMAL(10,2) NULL,
            recorded_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
            CONSTRAINT FK_sensors_devices
                FOREIGN KEY (device_id) REFERENCES dbo.devices(device_id)
        );
    END;

    IF OBJECT_ID(N'dbo.sensor_readings', N'U') IS NULL
    BEGIN
        CREATE TABLE dbo.sensor_readings (
            reading_id BIGINT IDENTITY(1,1) PRIMARY KEY,
            sensor_id INT NOT NULL,
            value DECIMAL(10,2) NOT NULL,
            recorded_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
            CONSTRAINT FK_sensor_readings_sensors
                FOREIGN KEY (sensor_id) REFERENCES dbo.sensors(sensor_id)
        );
    END;
    """

    with database_connection() as connection:
        connection.execute(schema)
        connection.commit()


if __name__ == "__main__":
    initialize_database()
    print(f"SmartyPants database is ready on {SQL_SERVER}: {SQL_DATABASE}")
