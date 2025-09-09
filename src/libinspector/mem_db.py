"""
In-Memory SQLite Database Utilities.

This module defines and initializes an in-memory SQLite database for storing device,
hostname, and network flow data used by the Inspector application. The database schema
includes tables for devices, hostnames, and network flows, with appropriate indexes
to optimize query performance. Optionally, the database can be persisted to disk for
debugging if configured in `inspector_config.json`.

Key Features:
- In-memory or on-disk SQLite database based on configuration.
- Thread-safe access using a lock for concurrent operations.
- Tables for devices, hostnames, and network flows with relevant indexes.
- Integration with OUI vendor lookup via a custom SQLite function.
- Designed for fast, temporary storage of network monitoring data.

Intended Usage:
Call `initialize_db()` to create and access the database connection and lock.
"""
import sqlite3
import threading

from .oui_parser import get_vendor
from . import local_config


# Writes the in-memory database to disk for debugging purposes, only if the
# config "use_in_memory_db" is explicitly set to False in the
# inspector_config.json file
debug_db_path = 'debug_mem_db.db'


def initialize_db():
    """
    Initialize and returns an in-memory (or optionally on-disk) SQLite database for network data.

    This function sets up the database schema with tables for devices, hostnames, and network flows,
    including indexes for efficient querying. It also registers a custom SQLite function for OUI
    vendor lookup. Thread safety is provided via a lock, allowing safe concurrent access.

    Returns:
        tuple: A tuple `(conn, rw_lock)` where `conn` is the SQLite connection object and `rw_lock`
        is a threading.Lock instance for synchronizing database access.

    Tables Created:
        - devices: Stores MAC and IP addresses, inspection status, gateway flag, timestamps, and metadata.
        - hostnames: Maps IP addresses to hostnames, with update timestamps and metadata.
        - network_flows: Records network flow data with source/destination info, ports, protocol, and statistics.

    Indexes:
        - On device IP address and inspection status.
        - On network flow source/destination IP addresses and hostnames.

    Notes:
        - If `use_in_memory_db` is False in the configuration, the database is persisted to `debug_mem_db.db`.
        - The function must be called before any database operations are performed.
    """
    db_uri = ':memory:'
    if not local_config.get('use_in_memory_db', True):
        db_uri = debug_db_path

    # Connect to an in-memory SQLite database
    conn = sqlite3.connect(db_uri, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row

    # Create a lock for thread-safe access
    rw_lock = threading.Lock()

    # Should we arp-spoof every device we discovered via ARP scanning?
    inspect_every_device_by_default = local_config.get('inspect_every_device_by_default', False)

    with rw_lock:
        cursor = conn.cursor()

        # Create the devices table
        cursor.execute(f'''
            CREATE TABLE devices (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT NOT NULL,
                is_inspected INTEGER DEFAULT {1 if inspect_every_device_by_default else 0},
                is_gateway INTEGER DEFAULT 0,
                updated_ts INTEGER DEFAULT 0,
                metadata_json TEXT DEFAULT '{{}}'
            )
        ''')

        # Create indexes on ip_address and is_inspected separately
        cursor.execute('CREATE INDEX idx_devices_ip_address ON devices(ip_address)')
        cursor.execute('CREATE INDEX idx_devices_is_inspected ON devices(is_inspected)')

        # Create the hostnames table
        cursor.execute('''
            CREATE TABLE hostnames (
                ip_address TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                updated_ts INTEGER DEFAULT 0,
                data_source TEXT NOT NULL,
                metadata_json TEXT DEFAULT '{}'
            )
        ''')

        # Create the network flows table, with a compound primary key as the flow_key
        cursor.execute('''
            CREATE TABLE network_flows (
                timestamp INTEGER,
                src_ip_address TEXT,
                dest_ip_address TEXT,
                src_hostname TEXT,
                dest_hostname TEXT,
                src_mac_address TEXT,
                dest_mac_address TEXT,
                src_port TEXT,
                dest_port TEXT,
                protocol TEXT,
                byte_count INTEGER DEFAULT 0,
                packet_count INTEGER DEFAULT 0,
                metadata_json TEXT DEFAULT '{}',
                PRIMARY KEY (
                       timestamp,
                       src_mac_address, dest_mac_address,
                       src_ip_address, dest_ip_address,
                       src_port, dest_port,
                       protocol
                    )
            )
        ''')

        # Create indexes on src_ip_address, dest_ip_address, src_hostname, dest_hostname and timestamp
        cursor.execute('CREATE INDEX idx_network_flows_src_ip_address ON network_flows(src_ip_address)')
        cursor.execute('CREATE INDEX idx_network_flows_dest_ip_address ON network_flows(dest_ip_address)')
        cursor.execute('CREATE INDEX idx_network_flows_src_hostname ON network_flows(src_hostname)')
        cursor.execute('CREATE INDEX idx_network_flows_dest_hostname ON network_flows(dest_hostname)')
        cursor.execute('CREATE INDEX idx_network_flows_timestamp ON network_flows(timestamp)')

        # Define a SQLite UDF to parse the OUI from the MAC address
        conn.create_function('get_oui_vendor', 1, get_vendor)

    return conn, rw_lock

