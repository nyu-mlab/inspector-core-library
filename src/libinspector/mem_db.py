"""
Defines an in-memory SQLite database for storing device, hostname, and network
flow data.

"""
import sqlite3
import threading



def initialize_db():
    """
    Returns the connection and rw_lock to an in-memory SQLite database.

    """
    # Connect to an in-memory SQLite database
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Create a lock for thread-safe access
    rw_lock = threading.Lock()

    with rw_lock:
        cursor = conn.cursor()

        # Create the devices table
        cursor.execute('''
            CREATE TABLE devices (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT,
                is_inspected INTEGER,
                metadata_json TEXT
            )
        ''')

        # Create indexes on ip_address and is_inspected separately
        cursor.execute('CREATE INDEX idx_ip_address ON devices(ip_address)')
        cursor.execute('CREATE INDEX idx_is_inspected ON devices(is_inspected)')

        # Create the hostnames table
        cursor.execute('''
            CREATE TABLE hostnames (
                ip_address TEXT PRIMARY KEY,
                hostname TEXT,
                data_source TEXT,
                metadata_json TEXT
            )
        ''')

        # Create the network flows table, with a compound primary key as the flow_key
        cursor.execute('''
            CREATE TABLE network_flows (
                timestamp INTEGER,
                src_ip_address TEXT,
                dest_ip_address TEXT,
                src_mac_address TEXT,
                dest_mac_address TEXT,
                src_port TEXT,
                dest_port TEXT,
                protocol TEXT,
                byte_count INTEGER,
                packet_count INTEGER,
                metadata_json TEXT,
                PRIMARY KEY (timstamp, src_ip_address, dest_ip_address, src_port, dest_port, protocol)
            )
        ''')

        conn.commit()

    return conn, rw_lock

