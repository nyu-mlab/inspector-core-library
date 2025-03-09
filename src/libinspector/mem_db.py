"""
Defines an in-memory SQLite database for storing device, hostname, and network
flow data.

"""
import sqlite3
import threading


# Use the in-memory SQL database to store devices and network flows; defaults to True
USE_IN_MEMORY_DB = False # TODO Set to True

# Inspector should ARP spoof every device by default; defaults to False
INSPECT_EVERY_DEVICE_BY_DEFAULT = True # TODO Set to False


debug_db_path = 'debug_mem_db.db'


def initialize_db():
    """
    Returns the connection and rw_lock to an in-memory SQLite database.

    """
    db_uri = ':memory:'
    if not USE_IN_MEMORY_DB:
        db_uri = debug_db_path

    # Connect to an in-memory SQLite database
    conn = sqlite3.connect(db_uri, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Create a lock for thread-safe access
    rw_lock = threading.Lock()

    with rw_lock:
        cursor = conn.cursor()

        # Create the devices table
        cursor.execute(f'''
            CREATE TABLE devices (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT NOT NULL,
                is_inspected INTEGER DEFAULT {1 if INSPECT_EVERY_DEVICE_BY_DEFAULT else 0},
                is_gateway INTEGER DEFAULT 0,
                updated_ts INTEGER DEFAULT 0,
                metadata_json TEXT DEFAULT '{{}}'
            )
        ''')

        # Create indexes on ip_address and is_inspected separately
        cursor.execute('CREATE INDEX idx_ip_address ON devices(ip_address)')
        cursor.execute('CREATE INDEX idx_is_inspected ON devices(is_inspected)')

        # Create the hostnames table
        cursor.execute('''
            CREATE TABLE hostnames (
                device_mac_address TEXT NOT NULL,
                ip_address TEXT,
                hostname TEXT NOT NULL,
                updated_ts INTEGER DEFAULT 0,
                data_source TEXT NOT NULL,
                metadata_json TEXT DEFAULT '{}',
                PRIMARY KEY (device_mac_address, ip_address, hostname)
            )
        ''')

        # Create an index on the hostnames
        cursor.execute('CREATE INDEX idx_hostnames_hostname ON hostnames(hostname)')

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

        conn.commit()

    return conn, rw_lock

