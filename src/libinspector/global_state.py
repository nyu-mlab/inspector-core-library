"""
Global State Management (Singleton Pattern).

This module maintains the global state for the Inspector application using a singleton-like approach.
It provides thread-safe access to shared variables that are used across different components of the system,
including networking information, application status flags, database connections, and packet processing queues.

Features:
- Thread-safe access to all global state variables via `global_state_lock`.
- Stores host network information (IP, MAC, interface, gateway, IP range).
- Manages the in-memory database connection and lock.
- Tracks application lifecycle and inspection mode status.
- Ensures only one instance of the Inspector core is running at a time.
- Provides a queue for packet processing and supports a custom packet callback.

Variables:
    global_state_lock (threading.Lock): Lock for synchronizing access to global state.
    host_ip_addr (str): Host machine's IP address.
    host_mac_addr (str): Host machine's MAC address.
    host_active_interface (str): Name of the active network interface.
    gateway_ip_addr (str): Default gateway IP address.
    ip_range (list): List of IP addresses in the local network range.
    db_conn_and_lock (tuple or None): In-memory database connection and its lock.
    read_only_db_lock (threading.RLock): Lock for read-only database operations, allowing concurrent reads (threading.RLock).
    is_running (bool): Indicates if the application is running.
    is_inspecting (bool): Indicates if inspection mode is enabled.
    inspector_started (list): Singleton flag to ensure only one Inspector instance.
    inspector_started_ts (float): Timestamp when Inspector was started.
    packet_queue (queue.Queue): Queue for packets to be processed.
    custom_packet_callback_func (callable or None): Custom callback for packet processing.
    labeling_target_mac (str or None): The MAC address of the device currently undergoing a labeling session.
    labeling_activity_name (str or None): The user-selected activity label for the current session.
    labeling_session_start_ts (int or None): The epoch timestamp when labeling packet collection officially began.
    system_has_npcap (bool): Flag set at startup confirming Npcap/WinPcap is installed.
    packet_collector_status (str): Status string of the packet collection thread (e.g., "Running", "Error").
    last_error_message (str or None): Stores the most recent critical error message from any background thread.
    packet_processor_thread (threading.Thread or None): Reference to the main packet processing thread object.
    device_discovery_complete (bool): Flag set after the initial network scan is complete.
Usage:
    Import this module and use the provided variables to access or modify global state.
    Always acquire `global_state_lock` before accessing or modifying any global state variable.
"""
import threading
import queue
from typing import Callable, Any, Tuple

# Should be held whenever accessing the global state's variables.
global_state_lock = threading.Lock()

# Network variables set up update_network_info
host_ip_addr = ''
host_mac_addr = ''
host_active_interface = ''
gateway_ip_addr = ''
ip_range = []

# In-memory database connection and lock (Exclusive WRITE Lock)
db_conn_and_lock: Tuple[Any, threading.Lock] | None = None

# In-memory database connection and RLock (Concurrent READ Lock)
# This variable replaces the old standalone read_only_db_lock.
db_conn_and_read_only_lock: Tuple[Any, threading.RLock] | None = None

# Whether the application is running or not. True by default; if false, the
# entire application shuts down.
is_running = True

# Whether inspection mode is enabled or not. True by default; if not, stops all
# inspection. Does not change the is_inspected state in the devices table.
is_inspecting = True

# Make sure that only one single instance of Inspector core is running
inspector_started = [False]
inspector_started_ts = 0

# A queue that holds packets to be processed
packet_queue = queue.Queue()

# A custom callback function for packet processing (runs in background thread)
custom_packet_callback_func: Callable[[Any], None] | None = None

# =========================================================================
# NEW: Thread-Safe Labeling Variables
# These variables eliminate the unsafe reliance on st.session_state
# in IoT Inspector v3
# =========================================================================

# The MAC address of the device currently undergoing a labeling session.
labeling_target_mac: str | None = None

# The IP address of the device currently undergoing a labeling session.
labeling_target_ip: str | None = None

# The user-selected activity label for the current session.
labeling_activity_name: str | None = None

# The epoch timestamp when the labeling packet collection officially began.
labeling_session_start_ts: int | None = None

# The epoch timestamp when the labeling packet collection officially ended.
labeling_session_end_ts: int | None = None

# =========================================================================
# NEW: Application Status and Monitoring Variables
# =========================================================================

# Flag set at startup confirming Npcap/WinPcap is correctly installed.
system_has_npcap: bool = True

# Status string of the packet collector thread (e.g., "Running", "Error").
packet_collector_status: str = "Initializing"

# The most recent critical error message from a background thread.
last_error_message: str | None = None

# Reference to the main packet processing thread object.
packet_processor_thread: threading.Thread | None = None

# Flag set after the initial network scan is complete.
device_discovery_complete: bool = False