"""
Maintains the global state in a singleton design pattern.

"""
import threading
import queue


# Should be held whenever accessing the global state's variables.
global_state_lock = threading.Lock()

# Network variables
host_ip_addr = ''
host_mac_addr = ''
host_active_interface = ''
gateway_ip_addr = ''
ip_range = []

# Database connection and lock
db_conn_and_lock = None

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

