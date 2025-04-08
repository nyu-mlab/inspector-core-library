import logging

LOG_FILE = 'inspector.log'

logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

import time
from . import global_state
from . import mem_db
from . import networking
from . import safe_loop
from . import arp_scanner
from . import packet_collector
from . import packet_processor
from . import arp_spoof
from . import ssdp_discovery
from . import mdns_discovery


def start_threads():
    """
    Main entry point if you use libinspector in your package.

    """

    # Make sure that only one single instance of Inspector core is running
    with global_state.global_state_lock:
        if global_state.inspector_started[0]:
            logger.error('[core] Another instance of Inspector is already running. Aborted.')
            return
        global_state.inspector_started[0] = True
        global_state.inspector_started_ts = time.time()

    logger.info('[core] Starting Inspector')

    # Initialize the database
    logger.info('[core] Initializing the database')
    with global_state.global_state_lock:
        global_state.db_conn_and_lock = mem_db.initialize_db()

    # Initialize the networking variables
    logger.info('[core] Initializing the networking variables')

    networking.enable_ip_forwarding()
    networking.update_network_info()

    logger.info('[core] Starting threads')

    # Update the network info from the OS every 60 seconds
    safe_loop.SafeLoopThread(networking.update_network_info, sleep_time=60)

    # Discover devices on the network every 10 seconds
    safe_loop.SafeLoopThread(arp_scanner.start, sleep_time=10)

    # Collect and process packets from the network
    safe_loop.SafeLoopThread(packet_collector.start)
    safe_loop.SafeLoopThread(packet_processor.start)

    # Spoof internet traffic
    safe_loop.SafeLoopThread(arp_spoof.start, sleep_time=1)

    # Start the mDNS and UPnP scanner threads
    safe_loop.SafeLoopThread(ssdp_discovery.start, sleep_time=5)
    safe_loop.SafeLoopThread(mdns_discovery.start, sleep_time=5)

    logger.info('[core] Inspector started')


def clean_up():

    networking.disable_ip_forwarding()


def main():
    """
    Execute this function to start Inspector as a standalone application from the command line.

    """

    start_threads()

    # Loop until the user quits
    try:
        while True:
            time.sleep(1)
            with global_state.global_state_lock:
                if not global_state.is_running:
                    break

    except KeyboardInterrupt:
        pass

    clean_up()


if __name__ == '__main__':
    main()