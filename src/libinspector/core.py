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


def start_threads():

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
        global_state.db_conn_and_lock = mem_db.init_db()

    # Initialize the networking variables
    logger.info('[core] Initializing the networking variables')

    networking.enable_ip_forwarding()
    networking.update_network_info()

    logger.info('[core] Starting threads')

    # Update the network info from the OS every 60 seconds
    safe_loop.SafeLoopThread(networking.update_network_info, sleep_time=60)



    # Discover devices on the network every 10 seconds
    safe_loop.SafeLoopThread(arp_scanner.start, sleep_time=10)


    core.common.SafeLoopThread(core.arp_scanner.start_arp_scanner, sleep_time=5)
    core.common.SafeLoopThread(core.packet_collector.start_packet_collector, sleep_time=0)
    core.common.SafeLoopThread(core.packet_processor.process_packet, sleep_time=0)
    core.common.SafeLoopThread(core.arp_spoofer.spoof_internet_traffic, sleep_time=5)
    core.common.SafeLoopThread(core.friendly_organizer.add_hostname_info_to_flows, sleep_time=5)
    core.common.SafeLoopThread(core.friendly_organizer.add_product_info_to_devices, sleep_time=5)
    core.common.SafeLoopThread(core.data_donation.start, sleep_time=15)

    core.common.log('[core] Inspector started')



def clean_up():

    core.networking.disable_ip_forwarding()


def init():
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