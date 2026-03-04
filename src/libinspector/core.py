"""
Inspector Core Module.

This module serves as the main entry point and orchestrator for the Inspector application.
It initializes logging, sets up the database, configures networking, and starts all core
background threads for device discovery, packet collection, processing, spoofing, and
network service discovery (mDNS, SSDP/UPnP). It also provides a command-line interface
for running Inspector as a standalone application.

Functions:
    start_threads(custom_packet_callback_func=None): Initializes and starts all Inspector threads.
    clean_up(): Disables IP forwarding and performs cleanup tasks.
    main(): Runs Inspector as a standalone application, handling process lifecycle and shutdown.

Dependencies:
    logging, time, os, sys, global_state, mem_db, networking, safe_loop, arp_scanner,
    packet_collector, packet_processor, arp_spoof, ssdp_discovery, mdns_discovery

Typical usage:
    python -m libinspector.core
"""
import logging
import time
import sys
from typing import Callable, Optional
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
from . import common

LOG_FILE = 'inspector.log'

logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

def start_threads(custom_packet_callback_func: Optional[Callable] = None):
    """
    Initialize and starts all core Inspector threads and services.

    This function ensures only one instance of Inspector is running, initializes the
    in-memory database, configures networking (including enabling IP forwarding),
    and launches background threads for:
      - Periodic network info updates
      - ARP-based device discovery
      - Packet collection and processing
      - ARP spoofing
      - mDNS and SSDP/UPnP device discovery

    Args:
        custom_packet_callback_func (callable, optional): A user-supplied callback function
            to process packets. If provided, it will be used by the packet processor.
    """
    # Make sure that only one single instance of Inspector core is running
    with global_state.global_state_lock:
        if global_state.inspector_started[0]:
            logger.error('[core] Another instance of Inspector is already running. Aborted.')
            return
        global_state.inspector_started[0] = True
        global_state.inspector_started_ts = time.time()
        global_state.custom_packet_callback_func = custom_packet_callback_func

    logger.info('[core] Starting Inspector')

    # Initialize the database
    logger.info('[core] Initializing the database')
    conn, exclusive_lock = mem_db.initialize_db()

    with global_state.global_state_lock:
        global_state.db_conn_and_lock = (conn, exclusive_lock)

    # Initialize the networking variables
    logger.info('[core] Initializing the networking variables')

    try:
        networking.enable_ip_forwarding()
        networking.update_network_info()
    except RuntimeError:
        logger.exception("Aborting startup")
        with global_state.global_state_lock:
            global_state.inspector_started[0] = False
        raise

    logger.info('[core] Starting threads')

    threads = [
        # Update the network info from the OS every 60 seconds
        safe_loop.SafeLoopThread(networking.update_network_info, name="networking", sleep_time=60),
        # Discover devices on the network every 10 seconds
        safe_loop.SafeLoopThread(arp_scanner.start, name="arp_scanner", sleep_time=10),
        # Collect and process packets from the network
        safe_loop.SafeLoopThread(packet_collector.start, name="packet_collector"),
        safe_loop.SafeLoopThread(packet_processor.start, name="packet_processor"),
        safe_loop.SafeLoopThread(packet_processor.update_hostnames_in_flows, name="hostname_updater", sleep_time=5),
        # Spoof internet traffic
        safe_loop.SafeLoopThread(arp_spoof.start, name="arp_spoof", sleep_time=10),
        # Start the mDNS and UPnP scanner threads
        safe_loop.SafeLoopThread(ssdp_discovery.start, name="ssdp_discovery", sleep_time=5),
        safe_loop.SafeLoopThread(mdns_discovery.start, name="mdns_discovery", sleep_time=5)
    ]

    with global_state.global_state_lock:
        global_state.active_threads.extend(threads)
    logger.info('[core] Inspector started')


def clean_up():
    """
    Disables IP forwarding and performs any necessary cleanup before shutdown.

    This function should be called before exiting the Inspector application to
    restore system networking settings to their original state.
    """
    with global_state.global_state_lock:
        global_state.is_running = False

    threads_to_kill = []
    with global_state.global_state_lock:
        threads_to_kill = global_state.active_threads

    for th in threads_to_kill:
        logger.info(f"[core] Stopping thread: {th.name}")
        th.stop()

    for th in threads_to_kill:
        th.join(timeout=1)

    for th in threads_to_kill:
        status = "SUCCESS" if not th.is_alive() else "HANGING"
        msg = f"[core] {status}: Thread '{th.name}'"
        logger.info(msg)

    try:
        networking.disable_ip_forwarding()
    except RuntimeError:
        logger.exception("Error occurred while disabling IP forwarding during cleanup.")
    logging.shutdown()


def main():
    """
    Run Inspector as a standalone application from the command line.

    This function checks for root privileges, starts all Inspector threads,
    and enters a loop to keep the application running until interrupted or
    signaled to stop. Handles graceful shutdown on KeyboardInterrupt.
    """
    # Ensure that we are running as root
    if not common.is_admin():
        logger.error('[networking] Inspector must be run as root to enable IP forwarding.')
        sys.exit(1)

    start_threads()

    # Loop until the user quits
    try:
        while True:
            time.sleep(1)
            if not common.inspector_is_running():
                break

    except KeyboardInterrupt:
        pass

    clean_up()


if __name__ == '__main__':
    main()