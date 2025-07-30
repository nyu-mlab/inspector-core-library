"""
Packet Collector Module for Network Inspection.

This module is responsible for capturing network packets from the active network interface
using Scapy, filtering out irrelevant traffic, and queuing packets for further analysis.
It provides functions to start the packet sniffing process, check the running state of
the Inspector, and safely add packets to a shared processing queue.

Key Features:
- Captures packets in 30-second intervals to ensure robustness against crashes.
- Excludes packets to/from the Inspector host, except for ARP packets needed for device discovery.
- Thread-safe access to global state for interface, IP address, and control flags.
- Periodically logs the size of the packet queue for monitoring.
- Designed for integration with a real-time network monitoring and analysis system.

Dependencies:
- scapy
- time
- logging

Intended Usage:
Import and invoke `start()` to begin packet collection as part of the Inspector's workflow.
"""
import scapy.all as sc
import time
import logging

from . import global_state

logger = logging.getLogger(__name__)

sc.load_layer('tls')

print_queue_size_dict = {'last_updated_ts': 0}


def start():
    """
    Continuously captures network packets from the active interface and adds them to the processing queue.

    This function acquires the Inspector's active network interface and IP address under a global lock,
    then uses Scapy's `sniff` to capture packets in 30-second intervals. The sniffing filter excludes
    packets to/from the host itself, except for ARP packets which are required for device discovery.
    Each captured packet is passed to `add_packet_to_queue`. Sniffing stops if the Inspector is no longer running.

    Returns:
        None
    """
    with global_state.global_state_lock:
        host_active_interface = global_state.host_active_interface
        host_ip_addr = global_state.host_ip_addr

    # Continuously sniff packets for 30 second intervals (as sniff might crash).
    # Also, avoid capturing packets to/from the host itself, except ARP, which
    # we need for discovery.
    sc.sniff(
        prn=add_packet_to_queue,
        iface=host_active_interface,
        stop_filter=lambda _: not inspector_is_running(),
        filter=f'(not arp and host not {host_ip_addr}) or arp',
        timeout=30
    )


def inspector_is_running() -> bool:
    """
    Check if the Inspector is currently running.

    This function acquires a global lock and returns the current running state of the Inspector,
    as indicated by the `is_running` flag in global state.

    Returns:
        bool: True if the Inspector is running, False otherwise.
    """
    with global_state.global_state_lock:
        return global_state.is_running


def add_packet_to_queue(pkt):
    """
    Add a captured packet to the global packet queue for processing.

    This function checks if packet inspection is currently enabled. If so, it puts the packet
    into the global queue for later processing. Additionally, it logs the current queue size
    every 10 seconds for monitoring purposes.

    Args:
        pkt (scapy.packet.Packet): The captured network packet to be queued.

    Returns:
        None
    """
    with global_state.global_state_lock:
        if not global_state.is_inspecting:
            return

    global_state.packet_queue.put(pkt)

    # Print the queue size every 10 seconds
    current_time = time.time()
    if current_time - print_queue_size_dict['last_updated_ts'] > 10:
        logger.info(f'[packet_collector] Packet queue size: {global_state.packet_queue.qsize()}')
        print_queue_size_dict['last_updated_ts'] = current_time