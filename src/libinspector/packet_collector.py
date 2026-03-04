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
from . import common

logger = logging.getLogger(__name__)

sc.load_layer('tls')

print_queue_size_dict = {'last_updated_ts': 0}


def start(timeout: int = 10):
    with global_state.global_state_lock:
        host_active_interface = global_state.host_active_interface
        host_ip_addr = global_state.host_ip_addr

    # We want to both store and count the packets during the sniff session
    session_stats = {'count': 0}

    def add_packet_to_queue(pkt: sc.Packet):
        session_stats['count'] += 1
        global_state.packet_queue.put(pkt)

    start_ts = time.time()

    sc.sniff(
        prn=add_packet_to_queue,
        iface=host_active_interface,
        stop_filter=lambda _: not common.inspector_is_running(),
        filter=f'(not arp and host not {host_ip_addr}) or arp',
        timeout=timeout,
        store=False
    )

    # After sniff finishes (either timeout or stop_filter)
    duration = time.time() - start_ts
    count = session_stats['count']

    if count > 0:
        packet_per_second = count / duration
        logger.info(f"[packet_collector] Interval complete. Collected {count} packets (~{packet_per_second:.2f} pkt/s)")
