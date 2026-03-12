"""
ARP Scanner Module

This module is responsible for discovering devices on the local network using ARP scanning.
It sends ARP requests to all IP addresses in the configured IP range from the host's active
network interface. As devices respond, their presence is detected, and the devices table is
populated or updated accordingly. The module also ensures that the default network routes
are kept up to date as new devices are discovered.

Features:
- Scans the local network for active devices using ARP.
- Populates and updates the devices table with discovered devices.
- Constantly refreshes the default routes based on network changes.
- By default, all discovered devices are set to be inspected.

Typical usage:
    This module is intended to be run periodically as a background thread by the Inspector core.

Dependencies:
    scapy, logging, global_state

Functions:
    start(): Performs an ARP scan over the configured IP range and updates device information.
"""
import scapy.all as sc
import logging
import threading
from . import global_state
from . import common

logger = logging.getLogger(__name__)


def start(stop_event: threading.Event = None, run_event: threading.Event = None):
    """
    Perform an ARP scan over the configured IP range.

    For each IP address in the range, send an ARP request from the host's active interface.
    Update the device's table and default routes as new devices are discovered.
    All devices in the IP range are inspected by default.
    """
    if run_event:
        run_event.wait()

    if not common.inspector_is_running():
        return

    # Obtain the IP range, Host Mac and Host Interface
    with global_state.global_state_lock:
        ip_range = global_state.ip_range
        host_mac_addr = global_state.host_mac_addr
        host_active_interface = global_state.host_active_interface

    logger.info(f'[ARP Scanner] Scanning {len(ip_range)} IP addresses.')

    for ip in ip_range:
        if stop_event and stop_event.is_set():
            break
        arp_pkt = sc.Ether(src=host_mac_addr, dst="ff:ff:ff:ff:ff:ff") / \
            sc.ARP(pdst=ip, hwsrc=host_mac_addr, hwdst="ff:ff:ff:ff:ff:ff")
        sc.sendp(arp_pkt, iface=host_active_interface, verbose=0)
