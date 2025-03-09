"""
Discovers local devices via ARP scanning. Populates the devices table with devices. Constantly updates the default routes.

By default, all devices are inspected.

"""
import scapy.all as sc
import logging
from . import global_state


logger = logging.getLogger(__name__)


def start():

    # Obtain the IP range
    with global_state.global_state_lock:
        ip_range = global_state.ip_range

    logger.info(f'[ARP Scanner] Scanning {len(ip_range)} IP addresses.')

    for ip in ip_range:

        # What is the MAC address of the host running Inspector?
        with global_state.global_state_lock:
            host_mac_addr = global_state.host_mac_addr
            host_active_interface = global_state.host_active_interface

        arp_pkt = sc.Ether(src=host_mac_addr, dst="ff:ff:ff:ff:ff:ff") / \
            sc.ARP(pdst=ip, hwsrc=host_mac_addr, hwdst="ff:ff:ff:ff:ff:ff")

        sc.sendp(arp_pkt, iface=host_active_interface, verbose=0)