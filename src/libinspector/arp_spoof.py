"""
ARP Spoofing Module.

This module is responsible for sending ARP spoofing packets to devices listed in the database.
It periodically spoofs ARP tables of inspected devices and the network gateway, redirecting
traffic through the Inspector host for monitoring or manipulation purposes.

Features:
- Periodically sends ARP spoofing packets between inspected devices and the gateway.
- Ensures only inspected, non-gateway, and non-host devices are targeted.
- Handles timing to avoid excessive spoofing.
- Logs errors and spoofing activity for traceability.

Typical usage:
    This module is intended to be run as a background thread by the Inspector core.

Functions:
    start(): Main entry point to perform ARP spoofing for all eligible devices.
    send_spoofed_arp(victim_mac_addr, victim_ip_addr, gateway_mac_addr, gateway_ip_addr):
        Sends bidirectional ARP spoofing packets between a victim device and the gateway.

Dependencies:
    time, scapy, traceback, logging, global_state, networking

Note:
    You should NOT run this directly on the NYU network, you will be banned for ARP spoofing!
"""
import scapy.all as sc
import traceback
import logging

from . import global_state
from . import networking
from . import common


logger = logging.getLogger(__name__)


def start():
    """
    Perform ARP spoofing for all inspected devices in the database.

    This function:
      - Checks if inspection mode is enabled.
      - Ensures spoofing is not performed more frequently than the configured interval.
      - Retrieves all devices marked as inspected (excluding the gateway and host).
      - Obtains the gateway's MAC address.
      - Sends ARP spoofing packets between each inspected device and the gateway.
      - Logs the number of devices spoofed and any errors encountered.

    Side Effects:
        - Sends ARP packets on the network.
        - Updates the timestamp of the last spoofing operation.
        - Logs activity and errors.
    """
    if not common.inspector_is_running():
        return

    conn, rw_lock = global_state.db_conn_and_lock

    # Get all inspected devices
    inspected_device_list = []
    with rw_lock:
        sql = """
            SELECT mac_address, ip_address
            FROM devices
            WHERE is_inspected = 1 AND ip_address != '' AND mac_address != '' AND is_gateway = 0
        """
        for row in conn.execute(sql):
            # Exclude the gateway and the current host from the list
            with global_state.global_state_lock:
                if row['ip_address'] in (global_state.gateway_ip_addr, global_state.host_ip_addr):
                    continue
                if row['mac_address'] == global_state.host_mac_addr:
                    continue
            inspected_device_list.append(row)

    if len(inspected_device_list) == 0:
        return

    # Get the gateway's IP and MAC addresses
    gateway_ip_addr = global_state.gateway_ip_addr
    try:
        gateway_mac_addr = networking.get_mac_address_from_ip(gateway_ip_addr)
    except KeyError:
        logger.error(f'[arp_spoof] Gateway (ip: {gateway_ip_addr}) MAC address not found in ARP cache. Cannot spoof internet traffic yet.')
        return

    logger.info(f'[arp_spoof] Spoofing internet traffic for {len(inspected_device_list)} devices')

    # Send ARP spoofing packets for each inspected device
    spoof_count = 0
    for device_dict in inspected_device_list:
        try:
            send_spoofed_arp(device_dict['mac_address'], device_dict['ip_address'], gateway_mac_addr, gateway_ip_addr)
            spoof_count += 1
        except Exception:
            logger.error(f'[arp_spoof] Error spoofing {device_dict["mac_address"]}, {device_dict["ip_address"]} <-> {gateway_mac_addr}, {gateway_ip_addr}, because\n' + traceback.format_exc())

    logger.info(f'[arp_spoof] Spoofed internet traffic for {spoof_count} devices')


def send_spoofed_arp(victim_mac_addr: str, victim_ip_addr: str, gateway_mac_addr: str, gateway_ip_addr: str):
    """
    Send bidirectional ARP spoofing packets between a victim device and the gateway.

    This function crafts and sends two ARP reply packets:
      - One to the gateway, making it believe the Inspector host is the victim.
      - One to the victim, making it believe the Inspector host is the gateway.

    Args:
        victim_mac_addr (str): MAC address of the victim device.
        victim_ip_addr (str): IP address of the victim device.
        gateway_mac_addr (str): MAC address of the gateway.
        gateway_ip_addr (str): IP address of the gateway.

    Side Effects:
        - Sends ARP packets on the network.
        - Does nothing if the victim is the gateway or if inspection mode is disabled.

    Raises:
        None (exceptions are handled by the caller).
    """
    host_mac_addr = global_state.host_mac_addr

    if victim_ip_addr == gateway_ip_addr:
        return

    # Do not spoof packets if we're not globally inspecting
    if not common.inspector_is_running():
        return

    # Enable control of ARP spoof direction, in case we have to worry about protections.
    if common.get_env_bool('ARP_SPOOF_ROUTER', True):
        logger.info("[arp_spoof] Sending ARP spoofing packet to gateway to impersonate victim")
        dest_arp = sc.ARP(op=2, psrc=victim_ip_addr, hwsrc=host_mac_addr, pdst=gateway_ip_addr, hwdst=gateway_mac_addr)
        dest_pkt = sc.Ether(src=host_mac_addr, dst=gateway_mac_addr) / dest_arp
        sc.sendp(dest_pkt, iface=global_state.host_active_interface, verbose=0)
    else:
        logger.info("[arp_spoof] Skipping ARP spoofing packet to gateway to impersonate victim due to environment variable setting")

    # Send ARP spoof request to a victim so that the victim thinks that Inspector's host is the gateway.
    if common.get_env_bool('ARP_SPOOF_DEVICE', True):
        logger.info("[arp_spoof] Sending ARP spoofing packet to victim to impersonate gateway")
        victim_arp = sc.ARP(op=2, psrc=gateway_ip_addr, hwsrc=host_mac_addr, pdst=victim_ip_addr, hwdst=victim_mac_addr)
        victim_pkt = sc.Ether(src=host_mac_addr, dst=victim_mac_addr) / victim_arp
        sc.sendp(victim_pkt, iface=global_state.host_active_interface, verbose=0)
    else:
        logger.info("[arp_spoof] Skipping ARP spoofing packet to victim to impersonate gateway due to environment variable setting")
