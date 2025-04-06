"""
Sends out ARP spoofing packets for devices in the Device table.

"""
import time
import scapy.all as sc
import traceback
import logging

from . import global_state
from . import networking


logger = logging.getLogger(__name__)


# How many seconds between successive ARP spoofing attempts for each host
INTERNET_SPOOFING_INTERVAL = 10


spoof_stat_dict = {
    'last_internet_spoof_ts': 0
}


def start():
    """
    Sends out ARP spoofing packets between inspected devices and the gateway.

    """
    with global_state.global_state_lock:
        if not global_state.is_inspecting:
            return

    # Check if enough time has passed since the last time we spoofed internet traffic
    if time.time() - spoof_stat_dict['last_internet_spoof_ts'] < INTERNET_SPOOFING_INTERVAL:
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
        except Exception:
            logger.error(f'[arp_spoof] Error spoofing {device_dict["mac_address"]}, {device_dict["ip_address"]} <-> {gateway_mac_addr}, {gateway_ip_addr}, because\n' + traceback.format_exc())
        else:
            spoof_count += 1

    logger.info(f'[arp_spoof] Spoofed internet traffic for {spoof_count} devices')
    if spoof_count > 0:
        spoof_stat_dict['last_internet_spoof_ts'] = time.time()



def send_spoofed_arp(victim_mac_addr, victim_ip_addr, gateway_mac_addr, gateway_ip_addr):
    """
    Sends out bidirectional ARP spoofing packets between the victim and the gateway.

    """
    host_mac_addr = global_state.host_mac_addr

    if victim_ip_addr == gateway_ip_addr:
        return

    # Do not spoof packets if we're not globally inspecting
    with global_state.global_state_lock:
        if not global_state.is_inspecting:
            return

    # Send ARP spoof request to gateway, so that the gateway thinks that Inspector's host is the victim.

    dest_arp = sc.ARP()
    dest_arp.op = 2
    dest_arp.psrc = victim_ip_addr
    dest_arp.hwsrc = host_mac_addr
    dest_arp.pdst = gateway_ip_addr
    dest_arp.hwdst = gateway_mac_addr

    sc.send(dest_arp, iface=global_state.host_active_interface, verbose=0)

    # Send ARP spoof request to victim, so that the victim thinks that Inspector's host is the gateway.

    victim_arp = sc.ARP()
    victim_arp.op = 2
    victim_arp.psrc = gateway_ip_addr
    victim_arp.hwsrc = host_mac_addr
    victim_arp.pdst = victim_ip_addr
    victim_arp.hwdst = victim_mac_addr

    sc.send(victim_arp, iface=global_state.host_active_interface, verbose=0)
