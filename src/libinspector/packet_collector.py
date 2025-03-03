"""
Captures and analyzes packets from the network.

"""
import scapy.all as sc
from . import global_state



def start_packet_collector():

    with global_state.global_state_lock:
        host_active_interface = global_state.host_active_interface
        host_ip_addr = global_state.host_ip_addr

    sc.load_layer('tls')

    # Continuously sniff packets for 30 second intervals
    sc.sniff(
        prn=add_packet_to_queue,
        iface=host_active_interface,
        stop_filter=lambda _: not inspector_is_running(),
        filter=f'(not arp and host not {host_ip_addr}) or arp', # Avoid capturing packets to/from the host itself, except ARP, which we need for discovery -- this is for performance improvement
        timeout=30
    )


def inspector_is_running():
    """
    Returns whether the Inspector is running or not.

    """
    with global_state.global_state_lock:
        return global_state.is_running


def add_packet_to_queue(pkt):
    """
    Adds a packet to the packet queue.

    """
    with global_state.global_state_lock:
        if not global_state.is_inspecting:
            return

    global_state.packet_queue.put(pkt)