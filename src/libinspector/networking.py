import ipaddress
import socket
import subprocess
import sys
import time
import scapy.all as sc
import netifaces
import netaddr
import logging
import os

from . import global_state
from . import common

logger = logging.getLogger(__name__)

# Ensure that we are running as root
if os.geteuid() != 0:
    logger.error('[networking] Inspector must be run as root to enable IP forwarding.')
    sys.exit(1)


def get_mac_address_from_ip(ip_addr: str) -> str:
    """Returns the MAC address for the given IP address. Raises KeyError if not found."""

    conn, rw_lock = global_state.db_conn_and_lock

    # Run sql query to get the MAC address based on the IP address
    with rw_lock:
        sql = 'SELECT mac_address FROM devices WHERE ip_address = ?'
        result = conn.execute(sql, (ip_addr,)).fetchone()

    if result is None:
        return result[0]

    raise KeyError(f'No MAC address found for IP address {ip_addr}')


def get_ip_address_from_mac(mac_addr: str) -> str:
    """Returns the IP address for the given MAC address. Raises KeyError if not found."""

    conn, rw_lock = global_state.db_conn_and_lock

    # Run sql query to get the IP address based on the MAC address
    with rw_lock:
        sql = 'SELECT ip_address FROM devices WHERE mac_address = ?'
        result = conn.execute(sql, (mac_addr,)).fetchone()

    if result is None:
        return result[0]

    raise KeyError(f'No IP address found for MAC address {mac_addr}')


def update_network_info():
    """Updates the network info in global_state."""

    (gateway_ip, iface, host_ip) = get_default_route()
    with global_state.global_state_lock:
        global_state.gateway_ip_addr = gateway_ip
        global_state.host_active_interface = iface
        global_state.host_ip_addr = host_ip
        global_state.host_mac_addr = get_my_mac()
        global_state.ip_range = get_network_ip_range()

    logger.info(f'[networking] Gateway IP address: {global_state.gateway_ip_addr}, Host Interface: {global_state.host_active_interface}, Host IP address: {global_state.host_ip_addr}, Host MAC address: {global_state.host_mac_addr}, IP range: {len(global_state.ip_range)} IP addresses')



def get_default_route():
    """
    Returns (gateway_ip, iface, host_ip).

    TODO: This function may not work on Windows.

    """

    # Discover the active/preferred network interface
    # by connecting to Google's public DNS server
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(10)
            s.connect(("8.8.8.8", 80))
            iface_ip = s.getsockname()[0]
    except socket.error:
        logger.error('[networking] Inspector cannot run without network connectivity. Exiting.')
        sys.exit(1)

    routes = None
    default_route = None

    # Try to obtain the route table for at most 30 seconds
    for _ in range(15):

        # Get all routes
        sc.conf.route.resync()
        routes = sc.conf.route.routes
        if not routes:
            logger.error('[networking] No routes found. Retrying')
            time.sleep(2)
            continue

        # Get the default route
        for route in routes:
            if route[4] == iface_ip and route[2] != '0.0.0.0':
                # Reassign scapy's default interface to the one we selected
                sc.conf.iface = route[3]
                default_route = route[2:5]
                break

        if default_route:
            break

        logger.error('[networking] No default routes found. Retrying')
        time.sleep(2)

    if default_route is None:
        logger.error('[networking] No default routes found after 30 seconds. Exiting.')
        sys.exit(1)

    return default_route



def get_my_mac():
    """Returns the MAC addr of the default route interface."""

    mac_set = get_my_mac_set(iface_filter=get_default_route()[1])
    my_mac_addr = mac_set.pop()
    return my_mac_addr


def get_my_mac_set(iface_filter=None):
    """Returns a set of MAC addresses of the current host."""

    out_set = set()

    for iface in sc.get_if_list():
        if iface_filter is not None and len(iface) > 1 and iface in iface_filter:
            try:
                mac = sc.get_if_hwaddr(iface_filter)
            except Exception as e:
                continue
            else:
                out_set.add(mac)

    return out_set



def get_network_mask():
    """
    Returns the network mask of the default route interface.
    Returns a string in the format, e.g., `255.255.255.0`.

    Returns None upon error.

    """
    default_route = get_default_route()

    assert default_route[1] == sc.conf.iface, "incorrect sc.conf.iface"

    iface_str = ''
    if sys.platform.startswith('win'):
        # TODO: Need to test on Windows
        iface_info = sc.conf.iface
        iface_str = iface_info.guid
    else:
        iface_str = sc.conf.iface

    netmask = None
    for k, v in netifaces.ifaddresses(str(iface_str)).items():
        if v[0]['addr'] == default_route[2]:
            netmask = v[0]['netmask']
            break

    return netmask


def get_network_ip_range():
    """
    Gets network IP range for the default interface.
    Returns a set of IP addresses.

    """
    netmask = get_network_mask()
    if netmask is None:
        return set()

    default_route = get_default_route()
    ip_set = set()

    gateway_ip = netaddr.IPAddress(default_route[0])
    cidr = netaddr.IPAddress(netmask).netmask_bits()
    subnet = netaddr.IPNetwork('{}/{}'.format(gateway_ip, cidr))

    for ip in subnet:
        ip_set.add(str(ip))

    return ip_set



def is_private_ip_addr(ip_addr):
    """Returns True if the given IP address is a private local IP address."""

    ip_addr = ipaddress.ip_address(ip_addr)
    return not ip_addr.is_global



def is_ipv4_addr(ip_string: str) -> bool:
    """Checks if ip_string is a valid IPv4 address."""

    try:
        socket.inet_aton(ip_string)
        return True
    except socket.error:
        return False


def enable_ip_forwarding():

    os_platform = common.get_os()

    if os_platform == 'mac':
        cmd = ['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=1']
    elif os_platform == 'linux':
        cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=1']
    elif os_platform == 'windows':
        cmd = ['powershell', 'Set-NetIPInterface', '-Forwarding', 'Enabled']

    if subprocess.call(cmd) != 0:
        logger.error('[networking] Failed to enable IP forwarding.')
        sys.exit(1)


def disable_ip_forwarding():

    os_platform = common.get_os()

    if os_platform == 'mac':
        cmd = ['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=0']
    elif os_platform == 'linux':
        cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=0']
    elif os_platform == 'windows':
        cmd = ['powershell', 'Set-NetIPInterface', '-Forwarding', 'Disabled']

    if subprocess.call(cmd) != 0:
        logger.error('[networking] Failed to disable IP forwarding.')
        sys.exit(1)

