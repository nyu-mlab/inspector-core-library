"""
Networking Utilities for Inspector.

This module provides functions for querying and managing network information on the host system.
It includes utilities to retrieve MAC and IP addresses from a local database, determine the default
network route, obtain the host's MAC address, compute the local network mask and IP range, and
check IP address properties. It also provides functions to enable or disable IP forwarding at the
operating system level.

Key Features:
- Database lookups for MAC and IP address associations.
- Detection of the default gateway, interface, and host IP.
- Retrieval of the host's MAC address and all local MAC addresses.
- Calculation of the network mask and all IPs in the local subnet.
- Validation and classification of IP addresses (private, IPv4).
- Cross-platform support for enabling/disabling IP forwarding.

Dependencies:
- scapy
- netaddr
- psutil
- ipaddress
- socket
- subprocess
- logging

Intended Usage:
Import and use these functions to interact with and manage network configuration as part of the Inspector's workflow.
"""
import ipaddress
import socket
import subprocess
import sys
import time
import scapy.all as sc
import netaddr
import logging
import psutil

from . import global_state
from . import common

logger = logging.getLogger(__name__)


def get_mac_address_from_ip(ip_addr: str) -> str:
    """
    Retrieve the MAC address associated with a given IP address from the devices database.

    Args:
        ip_addr (str): The IP address for which to retrieve the MAC address.

    Returns:
        str: The MAC address corresponding to the provided IP address.

    Raises:
        KeyError: If no MAC address is found for the specified IP address.
    """
    conn, rw_lock = global_state.db_conn_and_lock

    # Run sql query to get the MAC address based on the IP address
    with rw_lock:
        sql = 'SELECT mac_address FROM devices WHERE ip_address = ?'
        result = conn.execute(sql, (ip_addr,)).fetchone()

    if result is None:
        raise KeyError(f'No MAC address found for IP address {ip_addr}')

    return result['mac_address']


def get_ip_address_from_mac(mac_addr: str) -> str:
    """
    Retrieve the IP address associated with a given MAC address from the devices database.

    Args:
        mac_addr (str): The MAC address for which to retrieve the IP address.

    Returns:
        str: The IP address corresponding to the provided MAC address.

    Raises:
        KeyError: If no IP address is found for the specified MAC address.
    """
    conn, rw_lock = global_state.db_conn_and_lock

    # Run sql query to get the IP address based on the MAC address
    with rw_lock:
        sql = 'SELECT ip_address FROM devices WHERE mac_address = ?'
        result = conn.execute(sql, (mac_addr,)).fetchone()

    if result is None:
        return result[0]

    raise KeyError(f'No IP address found for MAC address {mac_addr}')


def update_network_info():
    """
    Update the current network configuration in the global state.

    This function determines the gateway IP, active network interface, host IP, host MAC address,
    and the set of IP addresses in the local network, and stores them in the global state object.
    Also logs the updated network information.
    """
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
    Determine the default network route and returns the gateway IP, interface, and host IP.

    Returns:
        tuple: A tuple containing (gateway_ip (str), iface (str), host_ip (str)).

    Raises:
        SystemExit: If no default route is found after multiple attempts or if network connectivity is unavailable.
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
            logger.info(f'[networking] route: {route}')
            # This is if we are within a container
            if route[1] == 0 and route[2] != '0.0.0.0':
                sc.conf.iface = route[3]
                default_route = (route[2], route[3], iface_ip)
                break
            # Fallback: original condition
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
    """
    Return the MAC address of the default route interface.

    Returns:
        str: The MAC address of the interface used for the default route.

    Raises:
        KeyError: If no MAC address is found for the default interface.
    """
    mac_set = get_my_mac_set(iface_filter=get_default_route()[1])
    my_mac_addr = mac_set.pop()
    return my_mac_addr


def get_my_mac_set(iface_filter=None) -> set:
    """
    Return a set of MAC addresses for the current host.

    Args:
        iface_filter (str, optional): The name of the interface to filter by. If None, all interfaces are included.

    Returns:
        set: A set of MAC address strings for the host's interfaces.
    """
    out_set = set()

    for iface in sc.get_if_list():
        if iface_filter is not None and len(iface) > 1 and iface in iface_filter:
            try:
                mac = sc.get_if_hwaddr(iface_filter)
            except Exception:
                continue
            else:
                out_set.add(mac)

    return out_set



def get_network_mask():
    """
    Return the network mask of the default route interface.

    Returns:
        str or None: The network mask as a string (e.g., '255.255.255.0'), or None if it cannot be determined.
    """
    default_route = get_default_route()

    assert default_route[1] == sc.conf.iface, "incorrect sc.conf.iface"
    if sys.platform.startswith('win'):
        iface_info = sc.conf.iface
        iface_str = iface_info.name
    else:
        iface_str = sc.conf.iface

    iface_addresses = psutil.net_if_addrs().get(str(iface_str), [])
    netmask = None
    for addr in iface_addresses:
        if addr.family == socket.AF_INET and addr.address == default_route[2]:
            netmask = addr.netmask
            break

    return netmask


def get_network_ip_range() -> set:
    """
    Return the set of all IP addresses in the local network for the default interface.

    Returns:
        set: A set of IP address strings in the local network.
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
    """
    Determine if the given IP address is a private (non-global) address.

    Args:
        ip_addr (str): The IP address to check.

    Returns:
        bool: True if the address is private/local, False if it is global/public.
    """
    ip_addr = ipaddress.ip_address(ip_addr)
    return not ip_addr.is_global



def is_ipv4_addr(ip_string: str) -> bool:
    """
    Check if the provided string is a valid IPv4 address.

    Args:
        ip_string (str): The string to validate as an IPv4 address.

    Returns:
        bool: True if the string is a valid IPv4 address, False otherwise.
    """
    try:
        socket.inet_aton(ip_string)
        return True
    except socket.error:
        return False


def enable_ip_forwarding():
    """
    Enable IP forwarding on the host system.

    This function enables IP forwarding (routing) at the OS level, allowing the host to forward packets between interfaces.
    Exits the program if the operation fails.
    """
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
    """
    Disable IP forwarding on the host system.

    This function disables IP forwarding (routing) at the OS level, preventing the host from forwarding packets between interfaces.
    Exits the program if the operation fails.
    """
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

