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
import time
import scapy.all as sc
import netaddr
import logging
import psutil
import sys
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

    # Run SQL query to get the MAC address based on the IP address
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

    if result is not None:
        return result[0]

    raise KeyError(f'No IP address found for MAC address {mac_addr}')


def update_network_info():
    """
    Update the current network configuration in the global state.

    This function determines the gateway IP, active network interface, host IP, host MAC address,
    and the set of IP addresses in the local network, and stores them in the global state object.
    Also logs the updated network information.
    """
    gateway_ip, iface, host_ip = get_default_route()
    my_mac = get_my_mac()
    ip_range = get_network_ip_range()
    with global_state.global_state_lock:
        global_state.gateway_ip_addr = gateway_ip
        global_state.host_active_interface = iface
        global_state.host_ip_addr = host_ip
        global_state.host_mac_addr = my_mac
        global_state.ip_range = ip_range
    logger.info(f'[networking] Gateway IP address: {gateway_ip}, Host Interface: {iface}, Host IP address: {host_ip}, Host MAC address: {my_mac}, IP range: {len(ip_range)} IP addresses')


def get_default_route() -> tuple:
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
        raise RuntimeError('[networking] Inspector cannot run without network connectivity. Exiting.')

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
        raise RuntimeError('[networking] No default routes found after 30 seconds. Exiting.')

    return default_route


def get_my_mac() -> str:
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


def get_my_mac_set(iface_filter: str = None) -> set:
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


def is_private_ip_addr(ip_addr: str) -> bool:
    """
    Determine if the given IP address is a private (non-global) address.

    Args:
        ip_addr (str): The IP address to check.

    Returns:
        bool: True if the address is private/local, False if it is global/public.
    """
    ip_address_type = ipaddress.ip_address(ip_addr)
    return not ip_address_type.is_global


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


def get_actual_icmp_redirect_state() -> str:
    """
    Retrieves the current ICMP redirect state for Windows, Mac, or Linux.
    CRASHES if the state cannot be determined to protect config integrity.
    """
    os_platform = common.get_os()

    if os_platform == 'windows':
        # This PowerShell snippet tries IcmpRedirects first, then Redirects as a fallback
        ps_cmd = (
            "$p = Get-NetIPv4Protocol; "
            "if ($p.IcmpRedirects -ne $null) { $p.IcmpRedirects } "
            "else { $p.Redirects }"
        )
        cmd = ['powershell', '-Command', ps_cmd]
        output = subprocess.check_output(cmd, text=True).strip()
        # PowerShell returns "Enabled" or "Disabled" regardless of OS language
        return output.lower()

    elif os_platform == 'linux':
        # '-n' returns ONLY the value (e.g., '1' or '0'), no labels to parse!
        output = subprocess.check_output(['sysctl', '-n', 'net.ipv4.conf.all.send_redirects'], text=True).strip()
        # 1 = Kernel will send redirects (Enabled)
        return "enabled" if output == "1" else "disabled"

    elif os_platform == 'mac':
        # '-n' returns ONLY the value
        output = subprocess.check_output(['sysctl', '-n', 'net.inet.icmp.drop_redirect'], text=True).strip()
        # NOTE: drop_redirect=1 means the kernel DROPS them (Disabled)
        return "disabled" if output == "1" else "enabled"

    else:
        raise OSError(f"Unsupported OS platform: {os_platform}")


def enable_ip_forwarding():
    """
    Enables IP forwarding and silences ICMP redirects.
    Uses check_call to ensure the program crashes if setup fails.
    """
    os_platform = common.get_os()

    # 1. Capture original state before we touch anything
    original_icmp_state = get_actual_icmp_redirect_state()
    with global_state.global_state_lock:
        global_state.icmp_redirect_enabled = original_icmp_state
    logger.info(f"[networking] Original ICMP state detected as: {original_icmp_state}")

    cmds = []
    if os_platform == 'mac':
        cmds.append(['sysctl', '-w', 'net.inet.ip.forwarding=1'])
        cmds.append(['sysctl', '-w', 'net.inet.icmp.drop_redirect=1'])
    elif os_platform == 'linux':
        cmds.append(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
        cmds.append(['sysctl', '-w', 'net.ipv4.conf.all.send_redirects=0'])
    elif os_platform == 'windows':
        cmds.append(['powershell', 'Set-NetIPInterface', '-Forwarding', 'Enabled', '-AddressFamily', 'IPv4'])
        cmds.append(['powershell', 'Set-NetIPInterface', '-Forwarding', 'Enabled', '-AddressFamily', 'IPv6'])

        cmds.append(['netsh', 'interface', 'ipv4', 'set', 'global', 'icmpredirects=disabled'])
        cmds.append(['netsh', 'interface', 'ipv6', 'set', 'global', 'icmpredirects=disabled'])

        # Have firewall drop ICMP redirects
        cmds.append(['powershell', 'New-NetFirewallRule', '-DisplayName', '"IoT-Inspector-Silence"',
                    '-Direction', 'Outbound', '-Protocol', 'ICMPv4', '-IcmpType', '5', '-Action', 'Block'])
        cmds.append(['powershell', 'New-NetFirewallRule', '-DisplayName', '"IoT-Inspector-Silence-v6"',
                    '-Direction', 'Outbound', '-Protocol', 'ICMPv6', '-IcmpType', '137', '-Action', 'Block'])
    else:
        raise NotImplementedError(f"Unsupported OS platform: {os_platform}")

    for cmd in cmds:
        logger.info(f"[networking] Setting up: {' '.join(cmd)}")
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def disable_ip_forwarding():
    """
    Restores original system state.
    """
    os_platform = common.get_os()
    with global_state.global_state_lock:
        original_icmp_state = global_state.icmp_redirect_enabled

    cmds = []
    if os_platform == 'mac':
        cmds.append(['sysctl', '-w', 'net.inet.ip.forwarding=0'])
        # If it was enabled (0), set drop back to 0. If it was disabled (1), set to 1.
        val = '1' if original_icmp_state == 'disabled' else '0'
        cmds.append(['sysctl', '-w', f'net.inet.icmp.drop_redirect={val}'])
    elif os_platform == 'linux':
        cmds.append(['sysctl', '-w', 'net.ipv4.ip_forward=0'])
        val = '0' if original_icmp_state == 'disabled' else '1'
        cmds.append(['sysctl', '-w', f'net.ipv4.conf.all.send_redirects={val}'])
    elif os_platform == 'windows':
        cmds.append(['powershell', 'Set-NetIPInterface', '-Forwarding', 'Disabled', '-AddressFamily', 'IPv4'])
        cmds.append(['powershell', 'Set-NetIPInterface', '-Forwarding', 'Disabled', '-AddressFamily', 'IPv6'])

        # Restore ICMP Redirect
        cmds.append(['netsh', 'interface', 'ipv4', 'set', 'global', f'icmpredirects={original_icmp_state}'])
        cmds.append(['netsh', 'interface', 'ipv6', 'set', 'global', f'icmpredirects={original_icmp_state}'])

        # Undo ICMP redirect drop
        cmds.append(['powershell', 'Remove-NetFirewallRule', '-DisplayName', '"IoT-Inspector-Silence"'])
        cmds.append(['powershell', 'Remove-NetFirewallRule', '-DisplayName', '"IoT-Inspector-Silence-v6"'])
    else:
        raise NotImplementedError(f"Unsupported OS platform: {os_platform}")

    for cmd in cmds:
        logger.info(f"[networking] Cleaning up: {' '.join(cmd)}")
        subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
