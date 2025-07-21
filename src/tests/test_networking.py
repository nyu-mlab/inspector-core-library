import unittest
import subprocess
import os
import libinspector.common as common
import libinspector.networking as networking


def cidr_to_netmask(cidr_prefix):
    """Converts a CIDR prefix to a dotted-decimal netmask."""
    num_bits = int(cidr_prefix)
    netmask_binary = '1' * num_bits + '0' * (32 - num_bits)

    netmask_parts = []
    for i in range(0, 32, 8):
        byte_binary = netmask_binary[i:i + 8]
        netmask_parts.append(str(int(byte_binary, 2)))
    return ".".join(netmask_parts)


def run_command(command):
    """Run a shell command and return the output."""
    try:
        result = subprocess.check_output(command, shell=True, text=True).strip()
        return result
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"


def get_default_interface():
    if common.get_os() == 'mac':
        command = "route get default | grep interface | awk '{print $2}'"
    elif common.get_os() == 'linux':
        command = "ip route show default | awk '/default/ {print $5}'"
    elif common.get_os() == 'windows':
        # Step 1: Get the InterfaceIndex from the default route
        powershell_command_ifindex = [
            "powershell", "-NoProfile", "-Command",
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property InterfaceMetric | Select-Object -First 1 -ExpandProperty IfIndex"
        ]
        if_index = run_command(powershell_command_ifindex)

        if not if_index:
            raise Exception("No default route found on Windows. Essentially, no interface has a default route (0.0.0.0/0).")

        # Step 2: Use the InterfaceIndex to get the InterfaceGuid
        powershell_command_alias = [
            "powershell", "-NoProfile", "-Command",
            f"(Get-NetAdapter -InterfaceIndex {if_index} | Select-Object -First 1).InterfaceGuid"
        ]
        raw_guid = run_command(powershell_command_alias)
        interface_name = f"\\Device\\NPF_{raw_guid}"
        return interface_name
    else:
        raise NotImplementedError(f"Unsupported OS: {common.get_os()}")
    return run_command(command)


def get_router_ip(interface):
    if common.get_os() == 'mac':
        command = f"netstat -rn | grep default | grep {interface} | awk '{{print $2}}'"
    elif common.get_os() == 'linux':
        command = f"ip route show default | grep {interface} | awk '{{print $3}}'"
    elif common.get_os() == 'windows':
        # Step 1: Get the InterfaceIndex from the default route
        powershell_command_ifindex = [
            "powershell", "-NoProfile", "-Command",
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property InterfaceMetric | Select-Object -First 1 -ExpandProperty IfIndex"
        ]
        if_index = run_command(powershell_command_ifindex)

        if not if_index:
            raise Exception("No default route found on Windows. Essentially, no interface has a default route (0.0.0.0/0).")

        # Step 2: Get the Default Gateway IP specifically
        # The key here is to expand the NextHop property of the default gateway object
        powershell_command_gateway = [
            "powershell", "-NoProfile", "-Command",
            f"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex {if_index} | Select-Object -First 1).NextHop"
        ]
        # This directly returns the IP as a string if a default route exists for that interface.
        return run_command(powershell_command_gateway)
    else:
        raise NotImplementedError(f"Unsupported OS: {common.get_os()}")
    return run_command(command)


def get_ip_address(interface):
    if common.get_os() == 'mac':
        command = f"ipconfig getifaddr {interface}"
    elif common.get_os() == 'linux':
        command = f"ip addr show {interface} | grep 'inet ' | awk '{{print $2}}' | cut -d'/' -f1"
    elif common.get_os() == 'windows':
        # Step 1: Get the InterfaceIndex from the default route
        powershell_command_ifindex = [
            "powershell", "-NoProfile", "-Command",
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property InterfaceMetric | Select-Object -First 1 -ExpandProperty IfIndex"
        ]
        if_index = run_command(powershell_command_ifindex)

        if not if_index:
            raise Exception("No default route found on Windows. Essentially, no interface has a default route (0.0.0.0/0).")

        # Step 2: Get the local IP address for the interface
        powershell_command_local_ip = [
            "powershell", "-NoProfile", "-Command",
            f"(Get-NetIPAddress -InterfaceIndex {if_index} -AddressFamily IPv4 | Select-Object -First 1).IPAddress"
        ]
        return run_command(powershell_command_local_ip)
    else:
        raise NotImplementedError(f"Unsupported OS: {common.get_os()}")
    return run_command(command)


def get_mac_address(interface):
    if common.get_os() == 'mac':
        command = f"ifconfig {interface} | grep ether | awk '{{print $2}}'"
    elif common.get_os() == 'linux':
        command = f"ifconfig {interface} | grep ether | awk '{{print $2}}'"
    elif common.get_os() == 'windows':
        # Step 1: Get the InterfaceIndex from the default route
        powershell_command_ifindex = [
            "powershell", "-NoProfile", "-Command",
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property InterfaceMetric | Select-Object -First 1 -ExpandProperty IfIndex"
        ]
        if_index = run_command(powershell_command_ifindex)

        if not if_index:
            raise Exception("No default route found on Windows. Essentially, no interface has a default route (0.0.0.0/0).")

        # Step 2: Get the MAC address for the interface
        powershell_command_mac = [
            "powershell", "-NoProfile", "-Command",
            f"(Get-NetAdapter -InterfaceIndex {if_index} | Select-Object -First 1).MacAddress"
        ]
        return run_command(powershell_command_mac).replace("-", ":").lower()
    else:
        raise NotImplementedError(f"Unsupported OS: {common.get_os()}")
    return run_command(command)


def get_netmask(interface):
    if common.get_os() == 'mac':
        command = f"ifconfig {interface} | grep 'netmask' | awk '{{print $4}}'"
    elif common.get_os() == 'linux':
        command = f"ifconfig {interface} | grep 'netmask' | awk '{{print $4}}'"
        return run_command(command)
    elif common.get_os() == 'windows':
        # Step 1: Get the InterfaceIndex from the default route
        powershell_command_ifindex = [
            "powershell", "-NoProfile", "-Command",
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property InterfaceMetric | Select-Object -First 1 -ExpandProperty IfIndex"
        ]
        if_index = run_command(powershell_command_ifindex)

        if not if_index:
            raise Exception(
                "No default route found on Windows. Essentially, no interface has a default route (0.0.0.0/0).")

        # Step 2: Get the CIDR for the interface
        powershell_command_local_ip = [
            "powershell", "-NoProfile", "-Command",
            f"(Get-NetIPAddress -InterfaceIndex {if_index} -AddressFamily IPv4 | Select-Object -First 1).PrefixLength"
        ]
        prefix = run_command(powershell_command_local_ip)
        return cidr_to_netmask(prefix)
    else:
        raise NotImplementedError(f"Unsupported OS: {common.get_os()}")
    netmask_hex = run_command(command)

    # Convert hexadecimal netmask to decimal format
    try:
        netmask_int = int(netmask_hex, 16)
        netmask_decimal = ".".join(str((netmask_int >> (i * 8)) & 0xFF) for i in reversed(range(4)))
        return netmask_decimal
    except ValueError:
        return "Unknown"


class TestNetworking(unittest.TestCase):

    def test_routes(self):
        interface = get_default_interface()
        router_ip = get_router_ip(interface)
        ip_address = get_ip_address(interface)
        mac_address = get_mac_address(interface)
        netmask = get_netmask(interface)

        default_route = networking.get_default_route()

        self.assertEqual(default_route, (router_ip, interface, ip_address))
        self.assertEqual(mac_address, networking.get_my_mac())
        self.assertEqual(netmask, networking.get_network_mask())

        ip_range = networking.get_network_ip_range()

        self.assertGreaterEqual(len(ip_range), 2)
        self.assertIn(ip_address, ip_range)
        self.assertIn(router_ip, ip_range)

        networking.update_network_info()

    # GitHub Actions often run in a controlled environment where IP forwarding may not be applicable or allowed.
    @unittest.skipIf(os.environ.get("GITHUB_ACTIONS") == "true", "Skipping IP forwarding test in CI/CD environment")
    def test_ip_forwarding(self):
        networking.enable_ip_forwarding()
        networking.disable_ip_forwarding()


if __name__ == '__main__':
    unittest.main()
