import unittest
import subprocess
import os
import libinspector.common as common
import libinspector.networking as networking


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
    else:
        raise NotImplementedError(f"Unsupported OS: {common.get_os()}")
    return run_command(command)

def get_router_ip(interface):
    if common.get_os() == 'mac':
        command = f"netstat -rn | grep default | grep {interface} | awk '{{print $2}}'"
    elif common.get_os() == 'linux':
        command = f"ip route show default | grep {interface} | awk '{{print $3}}'"
    else:
        raise NotImplementedError(f"Unsupported OS: {common.get_os()}")
    return run_command(command)

def get_ip_address(interface):
    if common.get_os() == 'mac':
        command = f"ipconfig getifaddr {interface}"
    elif common.get_os() == 'linux':
        command = f"ip addr show {interface} | grep 'inet ' | awk '{{print $2}}' | cut -d'/' -f1"
    else:
        raise NotImplementedError(f"Unsupported OS: {common.get_os()}")
    return run_command(command)

def get_mac_address(interface):
    if common.get_os() == 'mac':
        command = f"ifconfig {interface} | grep ether | awk '{{print $2}}'"
    elif common.get_os() == 'linux':
        command = f"ifconfig {interface} | grep ether | awk '{{print $2}}'"
    else:
        raise NotImplementedError(f"Unsupported OS: {common.get_os()}")
    return run_command(command)

def get_netmask(interface):
    if common.get_os() == 'mac':
        command = f"ifconfig {interface} | grep 'netmask' | awk '{{print $4}}'"
    elif common.get_os() == 'linux':
        command = f"ifconfig {interface} | grep 'netmask' | awk '{{print $4}}'"
        return run_command(command)
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
