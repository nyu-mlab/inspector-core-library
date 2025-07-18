import unittest
import subprocess
import sys
import libinspector.common as common
import libinspector.networking as networking


# Make sure we're running as root
if not common.is_admin():
    print('All tests must be run as root. Exiting.')
    sys.exit(1)


def run_command(command):
    """Run a shell command and return the output."""
    try:
        result = subprocess.check_output(command, shell=True, text=True).strip()
        return result
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"

def get_default_interface():
    command = "route get default | grep interface | awk '{print $2}'"
    return run_command(command)

def get_router_ip(interface):
    command = f"netstat -rn | grep default | grep {interface} | awk '{{print $2}}'"
    return run_command(command)

def get_ip_address(interface):
    command = f"ipconfig getifaddr {interface}"
    return run_command(command)

def get_mac_address(interface):
    command = f"ifconfig {interface} | grep ether | awk '{{print $2}}'"
    return run_command(command)

def get_netmask(interface):
    command = f"ifconfig {interface} | grep 'netmask' | awk '{{print $4}}'"
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
        """
        TODO need tests for Linux and Windows

        """
        if common.get_os() == 'mac':

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


    def test_ip_forwarding(self):

        networking.enable_ip_forwarding()
        networking.disable_ip_forwarding()




if __name__ == '__main__':
    unittest.main()