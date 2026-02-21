"""
mDNS Discovery Helper.

This module provides utilities for discovering devices and service types on the local network
using Multicast DNS (mDNS) via the zeroconf protocol. It includes listeners for service type
and device discovery, as well as functions to enumerate all available mDNS service types and
to collect device information for each discovered service.

Classes:
    ServiceTypeListener: Listener to collect available mDNS service types.
    MDNSDeviceListener: Listener to collect device information for a specific mDNS service type.

Functions:
    get_all_service_types(timeout=15): Discover all available mDNS service types.
    discover_mdns_devices(service_type): Discover devices for a given mDNS service type.
    get_mdns_devices(service_type_discovery_timeout=10, device_discovery_timeout=10): Discover devices using mDNS, grouped by IP address.

Dependencies:
    zeroconf, time, json

Typical usage example:
    device_dict = get_mdns_devices(service_type_discovery_timeout=5, device_discovery_timeout=5)
    print(json.dumps(device_dict, indent=4))
"""
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
import time
import json
import logging
from . import global_state

logger = logging.getLogger(__name__)


class ServiceTypeListener(ServiceListener):
    """
    Listener to discover available mDNS service types.

    Attributes:
        service_types (set): A set of discovered mDNS service type names.

    Methods:
        add_service(zeroconf, service_type, name): Called when a new service type is discovered.
        remove_service(zeroconf, service_type, name): Called when a service type is removed.
        update_service(zeroconf, service_type, name): Called when a service type is updated.
    """

    def __init__(self):
        """Initialize a new ServiceTypeListener with an empty set of service types."""
        self.service_types = set()

    def add_service(self, zeroconf: Zeroconf, service_type: str, name: str):
        """
        Call when a new mDNS service type is discovered.

        Args:
            zeroconf (Zeroconf): The Zeroconf instance.
            service_type (str): The type of the service.
            name (str): The name of the discovered service type.
        """
        if name not in self.service_types:
            self.service_types.add(name)

    def remove_service(self, zeroconf: Zeroconf, service_type: str, name: str):
        """
        Call when a service type is removed.

        Args:
            zeroconf (Zeroconf): The Zeroconf instance.
            service_type (str): The type of the service.
            name (str): The name of the removed service type.
        """
        print(f"[mDNS] [REMOVED SERVICE TYPE] {name}")

    def update_service(self, zeroconf: Zeroconf, service_type: str, name: str):
        """
        Call when a service type is updated.

        Args:
            zeroconf (Zeroconf): The Zeroconf instance.
            service_type (str): The type of the service.
            name (str): The name of the updated service type.
        """
        print(f"[mDNS] [UPDATED SERVICE TYPE] {name}")


def get_all_service_types(zeroconf: Zeroconf, timeout: int = 15) -> set:
    """
    Discover all available mDNS service types on the local network.

    Args:
        zeroconf (Zeroconf): An existing Zeroconf instance to use for service discovery.
        timeout (int, optional): Number of seconds to wait for service discovery. Defaults to 15.

    Returns:
        set: A set of discovered mDNS service type names (str).
    """
    listener = ServiceTypeListener()
    ServiceBrowser(zeroconf, "_services._dns-sd._udp.local.", listener)
    time.sleep(timeout)
    return listener.service_types


class MDNSDeviceListener(ServiceListener):
    """
    Listener to discover devices for a specific mDNS service type.

    Attributes:
        service_type (str): The mDNS service type being monitored.
        device_name (str or None): The name of the discovered device.
        device_ip_address (str or None): The IPv4 address of the discovered device.
        device_properties (dict or None): Properties of the discovered device.

    Methods:
        add_service(zeroconf, service_type, name): Called when a new device is discovered.
        remove_service(zeroconf, service_type, name): Called when a device is removed.
        update_service(zeroconf, service_type, name): Called when a device is updated.
    """

    def __init__(self, service_type: str):
        """
        Initialize a new MDNSDeviceListener for a specific service type.

        Args:
            service_type (str): The mDNS service type to monitor.
        """
        self.service_type = service_type
        self.device_name = None
        self.device_ip_address = None
        self.device_properties = None

    def add_service(self, zeroconf: Zeroconf, service_type: str, name: str):
        """
        Call when a new device is discovered for the monitored service type.

        Args:
            zeroconf (Zeroconf): The Zeroconf instance.
            service_type (str): The type of the service.
            name (str): The name of the discovered device.
        """
        try:
            info = zeroconf.get_service_info(service_type, name)
            if info:
                ip_address = ".".join(map(str, info.addresses[0])) if info.addresses else None
                self.device_ip_address = ip_address
                self.device_name = name
                if info.properties:
                    clean_property_dict = dict()
                    for key, value in info.properties.items():
                        if key is None or value is None:
                            continue
                        try:
                            clean_property_dict[key.decode(errors='replace')] = value.decode(errors='replace')
                        except Exception:
                            pass

                    self.device_properties = clean_property_dict
        except Exception:
            pass

    def remove_service(self, zeroconf: Zeroconf, service_type: str, name: str):
        """
        Call when a device is removed.

        Args:
            zeroconf (Zeroconf): The Zeroconf instance.
            service_type (str): The type of the service.
            name (str): The name of the removed device.
        """
        pass

    def update_service(self, zeroconf: Zeroconf, service_type: str, name: str):
        """
        Call when a device is updated.

        Args:
            zeroconf (Zeroconf): The Zeroconf instance.
            service_type (str): The type of the service.
            name (str): The name of the updated device.
        """
        self.device_name = name


def discover_mdns_devices(zeroconf: Zeroconf, service_type: str) -> MDNSDeviceListener:
    """
    Starts discovery for a specific service type using an existing Zeroconf instance.

    Args:
        zeroconf (Zeroconf): An existing Zeroconf instance to use for service discovery.
        service_type (str): The mDNS service type to discover devices for.
    Returns:
        MDNSDeviceListener: The listener instance that will collect device information for the specified service type
    """
    listener = MDNSDeviceListener(service_type)
    ServiceBrowser(zeroconf, service_type, listener)
    return listener


def get_mdns_devices(service_type_discovery_timeout: int = 10, device_discovery_timeout: int = 10):
    """
    Discover devices using mDNS and group them by IP address.

    Args:
        service_type_discovery_timeout (int, optional): Seconds to wait for service type discovery. Defaults to 10.
        device_discovery_timeout (int, optional): Seconds to wait for device discovery per service type. Defaults to 10.

    Returns:
        dict: A dictionary mapping device IP addresses (str) to a list of dictionaries,
        each containing 'device_name' and 'device_properties' for a discovered device.
    """
    with Zeroconf() as zeroconf:
        service_types = get_all_service_types(zeroconf, timeout=service_type_discovery_timeout)

        listeners = []
        for service_type in service_types:
            try:
                # We only return the listener now, not a new 'zc'
                listener = discover_mdns_devices(zeroconf, service_type)
                listeners.append(listener)
            except Exception as e:
                logger.error(f"Failed to browse {service_type}: {e}")
                continue

        time.sleep(device_discovery_timeout)

        device_dictionary = dict()
        for listener in listeners:
            if listener.device_ip_address and listener.device_name:
                device_dictionary.setdefault(listener.device_ip_address, []).append({
                    'device_name': listener.device_name,
                    'device_properties': listener.device_properties
                })
        return device_dictionary


def start():
    logger.info("[mDNS] Discovering devices...")

    # Parse the output of the subprocess
    device_dict = get_mdns_devices()

    # Add the discovered devices to the database
    conn, rw_lock = global_state.db_conn_and_lock

    with rw_lock:
        for (device_ip_address, device_info_list) in device_dict.items():
            rows_updated = conn.execute('''
                                        UPDATE devices
                                        SET metadata_json = json_patch(
                                                metadata_json,
                                                json_object('mdns_json', json(?))
                                                            )
                                        WHERE ip_address = ?
                                          AND json_extract(metadata_json, '$.mdns_json') IS NULL
                                        ''', (json.dumps(device_info_list), device_ip_address)).rowcount

            if rows_updated:
                logger.info(f"[mDNS] Discovered device: {device_ip_address}: {json.dumps(device_info_list, indent=2)}")


def main():
    """
    Main function to execute mDNS device discovery and print the results in JSON format.
    """
    import argparse
    parser = argparse.ArgumentParser(description=
                                     'Run mDNS discovery to find devices on the local network')
    parser.add_argument('--service', '-s', dest='service', action='store_true', type=int, default=10,
                        help='Time to wait for service type discovery in seconds. (default: 10)')
    parser.add_argument('--device', '-d', dest='device', action='store', type=int, default=10,
                        help='Time to wait for device discovery per device in seconds. (default: 10)')
    args = parser.parse_args()
    device_dict = get_mdns_devices(args.service, args.device)
    print(json.dumps(device_dict, indent=4))


if __name__ == "__main__":
    main()
