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
    print(json.dumps(device_dict, indent=2))
"""
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
import time
import json


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

    def add_service(self, zeroconf, service_type, name):
        """
        Call when a new mDNS service type is discovered.

        Args:
            zeroconf (Zeroconf): The Zeroconf instance.
            service_type (str): The type of the service.
            name (str): The name of the discovered service type.
        """
        if name not in self.service_types:
            self.service_types.add(name)

    def remove_service(self, zeroconf, service_type, name):
        """
        Call when a service type is removed.

        Args:
            zeroconf (Zeroconf): The Zeroconf instance.
            service_type (str): The type of the service.
            name (str): The name of the removed service type.
        """
        print(f"[mDNS] [REMOVED SERVICE TYPE] {name}")

    def update_service(self, zeroconf, service_type, name):
        """
        Call when a service type is updated.

        Args:
            zeroconf (Zeroconf): The Zeroconf instance.
            service_type (str): The type of the service.
            name (str): The name of the updated service type.
        """
        print(f"[mDNS] [UPDATED SERVICE TYPE] {name}")


def get_all_service_types(timeout=15):
    """
    Discover all available mDNS service types on the local network.

    Args:
        timeout (int, optional): Number of seconds to wait for service discovery. Defaults to 15.

    Returns:
        set: A set of discovered mDNS service type names (str).
    """
    zeroconf = Zeroconf()
    listener = ServiceTypeListener()
    ServiceBrowser(zeroconf, "_services._dns-sd._udp.local.", listener)

    time.sleep(timeout)
    zeroconf.close()

    return listener.service_types


class MDNSDeviceListener(ServiceListener):
    """
    Listener to discover devices for a specific mDNS service type.

    Atributes:
        service_type (str): The mDNS service type being monitored.
        device_name (str or None): The name of the discovered device.
        device_ip_address (str or None): The IPv4 address of the discovered device.
        device_properties (dict or None): Properties of the discovered device.

    Methods:
        add_service(zeroconf, service_type, name): Called when a new device is discovered.
        remove_service(zeroconf, service_type, name): Called when a device is removed.
        update_service(zeroconf, service_type, name): Called when a device is updated.
    """

    def __init__(self, service_type):
        """
        Initialize a new MDNSDeviceListener for a specific service type.

        Args:
            service_type (str): The mDNS service type to monitor.
        """
        self.service_type = service_type
        self.device_name = None
        self.device_ip_address = None
        self.device_properties = None

    def add_service(self, zeroconf, service_type, name):
        """
        Call when a new device is discovered for the monitored service type.

        Args:
            zeroconf (Zeroconf): The Zeroconf instance.
            service_type (str): The type of the service.
            name (str): The name of the discovered device.
        """
        try:
            info = zeroconf.get_service_info(service_type, name)
        except Exception:
            pass

        if info:
            ip_address = ".".join(map(str, info.addresses[0])) if info.addresses else None
            self.device_ip_address = ip_address

            self.device_name = name
            if info.properties:
                clean_property_dict = dict()
                for k, v in info.properties.items():
                    if k is None or v is None:
                        continue
                    try:
                        clean_property_dict[k.decode(errors='replace')] = v.decode(errors='replace')
                    except Exception:
                        pass

                self.device_properties = clean_property_dict

    def remove_service(self, zeroconf, service_type, name):
        """
        Call when a device is removed.

        Args:
            zeroconf (Zeroconf): The Zeroconf instance.
            service_type (str): The type of the service.
            name (str): The name of the removed device.
        """
        pass

    def update_service(self, zeroconf, service_type, name):
        """
        Call when a device is updated.

        Args:
            zeroconf (Zeroconf): The Zeroconf instance.
            service_type (str): The type of the service.
            name (str): The name of the updated device.
        """
        self.device_name = name


def discover_mdns_devices(service_type):
    """
    Discover devices for a given mDNS service type.

    Args:
        service_type (str): The mDNS service type to search for devices.

    Returns:
        tuple: A tuple (zeroconf, listener) where zeroconf is the Zeroconf instance and
        listener is the MDNSDeviceListener instance.
    """
    zeroconf = Zeroconf()
    listener = MDNSDeviceListener(service_type)
    ServiceBrowser(zeroconf, service_type, listener)
    return zeroconf, listener


def get_mdns_devices(service_type_discovery_timeout=10, device_discovery_timeout=10):
    """
    Discover devices using mDNS and group them by IP address.

    Args:
        service_type_discovery_timeout (int, optional): Seconds to wait for service type discovery. Defaults to 10.
        device_discovery_timeout (int, optional): Seconds to wait for device discovery per service type. Defaults to 10.

    Returns:
        dict: A dictionary mapping device IP addresses (str) to a list of dictionaries,
        each containing 'device_name' and 'device_properties' for a discovered device.
    """
    # Discover all available mDNS service types
    service_types = get_all_service_types(timeout=service_type_discovery_timeout)

    # Discover devices for each service type
    zc_listener_list = []
    for service_type in service_types:
        try:
            zc, listener = discover_mdns_devices(service_type)
        except Exception:
            continue
        zc_listener_list.append((zc, listener))

    # Wait for all the threads to finish
    time.sleep(device_discovery_timeout)

    # Maps device IP address to a list of {device_name, device_properties}
    device_dict = dict()

    # Extract the device information, grouping by IP address of the device
    for (zc, listener) in zc_listener_list:
        zc.close()
        if not listener.device_ip_address:
            continue
        if not listener.device_name:
            continue
        device_dict.setdefault(listener.device_ip_address, []).append({
            'device_name': listener.device_name,
            'device_properties': listener.device_properties
        })

    return device_dict


if __name__ == "__main__":

    device_dict = get_mdns_devices(
        service_type_discovery_timeout=5,
        device_discovery_timeout=5
    )

    print(json.dumps(device_dict, indent=2))