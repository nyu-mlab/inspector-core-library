from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
import time
import logging
import json

from . import global_state

logger = logging.getLogger(__name__)



class ServiceTypeListener(ServiceListener):
    """ Listener to discover available mDNS service types. """
    def __init__(self):
        self.service_types = set()

    def add_service(self, zeroconf, service_type, name):
        if name not in self.service_types:
            self.service_types.add(name)

    def remove_service(self, zeroconf, service_type, name):
        print(f"[mDNS] [REMOVED SERVICE TYPE] {name}")

    def update_service(self, zeroconf, service_type, name):
        print(f"[mDNS] [UPDATED SERVICE TYPE] {name}")

def get_all_service_types(timeout=15):
    """ Discover all available mDNS service types. """
    zeroconf = Zeroconf()
    listener = ServiceTypeListener()
    ServiceBrowser(zeroconf, "_services._dns-sd._udp.local.", listener)

    time.sleep(timeout)
    zeroconf.close()

    return listener.service_types


class MDNSDeviceListener(ServiceListener):
    """ Listener to discover devices for a specific service type. """
    def __init__(self, service_type):
        self.service_type = service_type

        self.device_name = None
        self.device_ip_address = None
        self.device_properties = None

    def add_service(self, zeroconf, service_type, name):
        try:
            info = zeroconf.get_service_info(service_type, name)
        except Exception as e:
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
                    except Exception as e:
                        pass

                self.device_properties = clean_property_dict

    def remove_service(self, zeroconf, service_type, name):
        pass

    def update_service(self, zeroconf, service_type, name):
        self.device_name = name


def discover_mdns_devices(service_type):
    """ Discover devices for a given mDNS service type. """
    zeroconf = Zeroconf()
    listener = MDNSDeviceListener(service_type)
    ServiceBrowser(zeroconf, service_type, listener)

    return (zeroconf, listener)


def start():
    """
    Discovers devices via mDNS. Saves the discovered devices to the `devices`
    table (under the `metadata_json` column) in the database.

    """
    device_dict = get_mdns_devices(
        service_type_discovery_timeout=5,
        device_discovery_timeout=5
    )

    conn, rw_lock = global_state.db_conn_and_lock

    with rw_lock:
        for (device_ip_address, device_info_list) in device_dict.items():
            rows_updated = conn.execute('''
                UPDATE devices
                SET metadata_json = json_patch(
                    metadata_json,
                    json_object('mdns_json', json(?))
                )
                WHERE ip_address = ? AND json_extract(metadata_json, '$.mdns_json') IS NULL
            ''', (json.dumps(device_info_list), device_ip_address)).rowcount

            if rows_updated:
                logger.info(f"[mDNS] Discovered device: {device_ip_address}: {json.dumps(device_info_list, indent=2)}")



def get_mdns_devices(service_type_discovery_timeout=10, device_discovery_timeout=10):
    """ Discover devices using mDNS. Returns a dictionary of devices grouped by IP address. """

    # Discover all available mDNS service types
    service_types = get_all_service_types(timeout=service_type_discovery_timeout)

    # Discover devices for each service type
    zc_list = []
    for service_type in service_types:
        zc = discover_mdns_devices(service_type)
        zc_list.append(zc)

    # Wait for all the threads to finish
    time.sleep(device_discovery_timeout)

    # Maps device IP address to a list of {device_name, device_properties}
    device_dict = dict()

    # Extract the device information, grouping by IP address of the device
    for (zc, listener) in zc_list:
        if not listener.device_ip_address:
            continue
        if not listener.device_name:
            continue
        device_dict.setdefault(listener.device_ip_address, []).append({
            'device_name': listener.device_name,
            'device_properties': listener.device_properties
        })

    zc.close()

    return device_dict


if __name__ == "__main__":

    import json
    device_dict = get_mdns_devices(
        service_type_discovery_timeout=5,
        device_discovery_timeout=5
    )

    print(json.dumps(device_dict, indent=2))