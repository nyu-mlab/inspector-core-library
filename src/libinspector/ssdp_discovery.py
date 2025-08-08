r"""
Discovers devices via SSDP. Returns an iterator of device_dict's.

Sample usage:

```
for discovered_device_dict in discover_upnp_devices():
    print(json.dumps(discovered_device_dict, indent=2))
    print('*' * 60)

```

The device dict returned will include the following keys:
  - device_ip_addr: The IP address of the discovered device.
  - ssdp_response_dict: A dictionary of the parsed SSDP response.
  - location_contents: A dictionary of the parsed XML contents at the LOCATION URL.

Example json returned for a Philips Hue:

```
{
  "device_ip_addr": "192.168.86.48",
  "ssdp_response_dict": {
    "HOST": "239.255.255.250:1900",
    "CACHE-CONTROL": "max-age=100",
    "LOCATION": "http://192.168.86.48:80/description.xml",
    "SERVER": "Hue/1.0 UPnP/1.0 IpBridge/1.69.0",
    "hue-bridgeid": "REDACTED",
    "ST": "upnp:rootdevice",
    "USN": "uuid:REDACTED::upnp:rootdevice"
  },
  "location_contents": {
    "root": {
      "specVersion": {
        "specVersion": {
          "major": "1",
          "minor": "0"
        }
      },
      "URLBase": "http://192.168.86.48:80/",
      "device": {
        "device": {
          "deviceType": "urn:schemas-upnp-org:device:Basic:1",
          "friendlyName": "Hue Bridge (192.168.86.48)",
          "manufacturer": "Signify",
          "manufacturerURL": "http://www.philips-hue.com",
          "modelDescription": "Philips hue Personal Wireless Lighting",
          "modelName": "Philips hue bridge 2015",
          "modelNumber": "BSB002",
          "modelURL": "http://www.philips-hue.com",
          "serialNumber": "ecb5fa9bf262",
          "UDN": "uuid:REDACTED",
          "presentationURL": "index.html"
        }
      }
    }
  }
}
```

And the output for a Google Chromecast looks like this:

```
{
  "device_ip_addr": "192.168.86.31",
  "ssdp_response_dict": {
    "CACHE-CONTROL": "max-age=1800",
    "DATE": "Mon, 17 Mar 2025 19:49:12 GMT",
    "LOCATION": "http://192.168.86.31:8008/ssdp/device-desc.xml",
    "OPT": "\"http://schemas.upnp.org/upnp/1/0/\"; ns=01",
    "01-NLS": "REDACTED",
    "SERVER": "Linux/3.8.13+, UPnP/1.0, Portable SDK for UPnP devices/1.6.18",
    "X-User-Agent": "redsonic",
    "ST": "upnp:rootdevice",
    "USN": "uuid:REDACTED::upnp:rootdevice",
    "BOOTID.UPNP.ORG": "1071",
    "CONFIGID.UPNP.ORG": "2403"
  },
  "location_contents": {
    "root": {
      "specVersion": {
        "specVersion": {
          "major": "1",
          "minor": "0"
        }
      },
      "URLBase": "http://192.168.86.31:8008",
      "device": {
        "device": {
          "deviceType": "urn:dial-multiscreen-org:device:dial:1",
          "friendlyName": "Living Room TV",
          "manufacturer": "Google Inc.",
          "modelName": "Eureka Dongle",
          "UDN": "uuid:REDACTED",
          "iconList": {
            "iconList": {
              "icon": {
                "icon": {
                  "mimetype": "image/png",
                  "width": "98",
                  "height": "55",
                  "depth": "32",
                  "url": "/setup/icon.png"
                }
              }
            }
          },
          "serviceList": {
            "serviceList": {
              "service": {
                "service": {
                  "serviceType": "urn:dial-multiscreen-org:service:dial:1",
                  "serviceId": "urn:dial-multiscreen-org:serviceId:dial",
                  "controlURL": "/ssdp/notfound",
                  "eventSubURL": "/ssdp/notfound",
                  "SCPDURL": "/ssdp/notfound"
                }
              }
            }
          }
        }
      }
    }
  }
}

```

"""

import socket
import requests
import xml.etree.ElementTree as ET
import json
import logging
import time

from . import global_state


logger = logging.getLogger(__name__)


# SSDP multicast address and port
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
MSEARCH_MSG = f"""M-SEARCH * HTTP/1.1
HOST: {SSDP_ADDR}:{SSDP_PORT}
MAN: "ssdp:discover"
MX: 3
ST: ssdp:all

""".encode("utf-8")


def start():
    """
    Start the SSDP discovery process and update the device database with discovered devices.

    This function performs SSDP (Simple Service Discovery Protocol) discovery to find UPnP devices
    on the local network. For each discovered device, it updates the `devices` table in the database
    with the device's SSDP and UPnP metadata if not already present.

    Side Effects:
        - Updates the `devices` table in the database with discovered device information.
        - Logs discovered devices using the module logger.

    Returns:
        None
    """
    conn, rw_lock = global_state.db_conn_and_lock

    # Set the socket timeout based on when the Inspector started; shorter
    # timeout when Inspector has started for 5 minutes for more aggressive
    # discovery
    current_ts = time.time()
    with global_state.global_state_lock:
        if current_ts - global_state.inspector_started_ts < 300:
            socket_timeout = 10
        else:
            socket_timeout = 30

    for discovered_device_dict in discover_upnp_devices(timeout=socket_timeout):

        if not discovered_device_dict:
            continue

        # Add discovered_device_dict to the metadata_json of the devices table
        with rw_lock:
            row_count = conn.execute('''
                UPDATE devices
                SET metadata_json = json_patch(
                    metadata_json,
                    json_object('ssdp_json', json(?))
                )
                WHERE ip_address = ? AND json_extract(metadata_json, '$.ssdp_json') IS NULL
            ''', (json.dumps(discovered_device_dict), discovered_device_dict['device_ip_addr'])).rowcount

        if row_count:
            logger.info(f"[ssdp] Discovered device: {discovered_device_dict['device_ip_addr']}")


def fetch_and_parse_xml(url):
    """
    Fetch the XML from the given URL and parse it into a dictionary.

    Args:
        url (str): The URL to fetch the XML from.

    Returns:
        dict or None: The parsed XML as a dictionary, or None if the request fails.
    """
    xml_content = None
    try:
        response = requests.get(url)
        response.raise_for_status()
        xml_content = response.content
        root = ET.fromstring(xml_content)
        return xml_to_dict(root)
    except requests.RequestException as e:
        logger.warning(f"Request failed for {url}: {e}")
        return None
    except ET.ParseError as e:
        if xml_content is not None:
            decoded_content = xml_content.decode("utf-8", errors="ignore").strip()
            if decoded_content != "status=ok":
                logger.warning(f"XML content:\n {xml_content}")
                logger.warning(f"XML parsing failed for {url}: {e}")
        else:
            logger.warning(f"XML parsing failed, and XML content is NOT populated {url}: {e}")
        return None


def xml_to_dict(element):
    """
    Convert an XML element and its children into a dictionary.

    Args:
        element (xml.etree.ElementTree.Element): The XML element to convert.

    Returns:
        dict or str: The element and its children as a dictionary, or the text if it has no children.
    """
    def strip_ns(tag):
        return tag.split('}', 1)[-1] if '}' in tag else tag

    if len(element) == 0:
        return element.text
    return {strip_ns(element.tag): {strip_ns(child.tag): xml_to_dict(child) for child in element}}


def parse_device_info(device_info):
    """
    Parsee the device info string into a dictionary.

    Args:
        device_info (str): The device info string, typically an SSDP response.

    Returns:
        dict: The parsed device info as a dictionary.
    """
    info_dict = {}
    lines = device_info.split("\r\n")
    for line in lines:
        if ": " in line:
            key, value = line.split(": ", 1)
            info_dict[key] = value
    return info_dict



def discover_upnp_devices(timeout=5):
    """
    Discover UPnP devices using SSDP.

    Args:
        timeout (int, optional): The socket timeout in seconds. Defaults to 5.

    Returns:
        Iterator[dict]: An iterator of discovered device dictionaries.
    """
    # Set to store the IP addresses of discovered devices
    device_ip_set = set()

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)

    # Bind to a random port and send the SSDP discovery request
    sock.sendto(MSEARCH_MSG, (SSDP_ADDR, SSDP_PORT))

    try:
        while True:
            response, addr = sock.recvfrom(4096)
            ssdp_response = response.decode("utf-8", errors="ignore")
            device_ip_addr = addr[0]

            # Skip if we have already seen this device's IP address
            if device_ip_addr in device_ip_set:
                continue
            device_ip_set.add(device_ip_addr)

            device_dict = {
                'device_ip_addr': device_ip_addr,
                'ssdp_response_dict': None,
                'location_contents': None
            }

            try:
                device_dict["ssdp_response_dict"] = parse_device_info(ssdp_response)
            except Exception:
                pass
            else:
                if "LOCATION" in device_dict["ssdp_response_dict"]:
                    xml_json = fetch_and_parse_xml(device_dict["ssdp_response_dict"]["LOCATION"])
                    if xml_json:
                        device_dict['location_contents'] = xml_json

            yield device_dict

    except socket.timeout:
        pass

    finally:
        sock.close()


if __name__ == "__main__":
    # Test code
    for discovered_device_dict in discover_upnp_devices():
        print(json.dumps(discovered_device_dict, indent=2))
        print('*' * 60)