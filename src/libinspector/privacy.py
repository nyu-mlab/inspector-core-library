import functools
import os
import geoip2.database as database
import json
from . import networking

ip_country_parser = database.Reader(
    os.path.join(os.path.dirname(__file__), 'data', 'geolite', 'GeoLite2-Country.mmdb')
)

_full_block_list_dict = {}

@functools.lru_cache(maxsize=8192)
def get_country_from_ip_addr(remote_ip_addr: str) -> str:
    """
    Determines the country associated with a given IP address using the GeoLite2 database.

    Args:
        remote_ip_addr (str): The IP address to look up.

    Returns:
        str: The country name if found, '(local network)' for private IPs, or an empty string if not found or on error.
    """

    if networking.is_private_ip_addr(remote_ip_addr):
        return '(local network)'

    try:
        country = ip_country_parser.country(remote_ip_addr).country.name
        if country:
            return country
    except Exception:
        pass

    return ''


def parse_tracking_json(json_contents: dict) -> dict:
    """
    A helper function to parse the JSON contents of a tracker file.
    """
    block_list_dict = dict()

    for domain, info in json_contents['trackers'].items():
        tracker_company = info['owner']['displayName']
        if tracker_company:
            block_list_dict[domain] = tracker_company

    return block_list_dict


@functools.lru_cache(maxsize=1)
def initialize_ad_tracking_db():
    """
    Initializes the AdTracker table with the default list of trackers.
    Run only once at startup.
    """
    _full_block_list_dict.clear()
    tracker_json_list = ['android-tds.json', 'ios-tds.json']

    for tracker_json_file in tracker_json_list:
        tracker_path = os.path.join(os.path.dirname(__file__), 'data', 'trackers', tracker_json_file)
        tracker_path = os.path.abspath(tracker_path)

        with open(tracker_path, 'r') as f:
            _full_block_list_dict.update(parse_tracking_json(json.load(f)))


def is_ad_tracked(domain: str) -> bool:
    """
    Returns the tracker company for a given hostname; if not a tracking company, returns an empty string
    Args:
        domain (str): The domain name to check.
    Returns:
        bool: True if the domain is a tracking company, False otherwise.
    """
    initialize_ad_tracking_db()
    return domain in _full_block_list_dict
