import functools
import os
import geoip2.database as database
from . import networking

ip_country_parser = database.Reader(
    os.path.join(os.path.dirname(__file__), 'data', 'geolite', 'GeoLite2-Country.mmdb')
)

@functools.lru_cache(maxsize=8192)
def get_country_from_ip_addr(remote_ip_addr):
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
