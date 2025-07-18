"""
OUI (Organizationally Unique Identifier) Parser Module.

This module provides functionality to parse and extract the vendor or company name
associated with a given MAC address using a Wireshark OUI database. It loads the
OUI-to-company mapping from a resource file and efficiently caches lookups for
performance. The main function, `get_vendor`, returns the vendor name for a given
MAC address, or an empty string if the vendor is unknown.

Key Features:
- Loads and parses the Wireshark OUI database from a packaged resource file.
- Supports OUI prefixes of varying lengths for accurate vendor identification.
- Uses LRU caching to optimize repeated lookups and database parsing.
- Provides a simple interface to retrieve the vendor for a given MAC address.

Intended Usage:
Call `get_vendor(mac_addr)` with a MAC address string to retrieve the associated
vendor or company name.

Dependencies:
- functools
- importlib.resources

Resource File:
- wireshark_oui_database.txt (must be present in the `libinspector` package)
"""
import functools
import importlib.resources


# Maps the first 3 (or more) bytes of the MAC address to the company name.
_oui_dict = {}

_oui_length_split_list = []



@functools.lru_cache(maxsize=1)
def parse_wireshark_oui_database():
    """
    Parse the Wireshark OUI database and populates the OUI-to-company mapping.

    This function reads the `wireshark_oui_database.txt` resource file, which contains mappings
    from OUI prefixes to company names, and populates the global `_oui_dict` with these mappings.
    It also determines the set of unique OUI prefix lengths found in the database and stores them
    in `_oui_length_split_list` for use in vendor lookups.

    The function is cached to ensure the database is only parsed once per process lifetime,
    improving performance for repeated lookups.

    File Format:
        Each line in the database file should be tab-separated, with the OUI prefix, an unused field,
        and the company name. Lines starting with '#' or empty lines are ignored.

    Side Effects:
        - Populates the global `_oui_dict` with OUI-to-company mappings.
        - Populates the global `_oui_length_split_list` with sorted OUI prefix lengths.

    Returns:
        None
    """
    _oui_length_splits = set()
    with importlib.resources.files('libinspector').joinpath('wireshark_oui_database.txt').open('r', encoding='utf-8') as fp:
        for line in fp:
            line = line.strip()
            if line == '' or line.startswith('#'):
                continue
            (oui, _, company) = line.split('\t')
            oui = oui.split('/', 1)[0].lower().replace(':', '').strip()
            _oui_dict[oui] = company.strip()
            _oui_length_splits.add(len(oui))

    _oui_length_split_list.extend(sorted(_oui_length_splits))



@functools.lru_cache(maxsize=1024)
def get_vendor(mac_addr: str) -> str:
    """
    Retrieve the vendor or company name associated with a given MAC address.

    This function normalizes the input MAC address by removing common delimiters and converting
    it to lowercase. It then attempts to match the longest possible OUI prefix from the MAC address
    against the entries in the OUI database, as loaded by `parse_wireshark_oui_database()`.
    If a matching OUI is found, the corresponding company name is returned; otherwise, an empty
    string is returned to indicate an unknown vendor.

    The function uses LRU caching to optimize repeated lookups for the same MAC addresses.

    Args:
        mac_addr (str): The MAC address to look up. Accepts formats with colons, dashes, or dots.

    Returns:
        str: The vendor or company name associated with the MAC address, or an empty string if unknown.

    Example:
        >>> get_vendor('00:1A:2B:3C:4D:5E')
        'Example Corp'
    """
    parse_wireshark_oui_database()

    mac_addr = mac_addr.lower().replace(':', '').replace('-', '').replace('.', '')

    # Split the MAC address in different ways and check against the oui_dict
    for split_length in _oui_length_split_list:
        oui = mac_addr[:split_length]
        if oui in _oui_dict:
            return _oui_dict[oui]

    return ''

