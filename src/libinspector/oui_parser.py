"""
OUI (Organizationally Unique Identifier) Parser Module.

This module provides functionality to parse and extract the vendor or company name
associated with a given MAC address using a locally downloaded IEEE OUI database.
It loads the OUI-to-company mapping from a resource file or a local CSV and
efficiently caches lookups for performance.

MA-L (Large): https://standards-oui.ieee.org/oui/oui.csv
MA-M (Medium): https://standards-oui.ieee.org/oui28/mam.csv
MA-S (Small): https://standards-oui.ieee.org/oui36/oui36.csv

Key Features:
- Loads and parses the IEEE OUI database from a local CSV file.
- Supports OUI prefixes of varying lengths for accurate vendor identification.
- Uses LRU caching to optimize repeated lookups and database parsing.
- Provides simple interfaces to retrieve the vendor for a given MAC address.

Intended Usage:
Call `get_vendor(mac_addr)` with a MAC address string to retrieve the associated
vendor or company name.

Dependencies:
- functools
- os
- csv (for parsing the IEEE file)

Resource Files:
- oui.csv
- mam.csv
- oui36.csv
"""
import functools
import os
import csv

# Maps the first 3 (or more) bytes of the MAC address to the company name.
_oui_dict = {}

_oui_length_split_list = []


@functools.lru_cache(maxsize=1)
def parse_ieee_oui_database_from_local_csv():
    """
    Parse local IEEE OUI databases (MA-L, MA-M, and MA-S) and populate the OUI-to-company mapping.
    See Module Docstring for more details where the files were obtained from.

    This function reads the `oui.csv`, `mam.csv`, and `oui36.csv` files from a local directory,
    which contain mappings from OUI prefixes to company names. It populates the global `_oui_dict`
    with these mappings. It clears any previously loaded data to ensure only the latest
    IEEE data is used. It also determines the set of unique OUI prefix lengths found in the
    databases and stores them in `_oui_length_split_list`.

    The function is cached to ensure the database is only parsed once per process lifetime,
    improving performance for repeated lookups.

    File Format (Expected):
        The CSV files are expected to have an OUI prefix in the 'Assignment' column and the
        company name in the 'Organization Name' column. They also contain a header row which
        is skipped.

    Side Effects:
        - Populates the global `_oui_dict` with OUI-to-company mappings, clearing any old data.
        - Populates the global `_oui_length_split_list` with sorted OUI prefix lengths,
          clearing any old data.

    Returns:
        None
    """
    # Clear existing data to avoid conflicts with other database parsers
    _oui_dict.clear()
    _oui_length_split_list.clear()

    _oui_length_splits = set()
    data_files = ['oui.csv', 'mam.csv', 'oui36.csv']

    for filename in data_files:
        data_path = os.path.join(os.path.dirname(__file__), 'data', 'oui', filename)
        data_path = os.path.abspath(data_path)

        try:
            with open(data_path, 'r', encoding='utf-8') as fp:
                reader = csv.reader(fp)
                header = next(reader, None)  # Skip the header row

                if header is None:
                    continue

                try:
                    oui_index = header.index("Assignment")
                    company_index = header.index("Organization Name")
                except ValueError:
                    continue

                for row in reader:
                    try:
                        oui = row[oui_index].lower().strip()
                        company = row[company_index].strip()
                        _oui_dict[oui] = company
                        _oui_length_splits.add(len(oui))
                    except IndexError:
                        continue
        except FileNotFoundError:
            # Continue to the next file if one is not found
            continue

    _oui_length_split_list.extend(sorted(_oui_length_splits, reverse=True))


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
    parse_ieee_oui_database_from_local_csv()

    mac_addr = mac_addr.lower().replace(':', '').replace('-', '').replace('.', '')

    # Split the MAC address in different ways and check against the oui_dict
    for split_length in _oui_length_split_list:
        oui = mac_addr[:split_length]
        if oui in _oui_dict:
            return _oui_dict[oui]

    return ''
