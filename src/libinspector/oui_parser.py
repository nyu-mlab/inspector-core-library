"""
Parses and extracts the company based on the MAC address.

"""
import functools
import importlib.resources


# Maps the first 3 (or more) bytes of the MAC address to the company name.
_oui_dict = {}

_oui_length_split_list = []



@functools.lru_cache(maxsize=1)
def parse_wireshark_oui_database():
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
    """Given a MAC address, returns the vendor. Returns '' if unknown. """

    parse_wireshark_oui_database()

    mac_addr = mac_addr.lower().replace(':', '').replace('-', '').replace('.', '')

    # Split the MAC address in different ways and check against the oui_dict
    for split_length in _oui_length_split_list:
        oui = mac_addr[:split_length]
        if oui in _oui_dict:
            return _oui_dict[oui]

    return ''

