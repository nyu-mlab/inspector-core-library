"""
Functions for processing the TLS layer in packets.

This module is in a separate file because I don't want `from scapy.all import *` (required for `TLSClientHello`) to pollute the namespace.

"""
from scapy.layers.tls.handshake import TLSClientHello


def extract_sni(packet) -> str:
    """
    Return the Server Name Indication (SNI) from a TLS packet, or an empty string if not present.

    This function inspects the given packet for a TLSClientHello layer and attempts to extract the SNI
    (Server Name Indication) extension, which indicates the hostname the client is attempting to connect to.
    If the SNI extension is not found or the packet does not contain a TLSClientHello, an empty string is returned.

    Args:
        packet: The packet object to inspect, expected to be a Scapy packet.

    Returns:
        str: The extracted SNI as a string, or an empty string if not found.
    """
    try:
        tls_layer = packet[TLSClientHello] # type: ignore
    except IndexError:
        return ''

    for attr in ['ext', 'extensions']:
        extensions = getattr(tls_layer, attr, [])
        if extensions:
            for extension in extensions:
                try:
                    if extension.type == 0:
                        return extension.servernames[0].servername.decode()
                except Exception:
                    pass

    return ''