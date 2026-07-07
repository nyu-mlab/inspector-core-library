"""
Tests for libinspector.tls_processor.
"""

import unittest

import scapy.all as sc
from scapy.layers.tls.extensions import (
    TLS_Ext_ServerName,
    ServerName,
    TLS_Ext_SupportedGroups,
)
from scapy.layers.tls.handshake import TLSClientHello

from libinspector.tls_processor import extract_sni


class TestExtractSni(unittest.TestCase):
    def _packet(self, client_hello=None):
        pkt = (
            sc.Ether(src="aa:bb:cc:dd:ee:ff", dst="10:00:00:00:00:01")
            / sc.IP(src="192.168.1.55", dst="93.184.216.34")
            / sc.TCP(sport=5000, dport=443)
        )
        if client_hello is not None:
            pkt = pkt / client_hello
        return pkt

    def test_returns_sni_when_present(self):
        # Finds the website name inside a TLS handshake.
        client_hello = TLSClientHello(
            ext=[
                TLS_Ext_ServerName(servernames=[ServerName(servername=b"example.com")])
            ]
        )
        self.assertEqual(extract_sni(self._packet(client_hello)), "example.com")

    def test_returns_empty_for_non_sni_extension(self):
        # Handshakes with other info but no website name return nothing.
        client_hello = TLSClientHello(ext=[TLS_Ext_SupportedGroups(groups=["x25519"])])
        self.assertEqual(extract_sni(self._packet(client_hello)), "")

    def test_returns_empty_for_malformed_sni_extension(self):
        # A broken website-name field is handled without crashing.
        client_hello = TLSClientHello(ext=[TLS_Ext_ServerName(servernames=[])])
        self.assertEqual(extract_sni(self._packet(client_hello)), "")

    def test_returns_empty_without_tls_layer(self):
        # Plain packets with no TLS handshake return nothing.
        self.assertEqual(extract_sni(self._packet()), "")


if __name__ == "__main__":
    unittest.main()
