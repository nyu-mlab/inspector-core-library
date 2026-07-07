"""
Tests for libinspector.packet_processor.
"""

import json
import os
import unittest
from unittest import mock

import scapy.all as sc

import libinspector.global_state as global_state
import libinspector.mem_db as mem_db
import libinspector.packet_processor as packet_processor


class PacketProcessorTestCase(unittest.TestCase):
    """Base fixture: fresh in-memory DB and fake host identity in global_state."""

    HOST_MAC = "10:00:00:00:00:01"
    HOST_IP = "192.168.1.100"
    GATEWAY_MAC = "20:00:00:00:00:01"
    GATEWAY_IP = "192.168.1.1"
    DEVICE_MAC = "aa:bb:cc:dd:ee:ff"
    DEVICE_IP = "192.168.1.55"

    def setUp(self):
        env_patcher = mock.patch.dict(os.environ)
        env_patcher.start()
        self.addCleanup(env_patcher.stop)
        os.environ.pop("USE_IN_MEMORY_DB", None)
        os.environ.pop("SCAN_ALL_DEVICES", None)

        self.conn, self.rw_lock = mem_db.initialize_db()
        self.addCleanup(self.conn.close)

        with global_state.global_state_lock:
            self._saved_state = (
                global_state.db_conn_and_lock,
                global_state.host_mac_addr,
                global_state.host_ip_addr,
                global_state.gateway_ip_addr,
            )
            global_state.db_conn_and_lock = (self.conn, self.rw_lock)
            global_state.host_mac_addr = self.HOST_MAC
            global_state.host_ip_addr = self.HOST_IP
            global_state.gateway_ip_addr = self.GATEWAY_IP
        self.addCleanup(self._restore_global_state)

    def _restore_global_state(self):
        with global_state.global_state_lock:
            (
                global_state.db_conn_and_lock,
                global_state.host_mac_addr,
                global_state.host_ip_addr,
                global_state.gateway_ip_addr,
            ) = self._saved_state

    def count(self, table):
        with self.rw_lock:
            return self.conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()[
                "n"
            ]


class TestProcessArp(PacketProcessorTestCase):
    def _arp(self, op=2, hwsrc=None, psrc=None):
        return sc.ARP(
            op=op,
            hwsrc=hwsrc or self.DEVICE_MAC,
            psrc=psrc or self.DEVICE_IP,
        )

    def test_inserts_device_with_oui_vendor(self):
        packet_processor.process_arp(self._arp())

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT * FROM devices WHERE mac_address = ?", (self.DEVICE_MAC,)
            ).fetchone()

        self.assertEqual(row["ip_address"], self.DEVICE_IP)
        self.assertEqual(row["is_gateway"], 0)
        self.assertGreater(row["updated_ts"], 0)
        self.assertIn("oui_vendor", json.loads(row["metadata_json"]))

    def test_gateway_flag_set_for_gateway_ip(self):
        packet_processor.process_arp(
            self._arp(hwsrc=self.GATEWAY_MAC, psrc=self.GATEWAY_IP)
        )

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT is_gateway FROM devices WHERE mac_address = ?",
                (self.GATEWAY_MAC,),
            ).fetchone()

        self.assertEqual(row["is_gateway"], 1)

    def test_ignores_packet_from_host(self):
        packet_processor.process_arp(self._arp(hwsrc=self.HOST_MAC))
        self.assertEqual(self.count("devices"), 0)

    def test_ignores_zero_source_ip(self):
        packet_processor.process_arp(self._arp(psrc="0.0.0.0"))
        self.assertEqual(self.count("devices"), 0)

    def test_ignores_non_request_reply_opcodes(self):
        packet_processor.process_arp(self._arp(op=3))
        self.assertEqual(self.count("devices"), 0)

    def test_updates_ip_for_existing_device(self):
        packet_processor.process_arp(self._arp(psrc="192.168.1.55"))
        packet_processor.process_arp(self._arp(psrc="192.168.1.66"))

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT ip_address FROM devices WHERE mac_address = ?",
                (self.DEVICE_MAC,),
            ).fetchone()

        self.assertEqual(self.count("devices"), 1)
        self.assertEqual(row["ip_address"], "192.168.1.66")


class TestProcessDhcp(PacketProcessorTestCase):
    def _dhcp(
        self, ether_dst="ff:ff:ff:ff:ff:ff", ether_src=None, hostname=b"my-iot-device"
    ):
        options = [("message-type", "request")]
        if hostname is not None:
            options.append(("hostname", hostname))
        options.append("end")
        return (
            sc.Ether(src=ether_src or self.DEVICE_MAC, dst=ether_dst)
            / sc.IP(src=self.DEVICE_IP, dst="255.255.255.255")
            / sc.UDP(sport=68, dport=67)
            / sc.BOOTP()
            / sc.DHCP(options=options)
        )

    def test_inserts_device_with_dhcp_hostname(self):
        packet_processor.process_dhcp(self._dhcp())

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT * FROM devices WHERE mac_address = ?", (self.DEVICE_MAC,)
            ).fetchone()

        self.assertEqual(row["ip_address"], self.DEVICE_IP)
        metadata = json.loads(row["metadata_json"])
        self.assertEqual(metadata["dhcp_hostname"], "my-iot-device")

    def test_ignores_non_broadcast(self):
        packet_processor.process_dhcp(self._dhcp(ether_dst=self.HOST_MAC))
        self.assertEqual(self.count("devices"), 0)

    def test_ignores_missing_hostname_option(self):
        packet_processor.process_dhcp(self._dhcp(hostname=None))
        self.assertEqual(self.count("devices"), 0)

    def test_ignores_packet_from_host(self):
        packet_processor.process_dhcp(self._dhcp(ether_src=self.HOST_MAC))
        self.assertEqual(self.count("devices"), 0)


class TestWriteHostnameIpMappingToDb(PacketProcessorTestCase):
    def test_inserts_one_row_per_ip(self):
        packet_processor.write_hostname_ip_mapping_to_db(
            self.DEVICE_MAC, "example.com", {"1.2.3.4", "5.6.7.8"}, "dns"
        )

        with self.rw_lock:
            rows = self.conn.execute(
                "SELECT ip_address, hostname, data_source FROM hostnames"
            ).fetchall()

        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["hostname"], "example.com")
            self.assertEqual(row["data_source"], "dns")
        self.assertEqual({row["ip_address"] for row in rows}, {"1.2.3.4", "5.6.7.8"})

    def test_upsert_replaces_hostname_for_existing_ip(self):
        packet_processor.write_hostname_ip_mapping_to_db(
            self.DEVICE_MAC, "old.example.com", {"1.2.3.4"}, "dns"
        )
        packet_processor.write_hostname_ip_mapping_to_db(
            self.DEVICE_MAC, "new.example.com", {"1.2.3.4"}, "sni"
        )

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT hostname, data_source FROM hostnames WHERE ip_address = ?",
                ("1.2.3.4",),
            ).fetchone()

        self.assertEqual(self.count("hostnames"), 1)
        self.assertEqual(row["hostname"], "new.example.com")
        self.assertEqual(row["data_source"], "sni")


class TestUpdateHostnamesInFlows(PacketProcessorTestCase):
    def test_fills_missing_hostnames_from_hostnames_table(self):
        with self.rw_lock:
            self.conn.execute(
                """
                INSERT INTO network_flows (
                    timestamp, src_ip_address, dest_ip_address,
                    src_mac_address, dest_mac_address, src_port, dest_port, protocol
                ) VALUES (1000, '192.168.1.55', '1.2.3.4', ?, ?, '5000', '443', 'tcp')
                """,
                (self.DEVICE_MAC, self.GATEWAY_MAC),
            )
            self.conn.execute(
                "INSERT INTO hostnames (ip_address, hostname, data_source) "
                "VALUES ('192.168.1.55', 'device.local', 'dns')"
            )
            self.conn.execute(
                "INSERT INTO hostnames (ip_address, hostname, data_source) "
                "VALUES ('1.2.3.4', 'example.com', 'dns')"
            )

        packet_processor.update_hostnames_in_flows()

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT src_hostname, dest_hostname FROM network_flows"
            ).fetchone()

        self.assertEqual(row["src_hostname"], "device.local")
        self.assertEqual(row["dest_hostname"], "example.com")


class TestProcessDns(PacketProcessorTestCase):
    def _dns(
        self, ether_src=None, ether_dst=None, qname="example.com.", answer_ip=None
    ):
        pkt = (
            sc.Ether(src=ether_src or self.DEVICE_MAC, dst=ether_dst or self.HOST_MAC)
            / sc.IP(src=self.DEVICE_IP, dst="8.8.8.8")
            / sc.UDP(sport=12345, dport=53)
        )
        if answer_ip:
            pkt = pkt / sc.DNS(
                qr=1,
                qd=sc.DNSQR(qname=qname),
                an=sc.DNSRR(rrname=qname, type=1, rdata=answer_ip),
            )
        else:
            pkt = pkt / sc.DNS(qd=sc.DNSQR(qname=qname))
        # Rebuild so scapy fills in computed fields like ancount.
        return sc.Ether(bytes(pkt))

    def _patch_gateway_mac(self, side_effect=None):
        patcher = mock.patch.object(
            packet_processor.networking,
            "get_mac_address_from_ip",
            side_effect=side_effect,
            return_value=self.GATEWAY_MAC,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_stores_hostname_with_answer_ip(self):
        # A DNS answer saves the website name and its IP address.
        self._patch_gateway_mac()
        packet_processor.process_dns(self._dns(answer_ip="1.2.3.4"))

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT hostname, data_source FROM hostnames WHERE ip_address = '1.2.3.4'"
            ).fetchone()

        self.assertEqual(row["hostname"], "example.com")
        self.assertEqual(row["data_source"], "dns")

    def test_stores_hostname_with_empty_ip_when_no_answer(self):
        # A DNS question with no answer still saves the website name.
        self._patch_gateway_mac()
        packet_processor.process_dns(self._dns())

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT hostname FROM hostnames WHERE ip_address = ''"
            ).fetchone()

        self.assertEqual(row["hostname"], "example.com")

    def test_ignores_packet_not_involving_host(self):
        # Traffic between two other machines is ignored.
        self._patch_gateway_mac()
        packet_processor.process_dns(
            self._dns(ether_src=self.DEVICE_MAC, ether_dst="30:00:00:00:00:01")
        )
        self.assertEqual(self.count("hostnames"), 0)

    def test_ignores_dns_from_gateway(self):
        # DNS traffic from the router itself is ignored.
        self._patch_gateway_mac()
        packet_processor.process_dns(self._dns(ether_src=self.GATEWAY_MAC))
        self.assertEqual(self.count("hostnames"), 0)

    def test_ignores_when_gateway_mac_unknown(self):
        # If the router's address can't be found, nothing is saved.
        self._patch_gateway_mac(side_effect=KeyError)
        packet_processor.process_dns(self._dns(answer_ip="1.2.3.4"))
        self.assertEqual(self.count("hostnames"), 0)


class TestProcessFlow(PacketProcessorTestCase):
    def _tcp(self, ether_src=None, ether_dst=None, ip_src=None, ip_dst="93.184.216.34"):
        return (
            sc.Ether(src=ether_src or self.DEVICE_MAC, dst=ether_dst or self.HOST_MAC)
            / sc.IP(src=ip_src or self.DEVICE_IP, dst=ip_dst)
            / sc.TCP(sport=5000, dport=443, seq=42)
        )

    def _patch_mac_lookup(self, side_effect=None):
        patcher = mock.patch.object(
            packet_processor.networking,
            "get_mac_address_from_ip",
            side_effect=side_effect,
            return_value=self.GATEWAY_MAC,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_tcp_flow_inserted(self):
        # One TCP packet creates one flow record with the right details.
        self._patch_mac_lookup()
        pkt = self._tcp()
        packet_processor.process_flow(pkt)

        with self.rw_lock:
            row = self.conn.execute("SELECT * FROM network_flows").fetchone()

        self.assertEqual(row["protocol"], "tcp")
        self.assertEqual(row["src_ip_address"], self.DEVICE_IP)
        self.assertEqual(row["dest_mac_address"], self.GATEWAY_MAC)
        self.assertEqual(row["packet_count"], 1)
        self.assertEqual(row["byte_count"], len(pkt))
        metadata = json.loads(row["metadata_json"])
        self.assertEqual(metadata["tcp_seq_min"], 42)
        self.assertEqual(metadata["tcp_seq_max"], 42)

    def test_repeated_packets_update_counts(self):
        # Sending the same packet twice doubles the byte and packet counts.
        self._patch_mac_lookup()
        pkt = self._tcp()
        with mock.patch("time.time", return_value=1000.0):
            packet_processor.process_flow(pkt)
            packet_processor.process_flow(pkt)

        with self.rw_lock:
            row = self.conn.execute("SELECT * FROM network_flows").fetchone()

        self.assertEqual(self.count("network_flows"), 1)
        self.assertEqual(row["packet_count"], 2)
        self.assertEqual(row["byte_count"], 2 * len(pkt))

    def test_udp_flow_inserted(self):
        # A UDP packet creates a flow record marked as UDP.
        self._patch_mac_lookup()
        pkt = (
            sc.Ether(src=self.DEVICE_MAC, dst=self.HOST_MAC)
            / sc.IP(src=self.DEVICE_IP, dst="93.184.216.34")
            / sc.UDP(sport=5000, dport=53)
        )
        packet_processor.process_flow(pkt)

        with self.rw_lock:
            row = self.conn.execute("SELECT protocol FROM network_flows").fetchone()

        self.assertEqual(row["protocol"], "udp")

    def test_ignores_broadcast(self):
        # Packets sent to everyone (broadcast) are ignored.
        self._patch_mac_lookup()
        packet_processor.process_flow(self._tcp(ether_dst="ff:ff:ff:ff:ff:ff"))
        self.assertEqual(self.count("network_flows"), 0)

    def test_ignores_packet_not_involving_host(self):
        # Traffic between two other machines is ignored.
        self._patch_mac_lookup()
        packet_processor.process_flow(
            self._tcp(ether_src=self.DEVICE_MAC, ether_dst="30:00:00:00:00:01")
        )
        self.assertEqual(self.count("network_flows"), 0)

    def test_ignores_non_tcp_udp(self):
        # Packets that aren't TCP or UDP are ignored.
        self._patch_mac_lookup()
        pkt = (
            sc.Ether(src=self.DEVICE_MAC, dst=self.HOST_MAC)
            / sc.IP(src=self.DEVICE_IP, dst="93.184.216.34")
            / sc.ICMP()
        )
        packet_processor.process_flow(pkt)
        self.assertEqual(self.count("network_flows"), 0)

    def test_ignores_when_mac_lookup_fails(self):
        # If the device's address can't be found, nothing is saved.
        self._patch_mac_lookup(side_effect=KeyError)
        packet_processor.process_flow(self._tcp())
        self.assertEqual(self.count("network_flows"), 0)


class TestProcessClientHello(PacketProcessorTestCase):
    def _tls(self, ether_dst=None):
        return (
            sc.Ether(src=self.DEVICE_MAC, dst=ether_dst or self.HOST_MAC)
            / sc.IP(src=self.DEVICE_IP, dst="93.184.216.34")
            / sc.TCP(sport=5000, dport=443)
        )

    def test_stores_lowercased_sni(self):
        # The website name from a TLS handshake is saved in lowercase.
        with mock.patch.object(
            packet_processor, "extract_sni", return_value="Example.COM"
        ):
            packet_processor.process_client_hello(self._tls())

        with self.rw_lock:
            row = self.conn.execute(
                "SELECT hostname, data_source FROM hostnames "
                "WHERE ip_address = '93.184.216.34'"
            ).fetchone()

        self.assertEqual(row["hostname"], "example.com")
        self.assertEqual(row["data_source"], "sni")

    def test_ignores_packet_not_destined_to_host(self):
        # Handshakes not passing through this computer are ignored.
        with mock.patch.object(
            packet_processor, "extract_sni", return_value="example.com"
        ) as mock_sni:
            packet_processor.process_client_hello(self._tls(ether_dst=self.GATEWAY_MAC))

        mock_sni.assert_not_called()
        self.assertEqual(self.count("hostnames"), 0)

    def test_ignores_packet_without_sni(self):
        # Handshakes with no website name save nothing.
        with mock.patch.object(packet_processor, "extract_sni", return_value=""):
            packet_processor.process_client_hello(self._tls())
        self.assertEqual(self.count("hostnames"), 0)


class TestProcessHttpUserAgent(PacketProcessorTestCase):
    def _http(self, dport=80, payload=None):
        if payload is None:
            payload = (
                b"GET / HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"User-Agent: TestAgent/1.0\r\n\r\n"
            )
        return (
            sc.Ether(src=self.DEVICE_MAC, dst=self.HOST_MAC)
            / sc.IP(src=self.DEVICE_IP, dst="93.184.216.34")
            / sc.TCP(sport=5000, dport=dport)
            / sc.Raw(load=payload)
        )

    def _seed_device(self):
        with self.rw_lock:
            self.conn.execute(
                "INSERT INTO devices (mac_address, ip_address) VALUES (?, ?)",
                (self.DEVICE_MAC, self.DEVICE_IP),
            )

    def _get_metadata(self):
        with self.rw_lock:
            row = self.conn.execute(
                "SELECT metadata_json FROM devices WHERE mac_address = ?",
                (self.DEVICE_MAC,),
            ).fetchone()
        return json.loads(row["metadata_json"])

    def test_stores_user_agent(self):
        # The browser name from a web request is saved for the device.
        self._seed_device()
        packet_processor.process_http_user_agent(self._http())
        self.assertEqual(self._get_metadata()["user_agent_info"], "TestAgent/1.0")

    def test_ignores_non_http_port(self):
        # Web requests on unusual ports are ignored.
        self._seed_device()
        packet_processor.process_http_user_agent(self._http(dport=443))
        self.assertNotIn("user_agent_info", self._get_metadata())

    def test_ignores_non_request_payload(self):
        # Server replies (not requests) are ignored.
        self._seed_device()
        packet_processor.process_http_user_agent(
            self._http(payload=b"HTTP/1.1 200 OK\r\n\r\n")
        )
        self.assertNotIn("user_agent_info", self._get_metadata())

    def test_ignores_request_without_user_agent(self):
        # Requests missing a browser name save nothing.
        self._seed_device()
        packet_processor.process_http_user_agent(
            self._http(payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )
        self.assertNotIn("user_agent_info", self._get_metadata())


class TestStartAndDispatch(PacketProcessorTestCase):
    def setUp(self):
        super().setUp()
        while not global_state.packet_queue.empty():
            global_state.packet_queue.get(block=False)
        with global_state.global_state_lock:
            self._saved_callback = global_state.custom_packet_callback_func
        self.addCleanup(self._restore_callback)

    def _restore_callback(self):
        with global_state.global_state_lock:
            global_state.custom_packet_callback_func = self._saved_callback

    def test_start_processes_queued_packets(self):
        # Packets waiting in line get processed and saved.
        global_state.packet_queue.put(
            sc.ARP(op=2, hwsrc=self.DEVICE_MAC, psrc=self.DEVICE_IP)
        )
        packet_processor.start(timeout=0.01)

        self.assertTrue(global_state.packet_queue.empty())
        self.assertEqual(self.count("devices"), 1)

    def test_start_with_empty_queue_returns(self):
        # With no packets waiting, the worker just waits briefly.
        packet_processor.start(timeout=0.01)
        self.assertTrue(global_state.packet_queue.empty())

    def test_custom_callback_is_called(self):
        # A user-provided function gets to see every packet.
        callback = mock.Mock()
        with global_state.global_state_lock:
            global_state.custom_packet_callback_func = callback
        pkt = sc.ARP(op=2, hwsrc=self.DEVICE_MAC, psrc=self.DEVICE_IP)

        packet_processor.process_packet_helper(pkt)

        callback.assert_called_once_with(pkt)

    def test_crashing_callback_does_not_stop_processing(self):
        # A broken user function doesn't crash the packet worker.
        with global_state.global_state_lock:
            global_state.custom_packet_callback_func = mock.Mock(
                side_effect=ValueError("boom")
            )
        packet_processor.process_packet_helper(
            sc.ARP(op=2, hwsrc=self.DEVICE_MAC, psrc=self.DEVICE_IP)
        )
        self.assertEqual(self.count("devices"), 1)

    def test_dispatch_ignores_traffic_involving_host_ip(self):
        # Traffic to or from this computer itself is ignored.
        pkt = (
            sc.Ether(src=self.DEVICE_MAC, dst=self.HOST_MAC)
            / sc.IP(src=self.HOST_IP, dst="93.184.216.34")
            / sc.TCP(sport=5000, dport=443)
        )
        packet_processor.process_packet_helper(pkt)
        self.assertEqual(self.count("network_flows"), 0)


if __name__ == "__main__":
    unittest.main()
