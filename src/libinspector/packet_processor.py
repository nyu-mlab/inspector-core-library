import time
import scapy.all as sc
import traceback
import logging
import json

from . import global_state
from .tls_processor import extract_sni
from . import networking


logger = logging.getLogger(__name__)

update_hostnames_in_flows_status_dict = {
    'last_update_ts': 0
}



def start():

    pkt = global_state.packet_queue.get()

    try:
        process_packet_helper(pkt)

    except Exception as e:
        logger.error(f'[Pkt Processor] Error processing packet: {e} for packet: {pkt}\n{traceback.format_exc()}')


def process_packet_helper(pkt):

    with global_state.global_state_lock:
        pkt_callback_func = global_state.custom_packet_callback_func

    if pkt_callback_func is not None:
        try:
            pkt_callback_func(pkt)
        except Exception as e:
            logger.error(f'[Pkt Processor] Custom packet callback function raised an error: {e} for packet: {pkt}\n{traceback.format_exc()}')

    # ====================
    # Process individual packets and terminate
    # ====================

    if sc.ARP in pkt:
        return process_arp(pkt)

    if sc.DHCP in pkt:
        return process_dhcp(pkt)

    # Must have Ether frame and IP frame.
    if not (sc.Ether in pkt and sc.IP in pkt):
        return

    # Ignore traffic to and from this host's IP. Hopefully we don't hit this statement because the sniff filter already excludes this host's IP.
    if global_state.host_ip_addr in (pkt[sc.IP].src, pkt[sc.IP].dst):
        return

    # DNS
    if sc.DNS in pkt:
        return process_dns(pkt)

    # ====================
    # Process flows and their first packets
    # ====================

    process_client_hello(pkt)

    # Process flow
    return process_flow(pkt)


def process_arp(pkt):
    """
    Updates ARP cache upon receiving ARP packets, only if the packet is not
    spoofed.

    """
    if not ((pkt.op == 1 or pkt.op == 2)):
        return

    if pkt.hwsrc == global_state.host_mac_addr:
        return

    if pkt.psrc == '0.0.0.0':
        return

    ip_addr = pkt.psrc
    mac_addr = pkt.hwsrc

    # Check if this is the gateway
    with global_state.global_state_lock:
        if ip_addr == global_state.gateway_ip_addr:
            is_gateway = 1
        else:
            is_gateway = 0

    # Insert or update the ip_addr and mac_addr in the devices table
    current_ts = int(time.time())
    conn, rw_lock = global_state.db_conn_and_lock
    with rw_lock:
        conn.execute('''
            INSERT INTO devices (mac_address, ip_address, updated_ts, is_gateway)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(mac_address) DO UPDATE SET
                ip_address=excluded.ip_address,
                updated_ts=excluded.updated_ts,
                is_gateway=excluded.is_gateway
        ''', (mac_addr, ip_addr, current_ts, is_gateway))

    # Update the OUI vendors
    with rw_lock:
        conn.execute('''
            UPDATE devices
            SET metadata_json = json_patch(
                metadata_json,
                json_object('oui_vendor', get_oui_vendor(mac_address))
            )
            WHERE json_extract(metadata_json, '$.oui_vendor') IS NULL
        ''')


def process_dns(pkt):

    src_mac_addr = pkt[sc.Ether].src
    dst_mac_addr = pkt[sc.Ether].dst

    # Find the device that makes this DNS request or response
    with global_state.global_state_lock:
        if global_state.host_mac_addr == src_mac_addr:
            device_mac_addr = dst_mac_addr
        elif global_state.host_mac_addr == dst_mac_addr:
            device_mac_addr = src_mac_addr
        else:
            return
        gateway_ip_addr = global_state.gateway_ip_addr

    # Find the gateway's MAC address given its known IP address
    try:
        gateway_mac_addr = networking.get_mac_address_from_ip(gateway_ip_addr)
    except KeyError:
        return

    # This device cannot be the gateway; otherwise, it'd be a direct communication between the gateway and this host
    if device_mac_addr == gateway_mac_addr:
        return

    # Parse hostname
    try:
        hostname = pkt[sc.DNSQR].qname.decode('utf-8').lower()
    except Exception:
        return

    # Remove trailing dot from hostname
    if hostname[-1] == '.':
        hostname = hostname[0:-1]

    # Parse DNS response to extract IP addresses in A records
    ip_set = set()
    if sc.DNSRR in pkt and pkt[sc.DNS].an:
        for ix in range(pkt[sc.DNS].ancount):
            # Extracts A-records
            try:
                if pkt[sc.DNSRR][ix].type == 1:
                    # Extracts IPv4 addr in A-record
                    ip = pkt[sc.DNSRR][ix].rdata
                    if networking.is_ipv4_addr(ip):
                        ip_set.add(ip)
            except IndexError:
                pass

    # If we don't have an IP address, that's fine. We'll still store the domain queried, setting the IP address to empty.
    if not ip_set:
        ip_set.add('')

    write_hostname_ip_mapping_to_db(device_mac_addr, hostname, ip_set, 'dns')


def write_hostname_ip_mapping_to_db(device_mac_addr, hostname, ip_set, data_source):

    current_ts = int(time.time())

    conn, rw_lock = global_state.db_conn_and_lock

    with rw_lock:
        for ip_addr in ip_set:
            conn.execute('''
                INSERT INTO hostnames (ip_address, hostname, updated_ts, data_source)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    hostname=excluded.hostname,
                    updated_ts=excluded.updated_ts,
                    data_source=excluded.data_source
            ''', (ip_addr, hostname, current_ts, data_source))

    logger.info(f'[Pkt Processor] Device {device_mac_addr}: {hostname} -> {ip_set} (data_source: {data_source})')



def process_flow(pkt):

    # Must have TCP or UDP layer
    if sc.TCP in pkt:
        protocol = 'tcp'
        layer = sc.TCP
    elif sc.UDP in pkt:
        protocol = 'udp'
        layer = sc.UDP
    else:
        return

    # Parse packet
    src_mac_addr = pkt[sc.Ether].src
    dst_mac_addr = pkt[sc.Ether].dst
    src_ip_addr = pkt[sc.IP].src
    dst_ip_addr = pkt[sc.IP].dst
    src_port = pkt[layer].sport
    dst_port = pkt[layer].dport

    # Extract the TCP sequence number
    if sc.TCP in pkt:
        tcp_seq = pkt[sc.TCP].seq
    else:
        tcp_seq = 0

    # No broadcast
    if dst_mac_addr == 'ff:ff:ff:ff:ff:ff' or dst_ip_addr == '255.255.255.255':
        return

    with global_state.global_state_lock:
        inspector_host_mac_addr = global_state.host_mac_addr

    # Find the actual MAC address that the Inspector host pretends to be if this
    # is a local communication; otherwise, assume that Inspector pretends to be
    # the gateway.
    if src_mac_addr == inspector_host_mac_addr:
        try:
            src_mac_addr = networking.get_mac_address_from_ip(src_ip_addr)
        except KeyError:
            return
    elif dst_mac_addr == inspector_host_mac_addr:
        try:
            dst_mac_addr = networking.get_mac_address_from_ip(dst_ip_addr)
        except KeyError:
            return
    else:
        return

    # Upsert the flow into the `network_flows` table in the database
    conn, rw_lock = global_state.db_conn_and_lock
    current_ts = int(time.time())
    with rw_lock:
        conn.execute('''
            INSERT INTO network_flows (
                timestamp, src_ip_address, dest_ip_address, src_mac_address, dest_mac_address,
                src_port, dest_port, protocol, byte_count, packet_count, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, json_object('tcp_seq_min', ?, 'tcp_seq_max', ?))
            ON CONFLICT (
                timestamp, src_mac_address, dest_mac_address, src_ip_address, dest_ip_address,
                src_port, dest_port, protocol
            ) DO UPDATE SET
                byte_count = byte_count + excluded.byte_count,
                packet_count = packet_count + excluded.packet_count,
                metadata_json = json_patch(
                    metadata_json,
                    json_object(
                        'tcp_seq_min', MIN(json_extract(metadata_json, '$.tcp_seq_min'), excluded.metadata_json->>'$.tcp_seq_min'),
                        'tcp_seq_max', MAX(json_extract(metadata_json, '$.tcp_seq_max'), excluded.metadata_json->>'$.tcp_seq_max')
                    )
                )
        ''', (
            current_ts, src_ip_addr, dst_ip_addr, src_mac_addr, dst_mac_addr,
            src_port, dst_port, protocol, len(pkt), 1, tcp_seq, tcp_seq
        ))

    update_hostnames_in_flows()


def update_hostnames_in_flows():
    """
    Every 2 seconds, we replace the ip_addresses with the hostnames from the hostnames table.

    """
    if time.time() - update_hostnames_in_flows_status_dict['last_update_ts'] < 2:
        return

    conn, rw_lock = global_state.db_conn_and_lock

    with rw_lock:
        sql = '''
            UPDATE network_flows
            SET src_hostname = (
                SELECT hostnames.hostname
                FROM hostnames
                WHERE hostnames.ip_address = network_flows.src_ip_address
            ),
            dest_hostname = (
                SELECT hostnames.hostname
                FROM hostnames
                WHERE hostnames.ip_address = network_flows.dest_ip_address
            )
            WHERE EXISTS (
                SELECT 1
                FROM hostnames
                WHERE
                    (
                        hostnames.ip_address = network_flows.src_ip_address OR
                        hostnames.ip_address = network_flows.dest_ip_address
                    ) AND (
                        network_flows.src_hostname IS NULL OR
                        network_flows.dest_hostname IS NULL
                    )
            );
        '''
        row_count = conn.execute(sql).rowcount

    update_hostnames_in_flows_status_dict['last_update_ts'] = time.time()

    logger.info(f'[Pkt Processor] Updated {row_count} rows in network_flows with hostnames.')


def process_dhcp(pkt):

    # Must be a DHCP Request broadcast
    if pkt[sc.Ether].dst != 'ff:ff:ff:ff:ff:ff':
        return

    try:
        option_dict = dict(
            [t for t in pkt[sc.DHCP].options if isinstance(t, tuple)]
        )
    except Exception:
        return

    try:
        device_hostname = option_dict.setdefault('hostname', '').decode('utf-8')
        if device_hostname == '':
            return
    except Exception:
        return

    device_mac = pkt[sc.Ether].src
    device_ip = pkt[sc.IP].src

    # Ignore DHCP responses from this host
    if device_mac == global_state.host_mac_addr:
        return

    # Update the devices table
    device_metadata_dict = {'dhcp_hostname': device_hostname}
    conn, rw_lock = global_state.db_conn_and_lock
    with rw_lock:
        conn.execute('''
            INSERT INTO devices (mac_address, ip_address, metadata_json)
            VALUES (?, ?, ?)
            ON CONFLICT(mac_address) DO UPDATE SET
                metadata_json = json_patch(devices.metadata_json, excluded.metadata_json),
                ip_address = excluded.ip_address
        ''', (device_mac, device_ip, json.dumps(device_metadata_dict)))

    logger.info(f'[Pkt Processor] DHCP: Device {device_mac}: {device_hostname}')


def process_client_hello(pkt):
    """Extracts the SNI field from the ClientHello packet."""

    # Make sure that the Inspector host should be the destination of this packet
    with global_state.global_state_lock:
        if pkt[sc.Ether].dst != global_state.host_mac_addr:
            return

    sni = extract_sni(pkt)
    if not sni:
        return

    sni = sni.lower()
    device_mac_addr = pkt[sc.Ether].src
    remote_ip_addr = pkt[sc.IP].dst

    write_hostname_ip_mapping_to_db(device_mac_addr, sni, {remote_ip_addr}, 'sni')
