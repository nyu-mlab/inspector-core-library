import logging
import json
import multiprocessing

from . import global_state
from . import mdns_discovery_helper


logger = logging.getLogger(__name__)




def start():
    """
    Discovers devices via mDNS. Saves the discovered devices to the `devices`
    table (under the `metadata_json` column) in the database.

    """
    logger.info("[mDNS] Discovering devices...")

    # I have to start the mdns_discovery_helper in a separate process. I
    # believe there is a bug in its original implementation that doesn't
    # properly close the socket. As a result, a few minutes of continuous
    # discovery will cause the OS to run out of sockets, even though I make sure
    # that the zeroconf object is closed after the discovery is done. Below is a
    # workaround to run the discovery in a separate process and then join it
    # back to the main process. Running it in a separate process allows the
    # socket to be properly closed when the process exits. - Danny
    result_queue = multiprocessing.Queue()
    proc = multiprocessing.Process(
        target=get_mdns_device_wrapper,
        args=(result_queue, )
    )
    proc.daemon = True
    proc.start()

    device_dict = result_queue.get()
    proc.join()

    conn, rw_lock = global_state.db_conn_and_lock

    with rw_lock:
        for (device_ip_address, device_info_list) in device_dict.items():
            rows_updated = conn.execute('''
                UPDATE devices
                SET metadata_json = json_patch(
                    metadata_json,
                    json_object('mdns_json', json(?))
                )
                WHERE ip_address = ? AND json_extract(metadata_json, '$.mdns_json') IS NULL
            ''', (json.dumps(device_info_list), device_ip_address)).rowcount

            if rows_updated:
                logger.info(f"[mDNS] Discovered device: {device_ip_address}: {json.dumps(device_info_list, indent=2)}")


def get_mdns_device_wrapper(result_queue):

    result = mdns_discovery_helper.get_mdns_devices(
        service_type_discovery_timeout=5,
        device_discovery_timeout=5
    )
    result_queue.put(result)

