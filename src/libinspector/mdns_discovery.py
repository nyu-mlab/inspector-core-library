"""
mDNS Device Discovery Integration.

This module provides functionality to discover devices on the local network using mDNS (Multicast DNS).
It launches the mDNS discovery helper as a separate subprocess to avoid socket exhaustion issues
and parses the discovered device information, saving it to the database. This approach ensures
proper resource cleanup and compatibility with environments such as Streamlit.

Functions:
    start(): Runs mDNS discovery in a subprocess and updates the devices table with discovered metadata.

Dependencies:
    logging, json, subprocess, sys, global_state

Typical usage example:
    import libinspector.mdns_discovery
    libinspector.mdns_discovery.start()
"""
import logging
import json
import subprocess
import sys
from . import global_state


logger = logging.getLogger(__name__)


def start():
    """
    Discovers devices via mDNS. Saves the discovered devices to the `devices` table (under the `metadata_json` column) in the database.

    Notes from Danny: I have to start the mdns_discovery_helper in a separate process.
    I believe there is a bug in its original implementation that
    doesn't properly close the socket. As a result, a few minutes of continuous
    discovery will cause the OS to run out of sockets, even though I make sure
    that the zeroconf object is closed after the discovery is done. Below is a
    workaround to run the discovery in a separate process and then join it back
    to the main process. Running it in a separate process allows the socket to
    be properly closed when the process exits. Also note that I cannot use
    multiprocessing as it does not play well with `streamlit`. The only way that
    works is `subprocess`.

    Args:
        None

    Returns:
        None
    """
    logger.info("[mDNS] Discovering devices...")

    # Run the mdns_discovery_helper in a separate subprocess
    proc = subprocess.Popen(
        [sys.executable, '-m', 'libinspector.mdns_discovery_helper'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate()

    # Check the return code of the subprocess
    return_code = proc.returncode
    if return_code != 0:
        logger.error(f"[mDNS] Error discovering devices: {stderr.decode()}")
        return

    # Parse the output of the subprocess
    try:
        device_dict = json.loads(stdout.decode().strip())
    except json.JSONDecodeError as e:
        logger.error(f"[mDNS] Error decoding JSON output: {e}")
        return

    # Add the discovered devices to the database
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
