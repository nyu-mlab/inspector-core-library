"""
Nmap Scanner Thread.

This module runs nmap against inspected devices on the local network and stores
the results in each device's metadata_json (under the 'nmap_json' key). It is
designed to run as a background SafeLoopThread alongside the mDNS and SSDP/UPnP
scanners in core.py.

Active scanning is opt-in: the scanner does nothing unless the ENABLE_NMAP_SCAN
environment variable is set to a truthy value. It also skips itself gracefully
if the nmap binary is not installed, so it never crashes the core on machines
without nmap.

Functions:
    is_nmap_available(): Return True if the nmap binary is installed.
    get_devices_to_scan(conn, rw_lock, current_ts): Return devices due for a scan.
    start(stop_event, run_event): Thread entry point used by core.py.

Dependencies:
    python-nmap (pip), and the system 'nmap' binary at runtime.

Typical usage:
    Started automatically by libinspector.core.start_threads().
"""

import json
import logging
import os
import shutil
import threading
import time

from . import common
from . import global_state

logger = logging.getLogger(__name__)

# Minimum seconds between scans of the same device, to avoid rescanning too often.
NMAP_SCAN_INTERVAL = 300

# Environment variable that must be truthy for any scanning to happen.
ENABLE_NMAP_SCAN_ENV = "ENABLE_NMAP_SCAN"

# Environment variable to override the nmap arguments; defaults to service/version detection.
NMAP_SCAN_ARGS_ENV = "NMAP_SCAN_ARGS"
DEFAULT_NMAP_ARGS = "-sV"


def is_nmap_available() -> bool:
    """
    Check whether the nmap binary is installed and on the system PATH.

    Returns:
        bool: True if the `nmap` executable can be found, False otherwise.

    This lets the scanner skip itself gracefully on systems (including CI runners)
    where nmap is not installed, rather than raising an error at scan time.
    """
    return shutil.which("nmap") is not None


def get_devices_to_scan(conn, rw_lock, current_ts: int) -> list:
    """
    Return the list of devices that are due for an nmap scan.

    A device is selected when it is being inspected, has a known IP address, is not
    the network gateway, is not this host, and has either never been scanned or was
    last scanned more than NMAP_SCAN_INTERVAL seconds ago.

    Args:
        conn: The SQLite database connection.
        rw_lock: The database read/write lock.
        current_ts (int): The current epoch time, used to apply the scan interval.

    Returns:
        list: A list of sqlite3.Row objects, each with 'mac_address' and 'ip_address'.
    """
    with global_state.global_state_lock:
        host_ip_addr = global_state.host_ip_addr

    oldest_allowed_ts = current_ts - NMAP_SCAN_INTERVAL

    with rw_lock:
        rows = conn.execute(
            """
            SELECT mac_address, ip_address
            FROM devices
            WHERE is_inspected = 1
              AND ip_address != ''
              AND ip_address != ?
              AND is_gateway = 0
              AND (
                    json_extract(metadata_json, '$.nmap_last_scan_ts') IS NULL
                    OR json_extract(metadata_json, '$.nmap_last_scan_ts') < ?
                  )
            """,
            (host_ip_addr, oldest_allowed_ts),
        ).fetchall()

    return rows


def run_nmap_on_device(
    conn, rw_lock, mac_address: str, ip_address: str, arguments: str
) -> bool:
    """
    Run nmap against a single device and store the results in its metadata_json.

    The scan lets nmap discover open ports itself using the given arguments
    (service/version detection by default). Results are written under the
    'nmap_json' key, and the current time is recorded under 'nmap_last_scan_ts'
    so the device is not rescanned until NMAP_SCAN_INTERVAL has elapsed.

    Args:
        conn: The SQLite database connection.
        rw_lock: The database read/write lock.
        mac_address (str): The MAC address of the device (used to update the row).
        ip_address (str): The IP address to scan.
        arguments (str): The nmap command-line arguments to use.

    Returns:
        bool: True if the scan ran and results were stored, False if it failed.
    """
    # Imported lazily so that importing this module does not require python-nmap.
    import nmap

    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=ip_address, arguments=arguments)
    except Exception as e:
        logger.error(f"[Nmap] Scan failed for {ip_address}: {e}")
        return False

    port_results = {}
    if ip_address in scanner.all_hosts():
        host_data = scanner[ip_address]
        for port in host_data.get("tcp", {}):
            port_info = host_data["tcp"][port]
            port_results[str(port)] = {
                "state": port_info.get("state", ""),
                "name": port_info.get("name", ""),
                "product": port_info.get("product", ""),
                "version": port_info.get("version", ""),
            }

    current_ts = int(time.time())
    with rw_lock:
        conn.execute(
            """
            UPDATE devices
            SET metadata_json = json_patch(
                metadata_json,
                json_object('nmap_json', json(?), 'nmap_last_scan_ts', ?)
            )
            WHERE mac_address = ?
            """,
            (json.dumps(port_results), current_ts, mac_address),
        )

    logger.info(
        f"[Nmap] Stored results for {ip_address} ({mac_address}): {len(port_results)} port(s)"
    )
    return True


def start(stop_event: threading.Event = None, run_event: threading.Event = None):
    """
    Thread entry point: scan due devices with nmap and store the results.

    Used by IoT Inspector within a SafeLoopThread. Does nothing unless the
    ENABLE_NMAP_SCAN environment variable is truthy and the nmap binary is
    installed. Scans each due device in turn, honoring an early stop request.

    Args:
        stop_event (threading.Event, optional): Signals early termination.
        run_event (threading.Event, optional): Signals to pause this thread.
    """
    if run_event:
        run_event.wait()

    if not common.inspector_is_running():
        return

    if not common.get_env_bool(ENABLE_NMAP_SCAN_ENV, False):
        return

    if not is_nmap_available():
        logger.warning(
            "[Nmap] nmap binary not found; skipping scan. Install nmap to enable this feature."
        )
        return

    arguments = os.environ.get(NMAP_SCAN_ARGS_ENV, DEFAULT_NMAP_ARGS)

    conn, rw_lock = global_state.db_conn_and_lock
    current_ts = int(time.time())
    devices = get_devices_to_scan(conn, rw_lock, current_ts)

    if not devices:
        logger.info("[Nmap] No devices due for scanning.")
        return

    logger.info(f"[Nmap] Scanning {len(devices)} device(s) with arguments: {arguments}")

    for device in devices:
        if stop_event and stop_event.is_set():
            break
        run_nmap_on_device(
            conn, rw_lock, device["mac_address"], device["ip_address"], arguments
        )
