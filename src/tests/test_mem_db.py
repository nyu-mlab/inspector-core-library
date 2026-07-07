"""
Tests for libinspector.mem_db.

Verifies the schema, environment-variable toggles, and UDF registration of
initialize_db(). Uses only in-memory (or temp-dir) SQLite; no network access.
"""

import os
import sqlite3
import tempfile
import unittest
from unittest import mock

import libinspector.mem_db as mem_db


class TestInitializeDb(unittest.TestCase):
    def setUp(self):
        # Ensure ambient shell env vars cannot leak into any test.
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("USE_IN_MEMORY_DB", None)
        os.environ.pop("SCAN_ALL_DEVICES", None)

    def test_creates_tables_and_indexes(self):
        conn, rw_lock = mem_db.initialize_db()
        self.addCleanup(conn.close)

        with rw_lock:
            tables = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            indexes = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
                )
            }

        self.assertEqual(conn.row_factory, sqlite3.Row)
        self.assertTrue({"devices", "hostnames", "network_flows"} <= tables)
        self.assertEqual(
            indexes,
            {
                "idx_devices_ip_address",
                "idx_devices_is_inspected",
                "idx_network_flows_src_ip_address",
                "idx_network_flows_dest_ip_address",
                "idx_network_flows_src_hostname",
                "idx_network_flows_dest_hostname",
                "idx_network_flows_timestamp",
            },
        )
        self.assertTrue(hasattr(rw_lock, "acquire") and hasattr(rw_lock, "release"))

    def test_is_inspected_default_zero(self):
        conn, rw_lock = mem_db.initialize_db()
        self.addCleanup(conn.close)

        with rw_lock:
            conn.execute(
                "INSERT INTO devices (mac_address, ip_address) VALUES (?, ?)",
                ("aa:bb:cc:dd:ee:ff", "10.0.0.2"),
            )
            row = conn.execute(
                "SELECT is_inspected FROM devices WHERE mac_address = ?",
                ("aa:bb:cc:dd:ee:ff",),
            ).fetchone()

        self.assertEqual(row["is_inspected"], 0)

    def test_scan_all_devices_sets_is_inspected_default_one(self):
        os.environ["SCAN_ALL_DEVICES"] = "true"
        conn, rw_lock = mem_db.initialize_db()
        self.addCleanup(conn.close)

        with rw_lock:
            conn.execute(
                "INSERT INTO devices (mac_address, ip_address) VALUES (?, ?)",
                ("aa:bb:cc:dd:ee:ff", "10.0.0.2"),
            )
            row = conn.execute(
                "SELECT is_inspected FROM devices WHERE mac_address = ?",
                ("aa:bb:cc:dd:ee:ff",),
            ).fetchone()

        self.assertEqual(row["is_inspected"], 1)

    def test_oui_vendor_udf_registered(self):
        conn, rw_lock = mem_db.initialize_db()
        self.addCleanup(conn.close)

        with rw_lock:
            row = conn.execute(
                "SELECT get_oui_vendor('aa:bb:cc:dd:ee:ff') AS vendor"
            ).fetchone()

        self.assertIsInstance(row["vendor"], str)

    def test_on_disk_db_when_env_false(self):
        os.environ["USE_IN_MEMORY_DB"] = "false"
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_db_path = os.path.join(tmp_dir, "debug_mem_db.db")
            with mock.patch.object(mem_db, "debug_db_path", tmp_db_path):
                conn, _ = mem_db.initialize_db()
                conn.close()
            self.assertTrue(os.path.exists(tmp_db_path))


if __name__ == "__main__":
    unittest.main()
