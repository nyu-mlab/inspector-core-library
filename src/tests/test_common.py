"""
Tests for libinspector.common.

Covers get_env_bool truthy/falsy parsing, get_os platform detection,
inspector_is_running state reads, and is_admin OS branches. All OS-specific
behavior is mocked so the tests run identically on macOS, Linux, and Windows.
"""

import os
import sys
import unittest
from unittest import mock

import libinspector.common as common
import libinspector.global_state as global_state


class TestGetEnvBool(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("TEST_BOOL_VAR", None)

    def test_unset_returns_default(self):
        self.assertTrue(common.get_env_bool("TEST_BOOL_VAR", True))
        self.assertFalse(common.get_env_bool("TEST_BOOL_VAR", False))

    def test_truthy_values(self):
        for value in ["true", "True", "1", "t", "T", "y", "YES"]:
            os.environ["TEST_BOOL_VAR"] = value
            self.assertTrue(common.get_env_bool("TEST_BOOL_VAR", False), value)

    def test_falsy_values(self):
        for value in ["false", "0", "no", "n", "garbage", ""]:
            os.environ["TEST_BOOL_VAR"] = value
            self.assertFalse(common.get_env_bool("TEST_BOOL_VAR", True), value)


class TestGetOs(unittest.TestCase):
    def test_mac(self):
        with mock.patch.object(sys, "platform", "darwin"):
            self.assertEqual(common.get_os(), "mac")

    def test_linux(self):
        with mock.patch.object(sys, "platform", "linux"):
            self.assertEqual(common.get_os(), "linux")

    def test_windows(self):
        with mock.patch.object(sys, "platform", "win32"):
            self.assertEqual(common.get_os(), "windows")

    def test_unsupported_platform_raises(self):
        with mock.patch.object(sys, "platform", "solaris"):
            with self.assertRaises(RuntimeError):
                common.get_os()


class TestInspectorIsRunning(unittest.TestCase):
    def setUp(self):
        with global_state.global_state_lock:
            self._original_is_running = global_state.is_running
        self.addCleanup(self._restore_is_running)

    def _restore_is_running(self):
        with global_state.global_state_lock:
            global_state.is_running = self._original_is_running

    def test_reflects_global_state(self):
        with global_state.global_state_lock:
            global_state.is_running = True
        self.assertTrue(common.inspector_is_running())

        with global_state.global_state_lock:
            global_state.is_running = False
        self.assertFalse(common.inspector_is_running())


class TestIsAdmin(unittest.TestCase):
    def test_posix_root(self):
        for os_name in ["mac", "linux"]:
            with mock.patch.object(common, "get_os", return_value=os_name):
                with mock.patch.object(os, "geteuid", return_value=0, create=True):
                    self.assertTrue(common.is_admin())

    def test_posix_non_root(self):
        for os_name in ["mac", "linux"]:
            with mock.patch.object(common, "get_os", return_value=os_name):
                with mock.patch.object(os, "geteuid", return_value=1000, create=True):
                    self.assertFalse(common.is_admin())

    def test_windows_admin(self):
        fake_windll = mock.MagicMock()
        fake_windll.shell32.IsUserAnAdmin.return_value = 1
        with mock.patch.object(common, "get_os", return_value="windows"):
            with mock.patch("ctypes.windll", fake_windll, create=True):
                self.assertTrue(common.is_admin())

    def test_unsupported_os_raises(self):
        with mock.patch.object(common, "get_os", return_value="solaris"):
            with self.assertRaises(RuntimeError):
                common.is_admin()


if __name__ == "__main__":
    unittest.main()
