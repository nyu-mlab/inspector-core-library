"""
Tests for libinspector.safe_loop.
"""

import threading
import unittest

from libinspector.safe_loop import SafeLoopThread


TIMEOUT = 5


class TestSafeLoopThread(unittest.TestCase):
    def _start(self, func, **kwargs):
        loop_thread = SafeLoopThread(func, **kwargs)
        self.addCleanup(loop_thread.join, TIMEOUT)
        self.addCleanup(loop_thread.stop)
        return loop_thread

    def test_runs_function_repeatedly(self):
        # The function keeps getting called over and over.
        counter = {"n": 0}
        called_enough = threading.Event()

        def func():
            counter["n"] += 1
            if counter["n"] >= 3:
                called_enough.set()

        self._start(func)
        self.assertTrue(called_enough.wait(TIMEOUT))
        self.assertGreaterEqual(counter["n"], 3)

    def test_injects_stop_and_run_events(self):
        # The loop hands the function its stop and pause switches.
        received = []
        got_events = threading.Event()

        def func(stop_event=None, run_event=None):
            received.append((stop_event, run_event))
            if stop_event is not None and run_event is not None:
                got_events.set()

        self._start(func)
        self.assertTrue(got_events.wait(TIMEOUT))
        stop_event, run_event = received[-1]
        self.assertIsInstance(stop_event, threading.Event)
        self.assertIsInstance(run_event, threading.Event)

    def test_pause_stops_execution_and_resume_restarts(self):
        # Pausing freezes the function; resuming wakes it up.
        called = threading.Event()

        def func():
            called.set()

        loop_thread = self._start(func)
        self.assertTrue(called.wait(TIMEOUT))

        loop_thread.pause()
        # Let any in-flight iteration finish, then verify no new calls happen.
        loop_thread._run_event.wait(0.2)
        threading.Event().wait(0.2)
        called.clear()
        self.assertFalse(called.wait(0.5))

        loop_thread.resume()
        self.assertTrue(called.wait(TIMEOUT))

    def test_stop_kills_thread(self):
        # Stopping shuts the background worker down completely.
        loop_thread = self._start(lambda: None)
        self.assertTrue(loop_thread.is_alive())

        loop_thread.stop()
        loop_thread.join(TIMEOUT)
        self.assertFalse(loop_thread.is_alive())

    def test_stop_while_paused_exits_thread(self):
        # A paused worker can still be shut down.
        loop_thread = self._start(lambda: None)
        loop_thread.pause()
        loop_thread.stop()
        loop_thread.join(TIMEOUT)
        self.assertFalse(loop_thread.is_alive())

    def test_crashing_function_is_restarted(self):
        # If the function crashes, it gets restarted instead of dying.
        state = {"calls": 0}
        recovered = threading.Event()

        def func():
            state["calls"] += 1
            if state["calls"] == 1:
                raise ValueError("boom")
            recovered.set()

        loop_thread = self._start(func)
        self.assertTrue(recovered.wait(TIMEOUT))
        self.assertTrue(loop_thread.is_alive())

    def test_thread_naming(self):
        # Workers can be given a name, or get one automatically.
        named = self._start(lambda: None, name="my-worker")
        self.assertEqual(named.name, "my-worker")
        self.assertEqual(named._thread.name, "my-worker")

        unnamed = self._start(lambda: None, name="  ")
        self.assertTrue(unnamed.name)


if __name__ == "__main__":
    unittest.main()
