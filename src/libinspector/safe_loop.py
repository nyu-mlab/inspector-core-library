"""
A wrapper to repeatedly execute a function in a daemon thread; if the function crashes, automatically restarts the function.

Usage:

def my_func(a, b=1):
    pass

SafeLoopThread(my_func, args=['a'], kwargs={'b': 2}, sleep_time=1)

"""
import threading
import logging
from typing import Callable


logger = logging.getLogger(__name__)


class SafeLoopThread(object):
    """
    Runs a function repeatedly in a daemon thread, automatically restarting it if it crashes.

    This class creates a background thread that continuously executes the given function
    with the provided arguments. If the function raises an exception, the error is logged,
    and the function is restarted after an optional sleep interval.

    Usage:
        def my_func(a, b=1):
            pass
        SafeLoopThread(my_func, args=['a'], kwargs={'b': 2}, sleep_time=1)

    Args:
        func (callable): The function to execute repeatedly.
        args (list, optional): Positional arguments to pass to the function. Defaults to [].
        kwargs (dict, optional): Keyword arguments to pass to the function. Defaults to {}.
        sleep_time (int, optional): Seconds to sleep between function calls. Defaults to 0.

    """

    def __init__(self, func: Callable, name: str = "", args: list = None, kwargs: dict = None, sleep_time: int = 0):
        """
        Initialize the SafeLoopThread and starts the background daemon thread.

        This constructor sets up the function and its arguments to be executed repeatedly
        in a background thread. It does not return any value or produce side effects
        except for starting the daemon thread that manages the repeated execution.

        Args:
            func (callable): The function to execute repeatedly in the thread.
            args (list, optional): Positional arguments to pass to the function. Defaults to [].
            kwargs (dict, optional): Keyword arguments to pass to the function. Defaults to {}.
            sleep_time (int, optional): Seconds to sleep between function calls. Defaults to 0.
        """
        self._func = func
        self._func_args = args or []
        self._func_kwargs = kwargs or {}
        self._sleep_time = sleep_time
        self._stop_event = threading.Event()
        self._run_event = threading.Event()
        self._run_event.set()

        th = threading.Thread(target=self._execute_repeated_func_safe)
        self.name = name if (name and name.strip()) else th.name
        th.name = self.name
        th.daemon = True
        th.start()
        self._thread = th

    def pause(self):
        """Keep the thread alive, but stop executing the function."""
        logger.info(f"[SafeLoopThread] Pausing {self.name}")
        self._run_event.clear()

    def resume(self):
        """Start executing the function again."""
        logger.info(f"[SafeLoopThread] Resuming {self.name}")
        self._run_event.set()

    def stop(self):
        """Kill the thread entirely."""
        self._stop_event.set()
        self._run_event.set()

    def join(self, timeout: int = None):
        self._thread.join(timeout)

    def is_alive(self):
        return self._thread.is_alive()

    def _execute_repeated_func_safe(self):
        """
        Repeatedly executes the target function in a loop, catching and logging any exceptions.

        This method runs in a background daemon thread. It continuously calls the user-provided
        function with the specified arguments. If the function raises an exception, the error
        (including traceback and invocation details) is logged and written to the log file. After each
        execution (successful or not), the method sleeps for the configured interval before
        restarting the function.
        """
        while not self._stop_event.is_set():
            # If _run_event is clear, the thread hangs here using 0% CPU.
            # It only moves forward once resume() is called.
            self._run_event.wait()

            # Double check stop event in case it was stopped while paused
            if self._stop_event.is_set():
                break
            try:
                self._func(*self._func_args, **self._func_kwargs)
            except Exception:
                logger.exception(f"[SafeLoopThread] Crash in {self.name} ({self._func.__name__}) "
                                 f"with args={self._func_args} kwargs={self._func_kwargs}")
                self._stop_event.wait(timeout=1)
            finally:
                if self._sleep_time:
                    self._stop_event.wait(timeout=self._sleep_time)

        logger.info(f"[SafeLoopThread] === {self.name} HAS OFFICIALLY EXITED ===")