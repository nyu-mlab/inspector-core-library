"""
A wrapper to repeatedly execute a function in a daemon thread; if the function crashes, automatically restarts the function.

Usage:

def my_func(a, b=1):
    pass

SafeLoopThread(my_func, args=['a'], kwargs={'b': 2}, sleep_time=1)

"""
import threading
import time
import logging
import datetime
import traceback
import sys


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
        sleep_time (int or float, optional): Seconds to sleep between function calls. Defaults to 0.

    """

    def __init__(self, func, args=[], kwargs={}, sleep_time=0) -> None:
        """
        Initialize the SafeLoopThread and starts the background daemon thread.

        This constructor sets up the function and its arguments to be executed repeatedly
        in a background thread. It does not return any value or produce side effects
        except for starting the daemon thread that manages the repeated execution.

        Args:
            func (callable): The function to execute repeatedly in the thread.
            args (list, optional): Positional arguments to pass to the function. Defaults to [].
            kwargs (dict, optional): Keyword arguments to pass to the function. Defaults to {}.
            sleep_time (int or float, optional): Seconds to sleep between function calls. Defaults to 0.
        """
        self._func = func
        self._func_args = args
        self._func_kwargs = kwargs
        self._sleep_time = sleep_time

        th = threading.Thread(target=self._execute_repeated_func_safe)
        th.daemon = True
        th.start()

    def _execute_repeated_func_safe(self):
        """
        Repeatedly executes the target function in a loop, catching and logging any exceptions.

        This method runs in a background daemon thread. It continuously calls the user-provided
        function with the specified arguments. If the function raises an exception, the error
        (including traceback and invocation details) is logged and written to stderr. After each
        execution (successful or not), the method sleeps for the configured interval before
        restarting the function.

        Args:
            None

        Returns:
            None
        """
        while True:
            try:
                self._func(*self._func_args, **self._func_kwargs)
            except Exception as e:
                err_msg = '=' * 80 + '\n'
                err_msg += 'Time: %s\n' % datetime.datetime.today()
                err_msg += 'Function: %s %s %s\n' % (self._func, self._func_args, self._func_kwargs)
                err_msg += 'Exception: %s\n' % e
                err_msg += str(traceback.format_exc()) + '\n\n\n'

                sys.stderr.write(err_msg + '\n')
                logger.error(err_msg)

            finally:
                if self._sleep_time:
                    time.sleep(self._sleep_time)
