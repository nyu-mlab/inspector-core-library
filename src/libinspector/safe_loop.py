"""
A wrapper to repeatedly execute a function in a daemon thread; if the
function crashes, automatically restarts the function.

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

    def __init__(self, func, args=[], kwargs={}, sleep_time=1) -> None:

        self._func = func
        self._func_args = args
        self._func_kwargs = kwargs
        self._sleep_time = sleep_time

        th = threading.Thread(target=self._execute_repeated_func_safe)
        th.daemon = True
        th.start()

    def _execute_repeated_func_safe(self):
        """Safely executes the repeated function calls."""

        while True:

            logger.info('[SafeLoopThread] Starting %s %s %s' % (self._func, self._func_args, self._func_kwargs))

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

                time.sleep(self._sleep_time)
