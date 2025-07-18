import unittest
import os
import sys


def main():
    # Make sure we're running as root
    if os.geteuid() != 0:
        print('All tests must be run as root. Exiting.')
        sys.exit(1)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir='tests')

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)


if __name__ == '__main__':
    main()