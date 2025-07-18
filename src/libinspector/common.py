"""
Common Helper Functions.

This module provides utility functions that are used throughout the Inspector project.
Currently, it includes helpers for determining the operating system platform in a
standardized way.

Functions:
    get_os(): Detects the current operating system and returns a normalized string.

Typical usage:
    from libinspector.common import get_os
    os_name = get_os()
"""
import sys
import os


def get_os() -> str:
    """
    Detect the current operating system and return a normalized string identifier.

    Returns:
        str: One of 'mac', 'linux', or 'windows' depending on the detected platform.

    Raises:
        RuntimeError: If the operating system is not recognized as macOS, Linux, or Windows.

    Example:
        get_os()
        'linux'

    This function inspects `sys.platform` and maps it to a simplified OS name.
    It is useful for writing cross-platform code that needs to branch on OS type.
    """
    os_platform = sys.platform

    if os_platform.startswith('darwin'):
        return 'mac'

    if os_platform.startswith('linux'):
        return 'linux'

    if os_platform.startswith('win'):
        return 'windows'

    raise RuntimeError('Unsupported operating system.')


def is_admin() -> bool:
    """
    Check if the current user has administrative privileges.

    Returns:
        bool: True if the user is an administrator, False otherwise.

    This function is a placeholder and should be implemented based on the specific
    requirements of the operating system.
    """
    if get_os() == 'mac':
        return os.geteuid() == 0
    elif get_os() == 'linux':
        return os.geteuid() == 0
    elif get_os() == 'windows':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    else:
        raise RuntimeError('Unsupported operating system for admin check.')