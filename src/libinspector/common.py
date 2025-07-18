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



