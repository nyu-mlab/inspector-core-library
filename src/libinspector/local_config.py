"""
Local Configuration File Parser (Read-Only).

This module provides utility functions to read configuration values from a local JSON file,
intended for use as a read-only configuration source for the Inspector application.

The configuration file should be named `libinspector_config.json` and located in the same
directory from which the script is run. The module is resilient to missing files, missing
keys, and malformed JSON: in all such cases, a user-supplied default value is returned.

Features:
- Reads configuration from a JSON file with caching for efficiency.
- Returns default values if the file or key is missing, or if the file is not valid JSON.
- Logs informative messages for file loading, missing files, and errors.

Typical usage:
    value = get('some_config_key', default=42)

Functions:
    get(config_key, default=None): Retrieve a configuration value by key.
    _load_config_file(): Load and cache the configuration file as a dictionary.
"""
import json
import functools
import logging


logger = logging.getLogger(__name__)


CONFIG_FILE_PATH = 'libinspector_config.json'


def get(config_key: str, default=None):
    """
    Retrieve the value for a given configuration key from the local config file.

    Args:
        config_key (str): The key to look up in the configuration file.
        default (Any, optional): The value to return if the key is not found or if
            the config file is missing or invalid. Defaults to None.

    Returns:
        Any: The value associated with `config_key` if present, otherwise `default`.

    Example:
        get('use_in_memory_db', default=True)
        True
    """
    config_dict = _load_config_file()
    try:
        return config_dict[config_key]
    except KeyError:
        return default


@functools.lru_cache(maxsize=1)
def _load_config_file():
    """
    Load the configuration file and return its contents as a dictionary.

    This function is cached to avoid repeated file reads. If the file is not found,
    is not valid JSON, or any other error occurs, an empty dictionary is returned.

    Returns:
        dict: The parsed configuration dictionary, or an empty dict on error.

    Logging:
        - Logs info when the config file is loaded or not found.
        - Logs errors for malformed JSON or unexpected exceptions.
    """
    try:
        with open(CONFIG_FILE_PATH, 'r') as fp:
            o = json.load(fp)
            logger.info(f'[local_config] Loaded config file {CONFIG_FILE_PATH}')
            return o
    except FileNotFoundError:
        logger.info(f'[local_config] Config file {CONFIG_FILE_PATH} not found.')
        return {}
    except json.JSONDecodeError:
        logger.error(f'[local_config] Config file {CONFIG_FILE_PATH} is not in proper JSON format.')
        return {}
    except Exception:
        logger.exception(f'[local_config] Error reading config file {CONFIG_FILE_PATH}.')
        return {}
