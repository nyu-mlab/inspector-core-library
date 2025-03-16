"""
Parsing a local configuration file (read-only).

The config file should be saved in JSON format as as a file named `inspector_config.json` in the same directory the script is run from.

If the config file is not found, or if the key is not found, or if the file is not in JSON format, or if there is any other error, the default value is returned.

"""
import json
import functools
import logging


logger = logging.getLogger(__name__)


CONFIG_FILE_PATH = 'inspector_config.json'


def get(config_key: str, default=None):
    """
    Returns the value of the given configuration key.
    If the key is not found, the default value is returned.

    """
    config_dict = _load_config_file()
    try:
        return config_dict[config_key]
    except KeyError:
        return default



@functools.lru_cache(maxsize=1)
def _load_config_file():
    """
    Returns the contents of the config file as a dictionary.
    If the file is not found, an empty dictionary is returned.

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
