import os
from typing import Tuple
from dotenv import load_dotenv

from .misc import convert_option_type

def get_dotenv_params() -> dict:
    load_dotenv(verbose=True)

    cfg = {}
    for key, value in os.environ.items():
        value = convert_option_type(value)
        if key.lower().startswith('probemon_'):
            key = key.lower().replace('probemon_', '')
            cfg[key] = value
    return cfg
