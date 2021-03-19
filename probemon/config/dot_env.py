import os
from typing import Tuple
from dotenv import load_dotenv

from .misc import convert_option_type

def get_dotenv_params() -> Tuple[dict, dict, dict]:
    load_dotenv(verbose=True)

    app = {}
    mqtt = {}
    sql = {}
    for key, value in os.environ.items():
        value = convert_option_type(value)

        if key.lower().startswith("probemon_"):
            key = key.lower().replace("probemon_", '')
            if key.startswith('sql_'):
                sql[key.replace('sql_', '')] = value
            elif key.startswith('mqtt_'):
                mqtt[key.replace('mqtt_', '')] = value
            else:
                app[key] = value
    return app, mqtt, sql
