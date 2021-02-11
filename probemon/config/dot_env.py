import os
from typing import Union
from dotenv import load_dotenv

def get_dotenv_params() -> Union[dict, dict, dict]:
    load_dotenv(verbose=True)

    app = {}
    mqtt = {}
    sql = {}
    for key, value in os.environ.items():
        if value and isinstance(value, str) and value.lower() == 'false':
            value = False
        elif value and isinstance(value, str) and value.isnumeric():
            value = int(value)
        elif not value:
            value = None

        if key.lower().startswith("probemon_"):
            key = key.lower().replace("probemon_", '')
            if key.startswith('sql_'):
                sql[key.replace('sql_', '')] = value
            elif key.startswith('mqtt_'):
                mqtt[key.replace('mqtt_', '')] = value
            else:
                app[key] = value
    return app, mqtt, sql
