import os
import logging
import configparser
from typing import Union

logger = logging.getLogger(__name__)

def get_configfile_params(
    config_path: str = ""
) -> Union[dict, dict, dict, list]:
    basedir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
    )
    config = configparser.ConfigParser()
    ret_val = config.read([
        config_path if config_path is not None else "",
        os.path.join(basedir, 'config.ini'),
        os.path.join(
            os.path.expanduser("~"), ".config", "probemon", "config.ini",
        ),
    ])

    app = dict(config.items('APP')) if 'APP' in config else {}
    mqtt = dict(config.items('MQTT')) if 'MQTT' in config else {}
    sql = dict(config.items('SQL')) if 'SQL' in config else {}

    for key, value in app.items():
        app[key] = convert_option_type(value)
    for key, value in mqtt.items():
        mqtt[key] = convert_option_type(value)
    for key, value in sql.items():
        sql[key] = convert_option_type(value)

    return app, mqtt, sql, ret_val


def convert_option_type(value):
    if value and isinstance(value, str) and value.lower() == 'false':
        new_value = False
    elif value and isinstance(value, str) and value.isnumeric():
        new_value = int(value)
    elif not value:
        new_value = None
    else:
        new_value = value
    return new_value
