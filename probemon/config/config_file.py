import os
import configparser
from typing import Tuple

from .misc import convert_option_type

def get_configfile_params(
    config_path: str = ""
) -> Tuple[dict, dict, dict, list]:
    basedir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
    )
    config = configparser.ConfigParser()
    parsed_files = config.read([
        config_path if config_path is not None else "",
        os.path.join(basedir, 'config.ini'),
        os.path.join(
            os.path.expanduser("~"), ".config", "probemon", "config.ini",
        ),
    ])

    app = dict(config.items('APP')) if 'APP' in config else {}
    if parsed_files:
        app.update({'parsed_files': parsed_files})
    mqtt = dict(config.items('MQTT')) if 'MQTT' in config else {}
    sql = dict(config.items('SQL')) if 'SQL' in config else {}

    for key, value in app.items():
        app[key] = convert_option_type(value)
    for key, value in mqtt.items():
        mqtt[key] = convert_option_type(value)
    for key, value in sql.items():
        sql[key] = convert_option_type(value)

    return app, mqtt, sql
