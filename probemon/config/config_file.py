import os
import logging
import configparser
from typing import Union

logger = logging.getLogger('config.file')

def get_configfile_params(config_path: str = "") -> Union[dict, dict, dict, list]:
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
    config = configparser.ConfigParser()
    ret_val = config.read([
        config_path if config_path is not None else "",
        os.path.join(basedir, 'config.ini'),
        os.path.join(os.path.expanduser("~"), ".config", "probemon", "config.ini"),
    ])

    app = dict(config.items('APP')) if 'APP' in config else {}
    for key, value in app.items():
        if value and isinstance(value, str) and value.lower() == 'false':
            app[key] = False
        elif value and isinstance(value, str) and value.isnumeric():
            app[key] = int(value)
        elif not value:
            app[key] = None
    mqtt = dict(config.items('MQTT')) if 'MQTT' in config else {}
    for key, value in mqtt.items():
        if value and isinstance(value, str) and value.lower() == 'false':
            mqtt[key] = False
        elif value and isinstance(value, str) and value.isnumeric():
            mqtt[key] = int(value)
        elif not value:
            mqtt[key] = None
    sql = dict(config.items('SQL')) if 'SQL' in config else {}
    for key, value in sql.items():
        if value and isinstance(value, str) and value.lower() == 'false':
            sql[key] = False
        elif value and isinstance(value, str) and value.isnumeric():
            sql[key] = int(value)
        elif not value:
            sql[key] = None

    return app, mqtt, sql, ret_val
