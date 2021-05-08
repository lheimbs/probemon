import os
import configparser

from .misc import convert_option_type

def get_configfile_params(config_path: str = "") -> dict:
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
    url = dict(config.items('URLPUBLISH')) if 'URLPUBLISH' in config else {}

    cfg = {}
    for key, value in app.items():
        cfg[key.lower()] = convert_option_type(value)
    for key, value in mqtt.items():
        cfg['mqtt_' + key.lower()] = convert_option_type(value)
    for key, value in sql.items():
        cfg['sql_' + key.lower()] = convert_option_type(value)
    for key, value in url.items():
        cfg['url_publish_' + key.lower()] = convert_option_type(value)

    return cfg
