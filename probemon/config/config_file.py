import os
# import sys
import logging
import configparser

from .misc import get_url
from ..mqtt import Mqtt
from ..sql import Sql

logger = logging.getLogger('config.file')

def parse_config_file(config_path: str = "") -> (dict, dict):
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
    config = configparser.ConfigParser()
    ret_val = config.read([
        config_path if config_path is not None else "",
        os.path.join(basedir, 'config.ini'),
        os.path.join(os.path.expanduser("~"), ".config", "probemon", "config.ini"),
    ])
    if not ret_val:
        logger.debug("No config file found.")
    else:
        logger.debug(f"Using data from config files {', '.join(ret_val)}")
    mqtt = get_mqtt_params(config)
    sql = get_sql_params(config)
    return mqtt, sql


def get_mqtt_params(config: configparser.ConfigParser) -> dict:
    """ translate cli parameters into unified parameter dict """
    parsed_params = {}
    parsed_params['host'] = config.get('MQTT', 'HOST', fallback='')
    parsed_params['port'] = config.getint('MQTT', 'PORT', fallback=0)
    parsed_params['user'] = config.get('MQTT', 'DIALECT', fallback='')
    parsed_params['password'] = config.get('MQTT', 'DIALECT', fallback='')
    parsed_params['ca_certs'] = config.get('MQTT', 'CA_CERTS', fallback=None)
    parsed_params['certfile'] = config.get('MQTT', 'CERTFILE', fallback=None)
    parsed_params['keyfile'] = config.get('MQTT', 'KEYFILE', fallback=None)
    return parsed_params


def get_sql_params(config: configparser.ConfigParser) -> dict:
    """ translate cli parameters into unified parameter dict """
    parsed_params = {}
    parsed_params['dialect'] = config.get('SQL', 'DIALECT', fallback='')
    parsed_params['driver'] = config.get('SQL', 'DRIVER', fallback='')
    parsed_params['host'] = config.get('SQL', 'HOST', fallback='')
    parsed_params['port'] = config.getint('SQL', 'PORT', fallback=0)
    parsed_params['user'] = config.get('SQL', 'USERNAME', fallback='')
    parsed_params['password'] = config.get('SQL', 'PASSWORD', fallback='')
    parsed_params['path'] = config.get('SQL', 'PATH', fallback='')
    parsed_params['database'] = config.get('SQL', 'DATABASE', fallback='')
    return parsed_params


def parse_mqtt(config: configparser.ConfigParser) -> Mqtt:
    """ Parse the MQTT section in configfile and return the configured Mqtt object """

    def set_tls(mqtt: Mqtt, mqtt_config: configparser.SectionProxy) -> None:
        """ if either ca_certs and/or both certfile and keyfile are given,
                test their path's validity and set them in mqtt client
        """
        certs = {
            'ca_certs': "Certificate Authority certificate files",
            'certfile': "PEM encoded client certificate used for authentification.",
            'keyfile': "PEM encoded private keys used for authentification.",
        }
        for cert, cert_description in certs.items():
            cert_path = mqtt_config.get(cert, '')
            if not os.path.exists(cert_path):
                logger.error(f"Path '{cert_path}' to the {cert_description} is not a valid path!")
                cert_path = None
            certs[cert] = cert_path

        mqtt.set_tls(**certs)

    if 'MQTT' in config:
        mqtt_config = config['MQTT']
        mqtt = Mqtt(enabled=True)
        mqtt.set_server(mqtt_config.get('HOST', ''), mqtt_config.get('PORT'))

        if mqtt_config.get("USER", ''):
            mqtt.set_user(mqtt_config.get("USER"), mqtt_config.get("PASSWORD", ''))

        set_tls(mqtt, mqtt_config)

        if mqtt_config.get('LOGLEVEL', ''):
            try:
                log_level = getattr(logging, mqtt_config.get('LOGLEVEL'))
                mqtt.enable_logger(log_level)
            except AttributeError:
                pass

        return mqtt
    return Mqtt(enabled=False)

def parse_sql(config: configparser.ConfigParser) -> Sql:
    """ Parse the SQL section in configfile and return the configured Sql object """
    if 'SQL' in config:
        sql_config = config['SQL']
        url = get_url(
            dialect=sql_config.get("DIALECT", ''),
            driver=sql_config.get("DRIVER", ''),
            username=sql_config.get("USERNAME", ''),
            password=sql_config.get("PASSWORD", ''),
            host=sql_config.get("HOST", ''),
            port=sql_config.get("PORT", 0),
            database=sql_config.get("DATABASE", ''),
            path=sql_config.get("PATH", ''),
        )
        sql = Sql(enabled=True)
        sql.set_url(url)
    else:
        sql = Sql(enabled=False)
    return sql
