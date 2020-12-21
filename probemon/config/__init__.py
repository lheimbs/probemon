import os
import sys
import logging
import configparser
from urllib.parse import quote_plus

from ..mqtt import Mqtt
from ..sql import Sql

logger = logging.getLogger()

def parse_config(config_path=""):
    basedir = os.path.abspath(os.path.dirname(__file__))
    config = configparser.ConfigParser()
    config.read([
        config_path,
        os.path.join(basedir, 'config.ini'),
        os.path.join(os.environ.get("HOME", ""), "probemon.ini"),
    ])
    mqtt = parse_mqtt(config)
    sql = parse_sql(config)

def parse_mqtt(config: configparser.ConfigParser) -> Mqtt:
    """ Parse the MQTT section in configfile and return the configured Mqtt object """

    def set_auth(mqtt: Mqtt, mqtt_config: configparser.SectionProxy) -> None:
        """ if username and password supplied, set then in the mqtt client """
        if mqtt_config.get("USER", ''):
            mqtt.set_user(mqtt_config.get("USER"), mqtt_config.get("PASSWORD", ''))

    def set_tls(mqtt: Mqtt, mqtt_config: configparser.SectionProxy) -> bool:
        """ if either ca_certs and/or both certfile and keyfile are given,
                test their path's validity and set them in mqtt client

            returns True if tls was set, False if not
        """
        certs = {
            'CA_CERTS': "Certificate Authority certificate files",
            'CERTFILE': "",
            'KEYFILE': "",
        }
        for cert, cert_description in certs.items():
            cert_path = mqtt_config.get(cert, '')
            if not os.path.exists(cert_path):
                logger.error(f"Path '{cert_path}' to the {cert_description} is not a valid path!")
                cert_path = None
            certs[cert] = cert_path

        if any(certs.values()):
            mqtt.set_tls(*certs.values())

    if 'MQTT' in config:
        mqtt_config = config['MQTT']

        if not (mqtt_config.get('HOST', '') and mqtt_config.get('PORT', 0)):
            logger.error(
                "MQTT section in config file used but no HOST is defined.\n" if not mqtt_config.get('HOST', '') else ""
                "MQTT section in config file used but no PORT is defined.\n" if not mqtt_config.get('PORT', 0) else ""
            )
            sys.exit(-1)
        mqtt = Mqtt(enabled=True)
        mqtt.set_server(mqtt_config.get('HOST'), mqtt_config.get('PORT'))
        set_auth(mqtt, mqtt_config)
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

    def get_url(
        dialect: str, username: str, password: str,
        host: str, port: int, database: str,
        driver: str = "", path: str = "",
    ):
        url = dialect
        if driver:
            url += f'+{driver}'
        url += "://"

        if dialect == "sqlite":
            if path:
                url += os.path.normpath(path)
            else:
                logger.debug("Using sqlite database in memory!")
        else:
            url += f"{username}:{quote_plus(password)}"
            url += f"@{host:port}/{database}"
        return url

    if 'SQL' in config:
        sql_config = config['SQL']
        url = get_url(
            dialect=sql_config.get("DIALECT", ''),
            driver=sql_config.get("DIALECT", ''),
            username=sql_config.get("DIALECT", ''),
            password=sql_config.get("DIALECT", ''),
            host=sql_config.get("DIALECT", 0),
            port=sql_config.get("DIALECT", ''),
            sql_config.get("DIALECT", ''),
            sql_config.get("DIALECT", ''),
            sql_config.get("DIALECT", ''),
        )
