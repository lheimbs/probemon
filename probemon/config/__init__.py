import os
import logging

from .misc import get_url
from .cli import cli
from .config_file import parse_config_file
from ..sql import Sql
from ..mqtt import Mqtt
# from ..probes import Session

logger = logging.getLogger('config')


def validate_mqtt_config(cli: dict, conf: dict) -> Mqtt:
    for param in cli.keys():
        if cli[param] and conf[param] and cli[param] != conf[param]:
            logger.info(
                f"MQTT config: CLI option '{param}': {cli[param]} takes precedence over config option {conf[param]}!"
            )
            conf[param] = cli[param]
    params = conf

    mqtt = Mqtt()
    mqtt.set_server(params['host'], params['password'])
    mqtt.set_user(params['user'], params['password'])
    for file in ['ca_certs', 'certfile', 'keyfile']:
        if not os.path.exists(file):
            logger.error(f"{file} '{params[file]}' does not exist!")
            params[file] = None
    mqtt.set_tls(params['ca_certs'], params['certfile'], params['keyfile'])
    return mqtt


def validate_sql_config(cli: dict, conf: dict) -> Sql:
    for param in cli.keys():
        if cli[param] and conf[param] and cli[param] != conf[param]:
            logger.info(
                f"SQL config: CLI option '{param}': {cli[param]} takes precedence over config option {conf[param]}!"
            )
            conf[param] = cli[param]
    params = conf

    sql = Sql()
    if not params['dialect']:
        logger.debug("No sql dialect supplied.")
        if any([params['host'], params['path'], params['user'], params['password']]):
            logger.warning("Warning: with sql dialect unset, all other sql options will be ignored!")
        return sql

    if params['dialect'].lower() != 'sqlite' and not params['host']:
        logger.debug("No sql host with dialect other than sqlite supplied. Disabling sql.")
        if any([params['user'], params['password']]):
            logger.warning(
                "Warning: with sql dialect not sqlite and sql host unset, "
                "all sql options will be ignored and no data will get published to a sql database."
            )
        return sql

    url = get_url(**params)
    sql.set_url(url)
    return sql


def get_config(interface: str, config: str, debug: bool, **params: dict) -> (Mqtt, Sql):
    logger.info(f"Using interface {interface}")
    if debug:
        logger.setLevel(logging.DEBUG)
        logging.basicConfig(level=logging.DEBUG)
        for handler in logger.handlers:
            if isinstance(handler, type(logging.StreamHandler())):
                handler.setLevel(logging.DEBUG)
                logger.debug('Debug logging enabled')
        # logging.basicConfig(level=logging.DEBUG)
        logger.debug("Debugging enabled.")
    else:
        logging.basicConfig(level=logging.INFO)

    mqtt_cli, sql_cli = cli(params)
    # print(logger.handlers)

    mqtt_file, sql_file = parse_config_file(config)
    mqtt = validate_mqtt_config(mqtt_cli, mqtt_file)
    sql = validate_sql_config(sql_cli, sql_file)
    return mqtt, sql
