import os
import logging
from collections import ChainMap
from typing import Union

from .misc import get_url
from .cli import get_cli_params
from .dot_env import get_dotenv_params
from .config_file import get_configfile_params
from ..sql import Sql
from ..mqtt import Mqtt
from ..ProbeRequest import ProbeRequest
# from ..probes import Session

logger = logging.getLogger('config')


class IgnoreNoneChainMap(ChainMap):
    """ careful: does not work with defaultdict because of 'key in mapping'! """
    def __missing__(self, key):
        return None

    def __getitem__(self, key):
        for mapping in self.maps:
            if key in mapping.keys() and mapping[key] is not None:
                return mapping[key]
        return self.__missing__(key)


def set_mqtt_from_params(mqtt_config: ChainMap) -> None:
    # mqtt = Mqtt()
    Mqtt.set_server(mqtt_config['host'], mqtt_config['port'])
    Mqtt.set_topic(mqtt_config['topic'])
    Mqtt.set_user(mqtt_config['user'], mqtt_config['password'])
    for file in ['ca_certs', 'certfile', 'keyfile']:
        if mqtt_config[file] and not os.path.exists(mqtt_config[file]):
            logger.error(f"{file} '{mqtt_config[file]}' does not exist!")
            mqtt_config[file] = None
    Mqtt.set_tls(mqtt_config['ca_certs'], mqtt_config['certfile'], mqtt_config['keyfile'])
    if mqtt_config['debug']:
        Mqtt.enable_debugging()
    # return mqtt


def set_sql_from_params(sql_config: ChainMap) -> Sql:
    sql = Sql()
    if not sql_config['dialect']:
        logger.debug("No sql dialect supplied.")
        if any([sql_config['host'], sql_config['sqlite_path'], sql_config['user'], sql_config['password']]):
            logger.warning("Warning: with sql dialect unset, all other sql options will be ignored!")
        return sql

    if str(sql_config['dialect']).lower() != 'sqlite' and not sql_config['host']:
        logger.debug("No sql host with dialect other than sqlite supplied. Disabling sql.")
        if any([sql_config['user'], sql_config['password']]):
            logger.warning(
                "Warning: with sql dialect not sqlite and sql host unset, "
                "all sql options will be ignored and no data will get published to a sql database."
            )
        return sql

    url = get_url(**sql_config)
    sql.set_url(url)
    return sql


def get_config_options(config: str, **params: dict) -> Union[ChainMap, ChainMap, ChainMap]:
    """ Gather config params from cli, dotenv and configfile and get settings where
            cli > dotenv > configfile.
        Also applies debugging setting (as early as possible)

        return dicts containing unified settings for app, mqtt and sql
    """

    app_cli, mqtt_cli, sql_cli = get_cli_params(params)
    # print("cli ", app_cli, mqtt_cli, sql_cli)
    app_dotenv, mqtt_dotenv, sql_dotenv = get_dotenv_params()
    # print("dotenv ", app_dotenv, mqtt_dotenv, sql_dotenv)
    app_file, mqtt_file, sql_file, parsed_files = get_configfile_params(config)
    # print("file ", app_file, mqtt_file, sql_file)

    app = IgnoreNoneChainMap(app_cli, app_dotenv, app_file)
    mqtt = IgnoreNoneChainMap(mqtt_cli, mqtt_dotenv, mqtt_file)
    sql = IgnoreNoneChainMap(sql_cli, sql_dotenv, sql_file)

    if app['debug']:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
        logging.basicConfig(level=logging.DEBUG)
        logger.debug("Debugging enabled.")

    if not parsed_files:
        logger.debug(f"Using data from config files {', '.join(parsed_files)}")
    else:
        logger.debug("No config file found.")

    logger.debug(f"APP  config: {dict([(key, value) for key, value in app.items()])}.")
    logger.debug(f"MQTT config: {dict([(key, value) for key, value in mqtt.items()])}.")
    logger.debug(f"SQL  config: {dict([(key, value) for key, value in sql.items()])}.")
    return app, mqtt, sql


def get_config(config: str, **params: dict) -> ChainMap:
    app_cfg, mqtt_cfg, sql_cfg = get_config_options(config, **params)

    set_mqtt_from_params(mqtt_cfg)
    sql = set_sql_from_params(sql_cfg)
    if app_cfg['raw']:
        ProbeRequest.raw = True
    if app_cfg['lower']:
        ProbeRequest.lower = True

    return app_cfg, sql
