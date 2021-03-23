import os
import logging
from collections import ChainMap
from typing import Tuple

from .misc import get_url, IgnoreNoneChainMap, set_mac_dialect
from .cli import get_cli_params
from .dot_env import get_dotenv_params
from .config_file import get_configfile_params
from ..sql import Sql
from ..mqtt import Mqtt
from ..probe_request import ProbeRequest

logger = logging.getLogger(__name__)


def set_mqtt_from_params(mqtt_config: IgnoreNoneChainMap) -> None:
    Mqtt.set_server(mqtt_config['host'], mqtt_config['port'])
    Mqtt.set_topic(mqtt_config['topic'])
    Mqtt.set_user(mqtt_config['user'], mqtt_config['password'])
    tls_files = {'ca_certs': None, 'certfile': None, 'keyfile': None}
    for file in tls_files:
        if mqtt_config[file]:
            if os.path.exists(mqtt_config[file]):
                tls_files[file] = mqtt_config[file]
            else:
                logger.error(f"{file} '{mqtt_config[file]}' does not exist!")
    Mqtt.set_tls(**tls_files)
    if mqtt_config['debug']:
        Mqtt.enable_debugging()

    if Mqtt.is_enabled():
        logger.info("Mqtt is enabled with following options:")
        for key, value in mqtt_config.items():
            if value and key != "password":
                logger.info(f"    {key:10}: {value}")


def set_sql_from_params(sql_config: IgnoreNoneChainMap) -> Sql:
    sql = Sql()
    if not sql_config['dialect']:
        logger.debug("No sql dialect supplied.")
        if any([
            sql_config['host'],
            sql_config['sqlite_path'],
            sql_config['user'],
            sql_config['password']
        ]):
            logger.warning(
                "Warning: with sql dialect unset, "
                "all other sql options will be ignored!"
            )
        return sql
    if str(sql_config['dialect']).lower() != 'sqlite' \
            and not sql_config['host']:
        logger.debug(
            "No sql host with dialect other than sqlite supplied. "
            "Disabling sql."
        )
        if any([sql_config['user'], sql_config['password']]):
            logger.warning(
                "Warning: with sql dialect not sqlite and sql host unset, "
                "all sql options will be ignored "
                "and no data will get published to a sql database."
            )
        return sql
    # TODO: what if get_url params are missing from config?
    url = get_url(**sql_config)
    sql.set_url(url)
    return sql


def set_probe_request_from_params(app_cfg: IgnoreNoneChainMap) -> None:
    """Set ProbeRequests class variables according to the app config"""
    if app_cfg['raw']:
        ProbeRequest.raw = True
    if app_cfg['lower']:
        ProbeRequest.lower = True
    if app_cfg['vendor']:
        ProbeRequest.get_vendor = True
    if app_cfg['maclookup_api_key']:
        ProbeRequest.maclookup_api_key = app_cfg['maclookup_api_key']
    if app_cfg['vendor_offline']:
        ProbeRequest.vendor_offline = True


def get_config_options(
        config: str,
        **params: dict) -> Tuple[ChainMap, ChainMap, ChainMap, str]:
    """ Gather config params from cli, dotenv and configfile and get settings.

    Use this Order: cli > dotenv > configfile.
    Also applies debugging setting (as early as possible)
    Returns ChainMaps containing unified settings for app, mqtt and sql
    """
    app_cli, mqtt_cli, sql_cli = get_cli_params(params)
    app_dotenv, mqtt_dotenv, sql_dotenv = get_dotenv_params()
    (
        app_file,
        mqtt_file,
        sql_file
    ) = get_configfile_params(config)

    app = IgnoreNoneChainMap(app_cli, app_dotenv, app_file)
    mqtt = IgnoreNoneChainMap(mqtt_cli, mqtt_dotenv, mqtt_file)
    sql = IgnoreNoneChainMap(sql_cli, sql_dotenv, sql_file)
    return app, mqtt, sql


def get_config(config: str, **params: dict) -> ChainMap:
    app_cfg, mqtt_cfg, sql_cfg = get_config_options(config, **params)
    if app_cfg['debug']:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug('Debugging enabled.')
    elif app_cfg['verbose']:
        logging.getLogger().setLevel(logging.INFO)
        logger.info("Verbosity increased.")

    if app_cfg['parsed_files']:
        logger.debug(
            f"Parsed config files: {', '.join(app_cfg['parsed_files'])}"
        )
    logger.debug(
        f"APP  config: {app_cfg}."
    )

    sql = set_sql_from_params(sql_cfg)
    sql.register(True if app_cfg['debug'] and sql_cfg['drop_all'] else False)
    if Sql.is_enabled():
        logger.info("Sql is enabled with following options:")
        for key, value in sql_cfg.items():
            if value and key != "password":
                logger.info(f"    {key:10}: {value}")

    set_mqtt_from_params(mqtt_cfg)
    set_probe_request_from_params(app_cfg)
    set_mac_dialect(app_cfg['mac_format'])
    return app_cfg
