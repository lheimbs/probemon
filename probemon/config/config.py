import os
import logging
from collections import ChainMap
from typing import Tuple

from .misc import get_url, MissingChainMap, set_mac_dialect
from .cli import get_cli_params
from .dot_env import get_dotenv_params
from .config_file import get_configfile_params
from ..sql import Sql
from ..mqtt import Mqtt
from ..probe_request import ProbeRequest

logger = logging.getLogger(__name__)


def set_mqtt_from_params(mqtt_config: MissingChainMap) -> None:
    Mqtt.set_server(mqtt_config['mqtt_host'], mqtt_config['mqtt_port'])
    Mqtt.set_topic(mqtt_config['mqtt_topic'])
    Mqtt.set_user(mqtt_config['mqtt_user'], mqtt_config['mqtt_password'])
    tls_files = {'mqtt_ca_certs': None, 'mqtt_certfile': None, 'mqtt_keyfile': None}
    for file in tls_files:
        if mqtt_config[file]:
            if os.path.exists(mqtt_config[file]):
                tls_files[file] = mqtt_config[file]
            else:
                logger.error(f"{file} '{mqtt_config[file]}' does not exist!")
    Mqtt.set_tls(**tls_files)
    if mqtt_config['mqtt_debug']:
        Mqtt.enable_debugging()

    if Mqtt.is_enabled():
        logger.info("Mqtt is enabled with following options:")
        for key, value in mqtt_config.items():
            if value and key != "mqtt_password":
                logger.info(f"    {key:10}: {value}")


def set_sql_from_params(cfg: MissingChainMap) -> Sql:
    sql = Sql()
    if not cfg['sql_dialect']:
        logger.debug("No sql dialect supplied.")
        if any([
            cfg['sql_host'],
            cfg['sql_sqlite_path'],
            cfg['sql_user'],
            cfg['sql_password']
        ]):
            logger.warning(
                "Warning: with sql dialect unset, "
                "all other sql options will be ignored!"
            )
        return sql
    if str(cfg['sql_dialect']).lower() != 'sqlite' \
            and not cfg['sql_host']:
        logger.debug(
            "No sql host with dialect other than sqlite supplied. "
            "Disabling sql."
        )
        if any([cfg['sql_user'], cfg['sql_password']]):
            logger.warning(
                "Warning: with sql dialect not sqlite and sql host unset, "
                "all sql options will be ignored "
                "and no data will get published to a sql database."
            )
        return sql
    # TODO: what if get_url params are missing from config?
    url = get_url(**cfg)
    sql.set_url(url)
    return sql


def set_probe_request_from_params(cfg: MissingChainMap) -> None:
    """Set ProbeRequests class variables according to the app config"""
    if cfg['raw']:
        ProbeRequest.raw = True
    if cfg['lower']:
        ProbeRequest.lower = True
    if cfg['vendor']:
        ProbeRequest.get_vendor = True
    if cfg['maclookup_api_key']:
        ProbeRequest.maclookup_api_key = cfg['maclookup_api_key']
    if cfg['vendor_offline']:
        ProbeRequest.vendor_offline = True


def get_config(config: str, **params: dict) -> ChainMap:
    cfg = MissingChainMap(
        get_cli_params(params),
        get_dotenv_params(),
        get_configfile_params(config)
    )
    if cfg['debug']:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug('Debugging enabled.')
    elif cfg['verbose']:
        logging.getLogger().setLevel(logging.INFO)
        logger.info("Verbosity increased.")

    if cfg['parsed_files']:
        logger.debug(
            f"Parsed config files: {', '.join(cfg['parsed_files'])}"
        )
    logger.debug(
        f"Config: {cfg}."
    )

    sql = set_sql_from_params(cfg)
    sql.register(True if cfg['debug'] and cfg['drop_all'] else False)
    if Sql.is_enabled():
        logger.info("Sql is enabled with following options:")
        for key, value in cfg.items():
            if value and key != "sql_password":
                logger.info(f"    {key:10}: {value}")

    set_mqtt_from_params(cfg)
    set_probe_request_from_params(cfg)
    set_mac_dialect(cfg['mac_format'])
    return cfg
