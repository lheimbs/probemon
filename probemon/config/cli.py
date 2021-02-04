import logging

from ..mqtt import Mqtt
from ..sql import Sql

logger = logging.getLogger('config.cli')

def cli(params: dict):
    logger.debug(f"CLI Parameters: {params}")
    # mqtt = validate_mqtt_params(params)
    # sql = validate_sql_params(params)
    return get_mqtt_params(params), get_sql_params(params)


def get_mqtt_params(params: dict) -> dict:
    """ translate cli parameters into unified parameter dict """
    parsed_params = {}
    parsed_params['host'] = params['mqtt_host'] if params['mqtt_host'] else ""
    parsed_params['port'] = params['mqtt_port']
    parsed_params['user'] = params['mqtt_user'] if params['mqtt_user'] else ""
    parsed_params['password'] = params['mqtt_password'] if params['mqtt_password'] else ""
    parsed_params['ca_certs'] = params['mqtt_ca_certs']
    parsed_params['certfile'] = params['mqtt_certfile']
    parsed_params['keyfile'] = params['mqtt_keyfile']
    return parsed_params


def get_sql_params(params: dict) -> dict:
    """ translate cli parameters into unified parameter dict """
    parsed_params = {}
    parsed_params['dialect'] = params['sql_dialect'] if params['sql_dialect'] else ""
    parsed_params['database'] = params['sql_database'] if params['sql_database'] else ""
    parsed_params['driver'] = params['sql_driver'] if params['sql_driver'] else ""
    parsed_params['host'] = params['sql_host'] if params['sql_host'] else ""
    parsed_params['port'] = params['sql_port'] if params['sql_port'] else 0
    parsed_params['user'] = params['sql_user'] if params['sql_user'] else ""
    parsed_params['password'] = params['sql_password'] if params['sql_password'] else ""
    parsed_params['path'] = params['sql_sqlite_path']
    return parsed_params


def validate_mqtt_params(params: dict):
    mqtt = Mqtt()
    if not params['mqtt_host']:
        logger.debug("No mqtt host supplied. Disabling mqtt.")
        if any([params['mqtt_user'], params['mqtt_password']]):
            logger.warning("Warning: with mqtt_host unset, all other mqtt options will be ignored!")
    else:
        logger.debug(f"Enabling mqtt with broker at {params['mqtt_host']}.")
        mqtt.enable()
        mqtt.set_server(params['mqtt_host'], params['mqtt_port'])
        mqtt.set_user(params['mqtt_user'], params['mqtt_password'])
    return mqtt


def validate_sql_params(params):
    clean_params = {}
    sql = Sql()

    if not params['sql_dialect']:
        logger.debug("No sql dialect supplied. Disabling sql.")
        if any([params['sql_host'], params['sql_sqlite_path'], params['sql_user'], params['sql_password']]):
            logger.warning("Warning: with --sql-dialect unset, all other sql options will be ignored!")
        return sql

    if params['sql_dialect'].lower() != 'sqlite' and not params['sql_host']:
        logger.debug("No sql host with dialiect other than sqlite supplied. Disabling sql.")
        if any([params['sql_user'], params['sql_password']]):
            logger.warning(
                "Warning: with --sql-dialect not sqlite and --sql-host unset, "
                "all sql options will be ignored and no data will get published to a sql database."
            )
        return sql

    sql.enable()
    if params['sql_dialect'].lower() == 'sqlite':
        if params['sql_sqlite_path']:
            logger.debug(f"Using sqlite database at {params['sql_sqlite_path']}.")
        else:
            logger.info("Using sqlite database in memory.")

    clean_params['dialect'] = params['sql_dialect'] if params['sql_dialect'] else ""
    clean_params['path'] = params['--sql-path'] if params['--sql-path'] else ""
    clean_params['host'] = params['sql_host'] if params['sql_host'] else ""
    clean_params['port'] = params['sql_port'] if params['sql_port'] else ""
    clean_params['username'] = params['sql_user'] if params['sql_user'] else ""
    clean_params['password'] = params['sql_password'] if params['sql_password'] else ""
    clean_params['database'] = params['sql_database'] if params['sql_database'] else ""
    clean_params['driver'] = ""

    # sql.set_url(get_url(**clean_params))
    return sql


def validate_file_params(params: dict, file_type: str):
    pass


if __name__ == '__main__':
    cli()
