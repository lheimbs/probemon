import logging

import click
from click_option_group import optgroup, MutuallyExclusiveOptionGroup
from sqlalchemy.orm import sessionmaker

from .config import get_config
from .wifi_channel import set_channel
# from .config.cli import cli
# from .config.config_file import parse_config

logging.basicConfig(
    format='%(name)-20s: %(funcName)-20s: %(levelname)-8s : %(message)s',
    level=logging.INFO,
)
logger = logging.getLogger()
Session = sessionmaker()

@click.command()
@click.argument('interface', default='mon0')
@click.option('--config', '-c', type=click.Path(), help="Provide a config file.")
@click.option('--lower', '-l', is_flag=True, help="Convert mac and venodor strings to lowercase.")
@click.option('--debug/--no-debug', default=False, help='Debug flag')
@optgroup.group(
    'Channel configuration', cls=MutuallyExclusiveOptionGroup,
    help=(
        "Set the wifi adapters channel for collection."
        "This can also be run directly by calling the module 'wifi_channel'."
    )
)
@optgroup.option('--channel-set', type=int, help="Manually set wifi channel.")
@optgroup.option('--channel-auto', is_flag=True, help="Automatically set wifi channel.")
@optgroup.group(
    'Mqtt configuration',
    help=(
        'Configuration for publishing recorded probes to a mqtt network. '
        "For more details see https://pypi.org/project/paho-mqtt/."
    )
)
@optgroup.option('--mqtt-host', help='Broker host name')
@optgroup.option('--mqtt-port', type=int, default=1883, help='Broker port')
@optgroup.option('--mqtt-user', help='Mqtt username')
@optgroup.option('--mqtt-password', help='Password for mqtt user')
@optgroup.option(
    '--mqtt-ca-certs', type=click.Path(),
    help='Certificate Authority certificate files - provides basic network encryption.'
)
@optgroup.option(
    '--mqtt-certfile', type=click.Path(),
    help=(
        "PEM encoded client certificate used for authentification - "
        "used as client information for TLS based authentication."
    )
)
@optgroup.option(
    '--mqtt-keyfile', type=click.Path(),
    help=(
        "PEM encoded private keys used for authentification - "
        "used as client information for TLS based authentication."
    )
)
@optgroup.group(
    'SQL configuration',
    help=(
        'Configuration for publishing recorded probes to a sql database. '
        "For more information visit https://docs.sqlalchemy.org/en/14/core/engines.html#database-urls."
    )
)
@optgroup.option(
    '--sql-dialect',
    type=click.Choice(['postgresql', 'mysql', 'oracle', 'mssql', 'sqlite'], case_sensitive=False),
    help='Sql host name',
)
@optgroup.option(
    '--sql-sqlite-path',
    type=click.Path(),
    help='Sqlite database path. Only needed when sql-dialect is sqlite.'
)
@optgroup.option('--sql-host', help='Sql host name')
@optgroup.option('--sql-port', type=int)
@optgroup.option('--sql-user', help='Username to connect to the database with')
@optgroup.option('--sql-password', help='Password for sql user')
@optgroup.option('--sql-database', help='Sql database which probes are written to.')
@optgroup.option('--sql-driver', help='Sql driver if non-standard driver is desired.')
# @optgroup.group('JSON configuration',
#                 help="Configuraiton for writing recorded probes to a json file.")
# @optgroup.option(
#     '--json-file',
#     type=click.Path(writable=True),
#     help='JSON file path. Can be either to a directory or a file.'
# )
# @optgroup.option('--json-max-filesize')
def main(interface: str, config: str, debug: bool, **params: dict):
    mqtt, sql = get_config(interface, config, debug, **params)
    sql.register_engine(Session)

    if any([optn.startswith('channel_') for optn in params]):
        set_channel(interface, params)


if __name__ == "__main__":
    main()
