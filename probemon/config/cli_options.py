from typing import Callable

import click
from click_option_group import OptionGroup, MutuallyExclusiveOptionGroup


def cli_options(main: Callable) -> Callable:
    click.argument('interface', default='mon0')(main)
    click.option(
        '--config', '-c', type=click.Path(),
        help="Provide a config file.",
    )(main)
    click.option(
        '--lower', '-l',
        is_flag=True,
        help="Convert mac and venodor strings to lowercase.",
    )(main)
    click.option(
        '--raw', '-r',
        is_flag=True,
        help="Include hex formatted raw probe request packet.",
    )(main)
    click.option(
        '--vendor', '-v',
        is_flag=True,
        help="Try to get vendor correlating to caputred mac address.",
    )(main)
    click.option(
        '--vendor-offline',
        is_flag=True,
        help="Don't use maclookup APIs (netaddr only).",
    )(main)
    click.option(
        '--worker-threads',
        '-t',
        type=click.IntRange(1, None),
        # default=1,
        help="Number of workers that parse the recorded probe requests.",
    )(main)
    click.option(
        '--count',
        '-n',
        type=click.IntRange(0, None),
        help=(
            "Number probe requests to capture before exiting. "
            "0 for infinite probes. Default 0."
        ),
    )(main)
    click.option(
        '--mac-format',
        type=click.Choice(
            ['bare', 'cisco', 'eui48', 'pgsql', 'unix', 'unix_expanded'],
            case_sensitive=False
        ),
        help="Mac address format for database/mqtt publishing."
    )(main)
    click.option(
        '--maclookup-api-key',
        help="Maclookup API key to use with macaddress.io api."
    )(main)
    click.option(
        '--channel',
        help=(
            "Pass an argument string for the module 'wifi_channel'. "
            "This will set the wifi adapters channel for collection. "
            "It can also be run directly by calling the module "
            "'wifi_channel'. Allowed arguments: ['set', 'scan', "
            "'hop', 'auto', 'search', 'hop_async_no_sniff', '--all', "
            "'--2ghz', '--5ghz', '--all-channels', '--popular', "
            "'--populated', '--time', '--random']. "
            "To specify the ssid for 'search', prefix the ssid with <SSID:> "
            "(without brackets). "
            "To get help on the arguments pass '--help' (ie: 'set --help')."
            "The Interface gets passed through!"
        ),
    )(main)
    click.option(
        '--debug/--no-debug',
        default=False,
        help='Enable debugging output.',
    )(main)
    click.option(
        '--verbose/--no-verbose',
        default=False,
        help=(
            "Enable verbose output: "
            "More status logs are given but no debugging."
        ),
    )(main)
    # main = click.option(
    #     '--no-stdout', is_flag=True,
    #     help="Disable printing probes to stdout. DOES NOT DISABLE LOGGING!",
    # )(main)
    return main


def cli_channel_options(main: Callable) -> Callable:        # pragma: no cover
    # CHANNEL OPTIONS
    channel_group = MutuallyExclusiveOptionGroup(
        'Channel configuration',
        help=(
            "Set the wifi adapters channel for collection. This can "
            "also be run directly by calling the module 'wifi_channel'."
        )
    )
    main = channel_group.option(
        '--channel-set', type=int,
        help="Manually set wifi channel.",
    )(main)
    main = channel_group.option(
        '--channel-auto', is_flag=True,
        help=(
            "Automatically set wifi channel "
            "to the most used channel in the vicinity."
        )
    )(main)
    main = channel_group.option(
        '--channel-hop', default=(None, None), type=(float, bool),
        help=(
            "Continously hop between channels while collecting probes. "
            "FLOAT: <hop interval>, "
            "BOOL: <True for random hopping, False for sequential>."
        ),
    )(main)
    main = channel_group.option(
        '--channel-ssid-select',
        help="Scan for supplied ssid and set channel accordingly.",
    )(main)
    return main


def cli_mqtt_options(main: Callable) -> Callable:
    # MQTT OPTIONS
    mqtt_group = OptionGroup(
        'Mqtt configuration',
        help=(
            "Configuration for publishing recorded probes to a mqtt network. "
            "For more details see https://pypi.org/project/paho-mqtt/."
        )
    )
    mqtt_group.option(
        '--mqtt-host', help='Broker host name',
    )(main)
    mqtt_group.option(
        '--mqtt-port', type=int,
        # default=1883,
        help='Broker port',
    )(main)
    mqtt_group.option(
        '--mqtt-topic', help="Topic to publish probes under.",
    )(main)
    mqtt_group.option(
        '--mqtt-user', help='Mqtt username',
    )(main)
    mqtt_group.option(
        '--mqtt-password', help='Password for mqtt user',
    )(main)
    mqtt_group.option(
        '--mqtt-ca-certs', type=click.Path(),
        help=(
            "Certificate Authority certificate files - "
            "provides basic network encryption."
        ),
    )(main)
    mqtt_group.option(
        '--mqtt-certfile', type=click.Path(),
        help=(
            "PEM encoded client certificate used for authentification - "
            "used as client information for TLS based authentication."
        ),
    )(main)
    mqtt_group.option(
        '--mqtt-keyfile', type=click.Path(),
        help=(
            "PEM encoded private keys used for authentification - "
            "used as client information for TLS based authentication."
        )
    )(main)
    mqtt_group.option(
        '--mqtt-debug', is_flag=True,
        help='Set mqtt client debugging individually.',
    )(main)
    return main


def cli_sql_options(main: Callable) -> Callable:
    # SQL OPTIONS
    sql_group = OptionGroup(
        'SQL configuration',
        help=(
            'Configuration for publishing recorded probes to a sql database. '
            "For more information visit "
            "https://docs.sqlalchemy.org/en/14/core/"
            "engines.html#database-urls."
        )
    )
    sql_group.option(
        '--sql-dialect',
        type=click.Choice(
            ['postgresql', 'mysql', 'oracle', 'mssql', 'sqlite'],
            case_sensitive=False
        ),
        help='Sql host name',
    )(main)
    sql_group.option(
        '--sql-sqlite-path',
        type=click.Path(),
        help='Sqlite database path. Only needed when sql-dialect is sqlite.'
    )(main)
    sql_group.option(
        '--sql-host', help='Sql host name',
    )(main)
    sql_group.option(
        '--sql-port', type=int,
    )(main)
    sql_group.option(
        '--sql-user', help='Username to connect to the database with',
    )(main)
    sql_group.option(
        '--sql-password', help='Password for sql user',
    )(main)
    sql_group.option(
        '--sql-database', help='Sql database which probes are written to.',
    )(main)
    sql_group.option(
        '--sql-driver', help='Sql driver if non-standard driver is desired.',
    )(main)
    sql_group.option(
        '--sql-kwargs',
        help="Sql additional url args that get appended 'as is' to url.",
    )(main)
    sql_group.option(
        '--sql-drop-all', is_flag=True,
        help=(
            "Drop probe request table on startup. "
            "Only valid in combination with DEBUG flag!"
        ),
    )(main)
    return main


def cli_server_publish_options(main: Callable) -> Callable:
    server_publish = OptionGroup(
        'Publish to webserver configuration',
        help="Configuration for publishing recieved Probes to a Webserver."
    )
    main = server_publish.option(
        '--url-publish-url',
        help="Url to post the revieved probes to."
    )(main)
    main = server_publish.option(
        '--url-publish-token',
        help="Token to authenticate probemon with against the server."
    )(main)
    main = server_publish.option(
        '--url-publish-token-prefix',
        help="Prefix of token in Authentication HTTP header. Defaults to 'Token <token>'."
    )(main)
    main = server_publish.option(
        '--url-publish-only-mac-and-time', is_flag=True,
    )(main)
    return main


# def cli_files_options(main: Callable) -> Callable:
#     file_group = OptionGroup(
#         'JSON configuration',
#         help="Configuraiton for writing recorded probes to a json file."
#     )
#     main = file_group.option(
#         '--json-file',
#         type=click.Path(writable=True),
#         help='JSON file path. Can be either to a directory or a file.'
#     )(main)
#     main = file_group.option('--json-max-filesize')(main)
#     return main
