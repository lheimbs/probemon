from types import FunctionType

import click
from click_option_group import OptionGroup, MutuallyExclusiveOptionGroup


def cli_options(main: FunctionType) -> FunctionType:
    main = click.command()(main)
    main = click.argument('interface', default='mon0')(main)
    main = click.option(
        '--config', '-c', type=click.Path(),
        help="Provide a config file.",
    )(main)
    main = click.option(
        '--lower', '-l', is_flag=True,
        help="Convert mac and venodor strings to lowercase.",
    )(main)
    main = click.option(
        '--raw', '-r', is_flag=True,
        help="Include hex formatted raw probe request packet.",
    )(main)
    main = click.option(
        '--vendor', '-v', is_flag=True,
        help="Try to get vendor correlating to caputred mac address.",
    )(main)
    main = click.option(
        '--worker-threads',
        '-t',
        type=click.IntRange(1, None),
        default=1,
        help="Number of workers that parse the recorded probe requests.",
    )(main)
    main = click.option(
        '--count',
        '-n',
        type=click.IntRange(0, None),
        default=0,
        help=(
            "Number probe requests to capture before exiting. "
            "0 for infinite probes. Default 0."
        ),
    )(main)
    main = click.option(
        '--maclookup-api-key',
        help="Maclookup API key to use with macaddress.io api."
    )(main)
    main = click.option(
        '--debug/--no-debug', default=False,
        help='Enable debugging output.',
    )(main)
    main = click.option(
        '--verbose/--no-verbose', default=False,
        help=(
            "Enable verbose output: "
            "More status logs are given but no debugging."
        ),
    )(main)
    # main = click.option(
    #     '--no-stdout', is_flag=True,
    #     help="Disable printing probes to stdout. DOES NOT DISABLE LOGGING!",
    # )(main)

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
        help="Automatically set wifi channel.",
    )(main)
    main = channel_group.option(
        '--channel-hop', type=float,
        help="Continously hop between channels.",
    )(main)

    # MQTT OPTIONS
    mqtt_group = OptionGroup(
        'Mqtt configuration',
        help=(
            'Configuration for publishing recorded probes to a mqtt network. '
            "For more details see https://pypi.org/project/paho-mqtt/."
        )
    )
    main = mqtt_group.option(
        '--mqtt-host', help='Broker host name',
    )(main)
    main = mqtt_group.option(
        '--mqtt-port', type=int, default=1883, help='Broker port',
    )(main)
    main = mqtt_group.option(
        '--mqtt-topic', help="Topic to publish probes under.",
    )(main)
    main = mqtt_group.option(
        '--mqtt-user', help='Mqtt username',
    )(main)
    main = mqtt_group.option(
        '--mqtt-password', help='Password for mqtt user',
    )(main)
    main = mqtt_group.option(
        '--mqtt-ca-certs', type=click.Path(),
        help=(
            "Certificate Authority certificate files - "
            "provides basic network encryption."
        ),
    )(main)
    main = mqtt_group.option(
        '--mqtt-certfile', type=click.Path(),
        help=(
            "PEM encoded client certificate used for authentification - "
            "used as client information for TLS based authentication."
        ),
    )(main)
    main = mqtt_group.option(
        '--mqtt-keyfile', type=click.Path(),
        help=(
            "PEM encoded private keys used for authentification - "
            "used as client information for TLS based authentication."
        )
    )(main)
    main = mqtt_group.option(
        '--mqtt-debug', is_flag=True,
        help='Set mqtt client debugging individually.',
    )(main)

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
    main = sql_group.option(
        '--sql-dialect',
        type=click.Choice(
            ['postgresql', 'mysql', 'oracle', 'mssql', 'sqlite'],
            case_sensitive=False
        ),
        help='Sql host name',
    )(main)
    main = sql_group.option(
        '--sql-sqlite-path',
        type=click.Path(),
        help='Sqlite database path. Only needed when sql-dialect is sqlite.'
    )(main)
    main = sql_group.option(
        '--sql-host', help='Sql host name',
    )(main)
    main = sql_group.option(
        '--sql-port', type=int,
    )(main)
    main = sql_group.option(
        '--sql-user', help='Username to connect to the database with',
    )(main)
    main = sql_group.option(
        '--sql-password', help='Password for sql user',
    )(main)
    main = sql_group.option(
        '--sql-database', help='Sql database which probes are written to.',
    )(main)
    main = sql_group.option(
        '--sql-driver', help='Sql driver if non-standard driver is desired.',
    )(main)
    main = sql_group.option(
        '--sql-kwargs',
        help="Sql additional url args that get appended 'as is' to url.",
    )(main)
    main = sql_group.option(
        '--sql-drop-all', is_flag=True,
        help=(
            "Drop probe request table on startup. "
            "Only valid in combination with DEBUG flag!"
        ),
    )(main)

    # file_group = OptionGroup(
    #     'JSON configuration',
    #     help="Configuraiton for writing recorded probes to a json file."
    # )
    # main = file_group.option(
    #     '--json-file',
    #     type=click.Path(writable=True),
    #     help='JSON file path. Can be either to a directory or a file.'
    # )(main)
    # main = file_group.option('--json-max-filesize')(main)
    return main
