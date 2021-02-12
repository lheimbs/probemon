# probemon
A (not that simple anymore) command line tool for monitoring and logging 802.11 probe frames


I decided to build this simple python script using scapy so that I could record 802.11 probe frames over a long period of time. This was specifically useful in my use case: proving that a person or device was present at a given location at a given time.

## Usage

```
Usage: __main__.py [OPTIONS] [INTERFACE]

Options:
  -c, --config PATH               Provide a config file.
  -l, --lower                     Convert mac and venodor strings to
                                  lowercase.

  -r, --raw                       Include hex formatted raw probe request
                                  packet.

  -v, --vendor                    Try to get vendor correlating to caputred
                                  mac address.

  -t, --worker-threads INTEGER RANGE
                                  Number of workers that parse the recorded
                                  probe requests.

  -c, --count INTEGER RANGE       Number probe requests to capture before
                                  exiting. 0 for infinite probes. Default 0.

  --debug / --no-debug            Debug flag
  --no-stdout                     Disable printing probes to stdout. DOES NOT
                                  DISABLE LOGGING!

  Channel configuration: [mutually_exclusive]
                                  Set the wifi adapters channel for
                                  collection.This can also be run directly by
                                  calling the module 'wifi_channel'.
    --channel-set INTEGER         Manually set wifi channel.
    --channel-auto                Automatically set wifi channel.

  Mqtt configuration:             Configuration for publishing recorded probes
                                  to a mqtt network. For more details see
                                  https://pypi.org/project/paho-mqtt/.
    --mqtt-host TEXT              Broker host name
    --mqtt-port INTEGER           Broker port
    --mqtt-topic TEXT             Topic to publish probes under.
    --mqtt-user TEXT              Mqtt username
    --mqtt-password TEXT          Password for mqtt user
    --mqtt-ca-certs PATH          Certificate Authority certificate files -
                                  provides basic network encryption.

    --mqtt-certfile PATH          PEM encoded client certificate used for
                                  authentification - used as client
                                  information for TLS based authentication.

    --mqtt-keyfile PATH           PEM encoded private keys used for
                                  authentification - used as client
                                  information for TLS based authentication.

    --mqtt-debug                  Set mqtt client debugging individually.

  SQL configuration:              Configuration for publishing recorded probes
                                  to a sql database. For more information
                                  visit https://docs.sqlalchemy.org/en/14/core
                                  /engines.html#database-urls.
    --sql-dialect [postgresql|mysql|oracle|mssql|sqlite]
                                  Sql host name
    --sql-sqlite-path PATH        Sqlite database path. Only needed when sql-
                                  dialect is sqlite.

    --sql-host TEXT               Sql host name
    --sql-port INTEGER
    --sql-user TEXT               Username to connect to the database with
    --sql-password TEXT           Password for sql user
    --sql-database TEXT           Sql database which probes are written to.
    --sql-driver TEXT             Sql driver if non-standard driver is
                                  desired.

    --sql-kwargs TEXT             Sql additional url args that get appended
                                  'as is' to url.

  --help                          Show this message and exit.
```

## systemd Service-File Example

```
[Unit]
Description=Probemon MQTT Service

[Service]
PIDFile=/run/probemon.pid
RemainAfterExit=no
Restart=on-failure
RestartSec=5s
ExecStart=/root/python/probemon/probemon.py -i mon0 --mac-info --ssid --rssi --mqtt-broker IP --mqtt-user USERNAME --mqtt-password PASSWORD --mqtt-topic TOPIC  --pid /run/probemon.pid
StandardOutput=null

[Install]
WantedBy=multi-user.target
Alias=probemon.servic
```
