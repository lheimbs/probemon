# probemon
A (not that simple) command line tool for monitoring and logging 802.11 probe frames

I decided to build upon klein0r's probemon script to add some more options and improve the mac vendor gathering.
The mess this is now evolved from there.
It kinda works - on my machine(s). 

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
  -n, --count INTEGER RANGE       Number probe requests to capture before
                                  exiting. 0 for infinite probes. Default 0.
  --maclookup-api-key TEXT        Maclookup API key to use with macaddress.io
                                  api.
  --debug / --no-debug            Enable debugging output.
  --verbose / --no-verbose        Enable verbose output: More status logs are
                                  given but no debugging.

  Channel configuration: [mutually_exclusive]
                                  Set the wifi adapters channel for
                                  collection. This can also be run directly by
                                  calling the module 'wifi_channel'.
    --channel-set INTEGER         Manually set wifi channel.
    --channel-auto                Automatically set wifi channel.
    --channel-hop FLOAT           Continously hop between channels.

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
Assuming you put probemon into /root/python:
```
[Unit]
Description=Probemon Service
Wants=network.target
After=network.target

[Service]
Type=simple
Restart=on-failure
RestartSec=5s
WorkingDirectory=/root/python
# uncomment the next lines if your to skip interface setup
ExecStartPre=-iw phy phy0 interface add mon0 type monitor
ExecStartPre=-ip link set wlan0 down  # disable original wifi interface. needed for me to enable channel switching
ExecStartPre=-ip link set mon0 up
ExecStart=/root/python/probemon/probes.py mon0
ExecStop=sh -c '/bin/kill -s SIGINT -$MAINPID && timeout 30s tail --pid=$MAINPID -f /dev/null'
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```
