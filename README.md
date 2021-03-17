# probemon
A (not that simple) command line tool for monitoring and logging 802.11 probe frames.

I decided to build upon klein0r's probemon script to add some more options and improve the mac vendor gathering.
The mess this is now evolved from there.
It kinda works - on my machine(s).
Python 3.7+ 

## Features
### Mac vendor lookup
Extensive MAC vendor lookup through multiple different APIs:
- [macaddress.io](https://macaddress.io/) (through [maclookup](https://pypi.org/project/maclookup/) package, API key required)
- [macvendorlookup.com](https://www.macvendorlookup.com)
- [macvendors.co](https://macvendors.co/)
- [macvendors.com](https://api.macvendors.com)

### SQL/MQTT Connectivity
Optional SQL and/or MQTT probes saving (see [Configuration](#configuration))

### Wifi Channel Setting:
Optionally set the wifi channel through several different methods:
  - Manual: Set the used channel manually to a channel of your choice.
  - Auto: Iterate through available channels and automatically select the channel the most APs are using.
  - Hop: Randomly or sequentially hop all available channel with a supplied hop time while collecting probes.
    WARNING: Currently this option can only be set through cli options.
  - SSID: Scan all channels for the supplied ssid of a wifi network and set the channel accordingly.
    If the ssid isn't found in 30 seconds, default to most used channel (see Auto).

### Raw probe request saving
If additional processing of the probes in the future is required, it is possible to save a hexdump of the probe request.
This can be especially useful if for example fingerprinting is later desired.
A recorded raw probe can be reread with scapy using `scapy.all.RadioTap(bytes.fromhex(raw_probe_string))`.

### MAC-Address formatting
Using the `netaddr` package, MAC-Addresses can be formatted to your liking.
Available are (with mac `a0:b1:c2:d3:e4:f5` as an example):
- bare: `AB01C2D3E4F5`
- cisco: `ab01.c2d3.e4f5`
- eui48: `AB-01-C2-D3-E4-F5`
- pgsql: `ab01c2:d3e4f5`
- unix: `ab:1:c2:d3:e4:f5`
- unix_expanded: `ab:01:c2:d3:e4:f5`

## Configuration
Probemon has three different configuration options:
1. [Commandline Arguments/Options](#CLI)
2. A [`config.ini`](#config.ini) file
3. A [`.env`](#.env) file

They can be used together, but CLI takes precedence over the `config.ini` which takes precedence over `.env`.
`config.ini` and `.env` options fail silently if they are misconfigured.

### SQL
The SQL configuration depends entirely on [sqlalchemy](https://docs.sqlalchemy.org/).
Since the ProbeRequest model is quite simple, most in sqlalchey available database flavours are working.
For details or configration help see [here](https://docs.sqlalchemy.org/en/14/core/engines.html).

### MQTT
The MQTT-Client uses [paho-mqtt](https://pypi.org/project/paho-mqtt/).

## Usage
### CLI
```
Usage: probemon.py [OPTIONS] [INTERFACE]

Options:
  --verbose / --no-verbose        Enable verbose output: More status logs are
                                  given but no debugging.

  --debug / --no-debug            Enable debugging output.
  --maclookup-api-key TEXT        Maclookup API key to use with macaddress.io
                                  api.

  --mac-format [bare|cisco|eui48|pgsql|unix|unix_expanded]
                                  Mac address format for database/mqtt
                                  publishing.

  -n, --count INTEGER RANGE       Number probe requests to capture before
                                  exiting. 0 for infinite probes. Default 0.

  -t, --worker-threads INTEGER RANGE
                                  Number of workers that parse the recorded
                                  probe requests.

  --vendor-offline                Don't use maclookup APIs (netaddr only).
  -v, --vendor                    Try to get vendor correlating to caputred
                                  mac address.

  -r, --raw                       Include hex formatted raw probe request
                                  packet.

  -l, --lower                     Convert mac and venodor strings to
                                  lowercase.

  -c, --config PATH               Provide a config file.
  Channel configuration: [mutually_exclusive]
                                  Set the wifi adapters channel for
                                  collection. This can also be run directly by
                                  calling the module 'wifi_channel'.

    --channel-ssid-select TEXT    Scan for supplied ssid and set channel
                                  accordingly.

    --channel-hop <FLOAT BOOLEAN>...
                                  Continously hop between channels while
                                  collecting probes. FLOAT: <hop interval>,
                                  BOOL: <True for random hopping, False for
                                  sequential>.

    --channel-auto                Automatically set wifi channel to the most
                                  used channel in the vicinity.

    --channel-set INTEGER         Manually set wifi channel.
  Mqtt configuration:             Configuration for publishing recorded probes
                                  to a mqtt network. For more details see
                                  https://pypi.org/project/paho-mqtt/.

    --mqtt-debug                  Set mqtt client debugging individually.
    --mqtt-keyfile PATH           PEM encoded private keys used for
                                  authentification - used as client
                                  information for TLS based authentication.

    --mqtt-certfile PATH          PEM encoded client certificate used for
                                  authentification - used as client
                                  information for TLS based authentication.

    --mqtt-ca-certs PATH          Certificate Authority certificate files -
                                  provides basic network encryption.

    --mqtt-password TEXT          Password for mqtt user
    --mqtt-user TEXT              Mqtt username
    --mqtt-topic TEXT             Topic to publish probes under.
    --mqtt-port INTEGER           Broker port
    --mqtt-host TEXT              Broker host name
  SQL configuration:              Configuration for publishing recorded probes
                                  to a sql database. For more information
                                  visit https://docs.sqlalchemy.org/en/14/core
                                  /engines.html#database-urls.

    --sql-drop-all                Drop probe request table on startup. Only
                                  valid in combination with DEBUG flag!

    --sql-kwargs TEXT             Sql additional url args that get appended
                                  'as is' to url.

    --sql-driver TEXT             Sql driver if non-standard driver is
                                  desired.

    --sql-database TEXT           Sql database which probes are written to.
    --sql-password TEXT           Password for sql user
    --sql-user TEXT               Username to connect to the database with
    --sql-port INTEGER
    --sql-host TEXT               Sql host name
    --sql-sqlite-path PATH        Sqlite database path. Only needed when sql-
                                  dialect is sqlite.

    --sql-dialect [postgresql|mysql|oracle|mssql|sqlite]
                                  Sql host name
  --help                          Show this message and exit.
```

### config.ini
Windows .ini -like config file with sections.
The path to the config can be supplied in the cli options `-c`-Flag.
Alternatively probemon looks for a `config.ini` in probemons basedir or in the users config files: `~/.config/probemon/config.ini` (but does __not__ automatically generate them).
An example of a config.ini file can be found [here](./config.ini_EXAMPLE) which contains all possible settings.

### .env
This file exports the config variables into the users environment, which probemon then searches for `PROBEMON_` variables.
It should sit in the current directory or in probemons base directory or any of its parents.
For truthy values in the config (see flags in the cli options) any string other than `false` is considered `True`, regardless of case.
An example of an .env file can be found [here](./.env_EXAMPLE) which contains all possible settings.

## systemd Service-File Example
To run the script in the background - for example on a Raspberry Pi, I recommend using a systemd service or cron.

Assuming you put probemon into `/root/python` here is my `probemon.service` file for reference:
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
# uncomment the next lines to do some interface setups
#ExecStartPre=-iw phy phy0 interface add mon0 type monitor
#ExecStartPre=-ip link set wlan0 down  # disable original wifi interface. needed for me to enable channel switching
#ExecStartPre=-ip link set mon0 up
ExecStart=/root/python/probemon/probes.py mon0
# give the script 30s to process queued probes. If its stil running after that, kill it
ExecStop=sh -c '/bin/kill -s SIGINT -$MAINPID && timeout 30s tail --pid=$MAINPID -f /dev/null'
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```
