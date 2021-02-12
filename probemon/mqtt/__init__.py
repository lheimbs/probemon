import logging
from typing import TypeVar

import paho.mqtt.client as mqtt_client

logger = logging.getLogger('mqtt')
ProbeRequest = TypeVar('ProbeRequest')

class Mqtt(object):
    """ Mqtt class to handle client connection and publishing """
    __enabled = False
    __host = None
    __port = None
    __user = None
    __password = None
    __ca_certs = __certfile = __keyfile = None
    __debug = False

    def is_enabled() -> bool:
        return Mqtt.__enabled

    def enable() -> None:
        Mqtt.__enabled = True

    def disable() -> None:
        Mqtt.__enabled = False

    def set_server(host: str, port: int = 0) -> None:
        if not host:
            logger.warning(
                "Can't configure Mqtt-Client because no host is supplied. "
                "Disabling mqtt!"
            )
            Mqtt.disable()
            return

        if not port:
            logger.info("No port supplied. Using default port 1883.")
            port = 1883
        elif port:
            try:
                port = int(port)
            except ValueError:
                logger.error("Invalid port supplied. Disabling Mqtt!")
                Mqtt.disable()
                return

        logger.debug(f"Setting mqtt host {host} with port {port}.")
        Mqtt.__host = host
        Mqtt.__port = port
        Mqtt.enable()

    def set_topic(topic: str) -> None:
        if Mqtt.is_enabled() and topic:
            logger.debug(f"Setting mqtt topic: {topic}")
            Mqtt.__topic = topic
        elif Mqtt.is_enabled() and not topic:
            logger.warning("A mqtt topic is required. Disabling mqtt!")
            Mqtt.disable()

    def set_user(user, password) -> None:
        if Mqtt.is_enabled():
            logger.debug(f"Setting mqtt user {user} with password {password}.")
            Mqtt.__user = str(user)
            Mqtt.__password = str(password)

    def set_tls(ca_certs: str, certfile: str, keyfile: str) -> None:
        if Mqtt.is_enabled() and (ca_certs or (certfile and keyfile)):
            logger.debug(
                "Setting tls encryption with "
                f"ca_certs file {ca_certs}, "
                f"certfile {certfile} and keyfile {keyfile}."
            )
            Mqtt.__ca_certs = ca_certs
            Mqtt.__certfile = certfile
            Mqtt.__keyfile = keyfile

    def enable_debugging() -> None:
        logger.debug("Enabling mqtt client debugging.")
        Mqtt.__debug = True

    def __init__(self) -> None:
        """initiate the mqtt client, """
        if Mqtt.is_enabled():
            self._client = mqtt_client.Client()
            self._client.username_pw_set(Mqtt.__user, Mqtt.__password)
            if Mqtt.__ca_certs or (Mqtt.__certfile and Mqtt.__keyfile):
                self._client.tls_set(
                    ca_certs=Mqtt.__ca_certs,
                    certfile=Mqtt.__certfile,
                    keyfile=Mqtt.__keyfile
                )
            if Mqtt.__debug:
                self._client.enable_logger(logger.setLevel(logging.DEBUG))
        else:
            self._client = None

    def __enter__(self):
        if self._client is not None:
            logger.debug("Connecting to mqtt broker...")
            try:
                self._client.connect(Mqtt.__host, port=Mqtt.__port)
                logger.debug("Starting mqtt network loop...")
                self._client.loop_start()
            except ConnectionRefusedError:
                logger.error(
                    "Connection to mqtt broker refused. Disabling mqtt!"
                )
                Mqtt.disable()
            except mqtt_client.ssl.SSLError as err:
                logger.error(f"SSL error: {err}.")
                Mqtt.disable()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._client is not None:
            logger.debug("Stopping mqtt client.")
            self._client.loop_stop()

    def publish_probe(self, probe_request: ProbeRequest) -> None:
        if Mqtt.is_enabled() and self._client is not None:
            logger.debug("Publishing ProbeRequest to mqtt.")
            self._client.publish(Mqtt.__topic, str(probe_request))
