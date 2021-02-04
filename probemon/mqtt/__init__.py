import json
import logging
import paho.mqtt.client as mqtt_client

logger = logging.getLogger('mqtt')

class Mqtt(object):
    """ Mqtt class to handle client connection and publishing """

    def __init__(self, enabled=False):
        """initiate the mqtt client, """
        self._client = mqtt_client.Client()
        self.__enabled = enabled

    def is_enabled(self):
        return self.__enabled

    def enable(self):
        self.__enabled = True

    def set_server(self, host, port=1883):
        if not host:
            logger.error(
                "Can't configure Mqtt-Client because no host is supplied. "
                "Disabling mqtt!"
            )
            self.__enabled = False
            return

        if not port:
            logger.info("No port supplied. Using default port 1883.")

        logger.debug(f"Setting mqtt host {host} with port {port}.")
        self.__host = host
        self.__port = port

    def set_user(self, user, password):
        logger.debug(f"Setting mqtt user {user} with password {password}.")
        self._client.username_pw_set(user, password)

    def set_tls(self, ca_certs, certfile, keyfile):
        if ca_certs or (certfile and keyfile):
            logger.debug(
                "Setting tls encryption with "
                f"ca_certs file {ca_certs}, "
                f"certfile {certfile} and keyfile {keyfile}."
            )
            self._client.tls_set(ca_certs=ca_certs, certfile=certfile, keyfile=keyfile)

    def enable_logger(self, log_level):
        logger.debug(f"Enabling mqtt logger with loglevel {log_level}.")
        self._client.enable_logger(logger.setLevel(log_level))

    def connect(self):
        logger.debug("Connecting to mqtt broker.")
        self._client.connect(self.__host, port=self.__port)

    def start(self):
        logger.debug("Starting mqtt network loop.")
        self._client.loop_start()

    def publish_probe(self, probe_request):
        logger.debug("Publishing ProbeRequest to mqtt.")
        self._client.publish(json.dumps(probe_request))
