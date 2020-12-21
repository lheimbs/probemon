import json
import logging
import paho.mqtt.client as mqtt_client

logger = logging.getLogger('mqtt')

class Mqtt(object):
    """ Mqtt class to handle client connection and publishing """

    def __init__(self, enabled):
        self._client = mqtt_client.Client()
        self.__enabled = enabled

    def set_server(self, host, port):
        self.__host = host
        self.__port = port

    def set_user(self, user, password):
        self._client.username_pw_set(user, password)

    def set_tls(self, ca_certs, certfile, keyfile):
        self._client.tls_set(ca_certs=ca_certs, certfile=certfile, keyfile=keyfile)

    def enable_logger(self, log_level):
        logger.setLevel(log_level)
        self._client.enable_logger(logger)

    def connect(self):
        self._client.connect(self.__host, port=self.__port)

    def start(self):
        self._client.loop_start()

    def publish_probe(self, probe_request):
        self._client.publish(json.dumps(probe_request))
