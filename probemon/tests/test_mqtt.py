import logging
from unittest import TestCase, mock

from ..mqtt import Mqtt


class FakeClient():
    def __init__(self, *args, **kwargs):
        self.connected = False

    def connect(self, *args, **kwargs):
        self.connected = True

    def is_connected(self):
        return self.connected

    def username_pw_set(self, *args, **kwargs):
        pass

    def tls_set(self, *args, **kwargs):
        pass

    def enable_logger(self, *args, **kwargs):
        pass

    def loop_start(self, *args, **kwargs):
        pass

    def loop_stop(self, *args, **kwargs):
        self.connected = False


class MqttUnitTest(TestCase):
    def setUp(self) -> None:
        logging.disable(logging.ERROR)
        return super().setUp()

    def tearDown(self) -> None:
        logging.disable(logging.NOTSET)
        Mqtt._enabled = False
        Mqtt._host = None
        Mqtt._port = None
        Mqtt._user = None
        Mqtt._password = None
        Mqtt._topic = None
        Mqtt._ca_certs = Mqtt._certfile = Mqtt._keyfile = None
        Mqtt._debug = False
        return super().tearDown()

    def test_init_without_any_configuraiton(self):
        mqtt = Mqtt()
        self.assertIsInstance(mqtt, Mqtt)

    def test_is_enabled_without_configuration(self):
        self.assertFalse(Mqtt.is_enabled())

    def test_enable_disable(self):
        Mqtt.enable()
        self.assertTrue(Mqtt.is_enabled())
        Mqtt.disable()
        self.assertFalse(Mqtt.is_enabled())

    def test_set_server_with_empty_host(self):
        Mqtt.set_server('')
        self.assertFalse(Mqtt.is_enabled())
        self.assertIsNone(Mqtt._host, None)

    def test_set_server_with_valid_host_and_no_port(self):
        Mqtt.set_server('127.0.0.1')
        self.assertEqual(Mqtt._host, '127.0.0.1')
        self.assertEqual(Mqtt._port, 1883)
        self.assertTrue(Mqtt.is_enabled())

    def test_set_server_with_valid_host_and_valid_port(self):
        Mqtt.set_server('127.0.0.1', 8883)
        self.assertEqual(Mqtt._host, '127.0.0.1')
        self.assertEqual(Mqtt._port, 8883)
        self.assertTrue(Mqtt.is_enabled())

    def test_set_server_with_valid_host_and_invalid_port(self):
        Mqtt.set_server('127.0.0.1', 'asdasdasd')
        self.assertIsNone(Mqtt._host, None)
        self.assertIsNone(Mqtt._port, None)
        self.assertFalse(Mqtt.is_enabled())

    def test_set_user_with_mqtt_disabled(self):
        Mqtt.set_user('test', 'test')
        self.assertIsNone(Mqtt._user, None)
        self.assertIsNone(Mqtt._password, None)

    def test_set_user_with_mqtt_enabled(self):
        Mqtt.enable()
        Mqtt.set_user('test', 'test')
        self.assertEqual(Mqtt._user, 'test')
        self.assertEqual(Mqtt._password, 'test')

    def test_set_topic_with_mqtt_disabled(self):
        Mqtt.set_topic("asd")
        self.assertIsNone(Mqtt._topic, None)

    def test_set_topic_with_mqtt_enabled_and_valid_topic(self):
        Mqtt.enable()
        Mqtt.set_topic('asd')
        self.assertEqual(Mqtt._topic, 'asd')

    def test_set_topic_with_mqtt_enabled_and_invalid_topic(self):
        Mqtt.enable()
        Mqtt.set_topic('')
        self.assertIsNone(Mqtt._topic, None)
        self.assertFalse(Mqtt.is_enabled())

    def test_set_tls_with_mqtt_disabled(self):
        Mqtt.set_tls('testca', 'testcer', 'testkey')
        self.assertIsNone(Mqtt._ca_certs, None)
        self.assertIsNone(Mqtt._certfile, None)
        self.assertIsNone(Mqtt._keyfile, None)

    def test_set_tls_with_mqtt_enabled_and_valid_ca(self):
        Mqtt.enable()
        Mqtt.set_tls('testca', '', '')
        self.assertEqual(Mqtt._ca_certs, 'testca')
        self.assertIsNone(Mqtt._certfile, None)
        self.assertIsNone(Mqtt._keyfile, None)

    def test_set_tls_with_mqtt_enabled_and_valid_key_and_cert(self):
        Mqtt.enable()
        Mqtt.set_tls('', 'testcer', 'testkey')
        self.assertIsNone(Mqtt._ca_certs, None)
        self.assertEqual(Mqtt._certfile, 'testcer')
        self.assertEqual(Mqtt._keyfile, 'testkey')

    def test_enable_mqtt_debugging(self):
        Mqtt.enable_debugging()
        self.assertTrue(Mqtt._debug)

    def test_mqtt_with_statement_and_mqtt_disabled(self):
        with Mqtt() as mqtt:
            self.assertIsNone(mqtt._client)
        self.assertIsNone(mqtt._client)

    @mock.patch('paho.mqtt.client.Client', new=FakeClient, create=True)
    def test_mqtt_with_statement_and_mqtt_enabled(self):
        Mqtt.set_server('localhost')
        with Mqtt() as mqtt:
            self.assertIsNotNone(mqtt._client)
            self.assertTrue(mqtt._client.is_connected())
        self.assertFalse(mqtt._client.is_connected())

    @mock.patch('paho.mqtt.client.Client')
    def test_publish_probe(self, _):
        Mqtt.set_server('localhost')
        Mqtt.set_topic('test')
        mqtt = Mqtt()
        mqtt.publish_probe(None)
        mqtt._client.publish.assert_called_with('test', str(None))

    def test_publish_probe_with_mqtt_disabled(self):
        mqtt = Mqtt()
        mqtt.publish_probe(None)
        self.assertIsNone(mqtt._client)
