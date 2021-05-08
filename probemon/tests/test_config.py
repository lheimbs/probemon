import logging
from probemon.probe_request.probe_request import ProbeRequest
from probemon.mqtt.mqtt import Mqtt
from unittest import TestCase, mock

import netaddr

from .test_mqtt import reset_mqtt
from .test_probe_request import reset_probe

from ..config.cli import get_cli_params
from ..config.config_file import get_configfile_params
from ..config.dot_env import get_dotenv_params
from ..config.misc import convert_option_type, get_url, MissingChainMap, set_mac_dialect
from ..config import config
from ..mac import Mac
from probemon.config import misc

EMPTY_CONFIG = ''
APP_CONFIG = """
[APP]
key = value
"""
MQTT_CONFIG = """
[MQTT]
key = value
"""
SQL_CONFIG = """
[SQL]
key = value
"""
URL_CONFIG = """
[URLPUBLISH]
key = value
"""

def mock_exists_getter(falsies=None):
    falsies = falsies if falsies is not None else []

    def mock_exists(file):
        if file in falsies:
            return False
        return True
    return mock_exists


class ConvertOptionTypeUnitTest(TestCase):
    def test_convert_option_type_str(self):
        val = convert_option_type('testval')
        self.assertEqual(val, 'testval')

    def test_convert_option_type_numeric_str(self):
        val = convert_option_type('123')
        self.assertEqual(val, 123)

    def test_convert_option_type_falsy_value(self):
        val = convert_option_type('')
        self.assertEqual(val, None)

    def test_convert_option_false_str(self):
        val = convert_option_type('false')
        self.assertFalse(val)

    def test_convert_option_true_str(self):
        val = convert_option_type('true')
        self.assertTrue(val)


class GetUrlUnitTest(TestCase):
    def tearDown(self) -> None:
        logging.disable(logging.NOTSET)
        return super().tearDown()

    def test_sqlite_dialect_without_path(self):
        logging.disable(logging.WARNING)
        url = get_url('sqlite')
        self.assertEqual(url, "sqlite://")

    def test_sqlite_dialect_with_path(self):
        logging.disable(logging.WARNING)
        url = get_url('sqlite', sql_sqlite_path='test')
        self.assertEqual(url, "sqlite:///test")

    def test_dialect_bare(self):
        logging.disable(logging.WARNING)
        url = get_url('mysql')
        self.assertEqual(url, "mysql://@/")

    def test_dialect_with_port(self):
        logging.disable(logging.WARNING)
        url = get_url('mysql', sql_port=12345)
        self.assertEqual(url, "mysql://@:12345/")

    def test_dialect_with_driver(self):
        logging.disable(logging.WARNING)
        url = get_url('mysql', sql_driver='test')
        self.assertEqual(url, "mysql+test://@/")

    def test_dialect_with_password(self):
        logging.disable(logging.WARNING)
        url = get_url('mysql', sql_password='test')
        self.assertEqual(url, "mysql://:test@/")

    def test_dialect_with_kwarg(self):
        logging.disable(logging.WARNING)
        url = get_url('mysql', sql_kwargs="test")
        self.assertEqual(url, "mysql://@/?test")

    def test_dialect_with_unknown_kwarg(self):
        logging.disable(logging.WARNING)
        url = get_url('mysql', unknownkwarg="test")
        self.assertEqual(url, "mysql://@/")


class MissingChainMapUnitTest(TestCase):
    def test_missing(self):
        map = MissingChainMap()
        self.assertIsNone(map['test'])

    # def test_getitem_with_item_in_map_and_not_none(self):
    #     map = MissingChainMap({'placeholder': None}, {'test': 'test'})
    #     self.assertEqual(map['test'], 'test')

    # def test_getitem_with_item_in_map_but_none(self):
    #     map = MissingChainMap({'placeholder': None}, {'test': None})
    #     self.assertIsNone(map['test'])

    # def test_getall_with_item_not_in_map(self):
    #     map = MissingChainMap({'placeholder': None}, {'test1': 'test'})
    #     self.assertEqual(map.get_all('test'), [])

    # def test_getall_with_item_in_map_twice_and_not_ignore_none(self):
    #     map = MissingChainMap({'test': None}, {'test': 'test'})
    #     self.assertEqual(map.get_all('test'), [None, 'test'])

    # def test_getitem_with_item_in_map_ignore_none(self):
    #     map = MissingChainMap({'test': None}, {'test': 'test'})
    #     self.assertEqual(map.get_all('test', ignore_none=True), ['test'])


class SetMacDialectUnitTest(TestCase):
    def test_falsy_dialect(self):
        initial_dialect = Mac.dialect
        set_mac_dialect('')
        self.assertEqual(Mac.dialect, initial_dialect)

    def test_invalid_dialect(self):
        logging.disable(logging.WARNING)
        initial_dialect = Mac.dialect
        set_mac_dialect('doesnotexist')
        self.assertEqual(Mac.dialect, initial_dialect)
        logging.disable(logging.NOTSET)

    def test_valid_dialect(self):
        initial_dialect = Mac.dialect
        set_mac_dialect('bare')
        self.assertNotEqual(Mac.dialect, initial_dialect)
        self.assertEqual(Mac.dialect, netaddr.mac_bare)
        Mac.dialect = netaddr.mac_unix_expanded

class CliParamsUnitTest(TestCase):
    def test_with_empty_params(self):
        params = {}
        cfg = get_cli_params(params)
        self.assertDictEqual(cfg, {})

    def test_with_falsy_app_values(self):
        params = {'test': '1', 'test2': 0, 'test3': None}
        cfg = get_cli_params(params)
        self.assertDictEqual(cfg, {'test': '1'})

    def test_with_mqtt_params(self):
        params = {'mqtt_test': 'test'}
        cfg = get_cli_params(params)
        self.assertDictEqual(cfg, params)

    def test_with_sql_params(self):
        params = {'sql_test': 'test'}
        cfg = get_cli_params(params)
        self.assertDictEqual(cfg, params)


class ConfigFileUnitTest(TestCase):
    @mock.patch('probemon.config.config_file.configparser.ConfigParser.read', return_value=[])
    def test_configfile_with_empty_config(self, read):
        cfg = get_configfile_params()
        self.assertDictEqual(cfg, {})

    @mock.patch('builtins.open', mock.mock_open(read_data=APP_CONFIG))
    def test_configfile_app_empty_config(self):
        cfg = get_configfile_params()
        cfg.pop('parsed_files')
        self.assertTrue('key' in cfg)
        self.assertEqual(cfg['key'], 'value')

    @mock.patch('builtins.open', mock.mock_open(read_data=MQTT_CONFIG))
    def test_configfile_with_mqtt_config(self):
        cfg = get_configfile_params()
        cfg.pop('parsed_files')
        self.assertDictEqual(cfg, {'mqtt_key': 'value'})

    @mock.patch('builtins.open', mock.mock_open(read_data=SQL_CONFIG))
    def test_configfile_with_sql_config(self):
        cfg = get_configfile_params()
        cfg.pop('parsed_files')
        self.assertDictEqual(cfg, {'sql_key': 'value'})

    @mock.patch('builtins.open', mock.mock_open(read_data=URL_CONFIG))
    def test_configfile_with_url_config(self):
        cfg = get_configfile_params()
        cfg.pop('parsed_files')
        self.assertDictEqual(cfg, {'url_publish_key': 'value'})


@mock.patch('probemon.config.dot_env.load_dotenv')
class DotEnvUnitTest(TestCase):
    @mock.patch.dict('probemon.config.dot_env.os.environ', {}, clear=True)
    def test_no_params(self, _):
        cfg = get_dotenv_params()
        self.assertDictEqual(cfg, {})

    @mock.patch.dict('probemon.config.dot_env.os.environ', {'PROBEMON_TEST': 'value'}, clear=True)
    def test_app_param(self, _):
        cfg = get_dotenv_params()
        self.assertDictEqual(cfg, {'test': 'value'})

    @mock.patch.dict('probemon.config.dot_env.os.environ', {'PROBEMON_SQL_TEST': 'value'}, clear=True)
    def test_sql_param(self, _):
        cfg = get_dotenv_params()
        self.assertDictEqual(cfg, {'sql_test': 'value'})

    @mock.patch.dict('probemon.config.dot_env.os.environ', {'PROBEMON_MQTT_TEST': 'value'}, clear=True)
    def test_mqtt_param(self, _):
        cfg = get_dotenv_params()
        self.assertDictEqual(cfg, {'mqtt_test': 'value'})


class MqttFromParamsUnitTest(TestCase):
    def tearDown(self) -> None:
        logging.disable(logging.NOTSET)
        reset_mqtt()
        return super().tearDown()

    def test_empty_map(self):
        map = MissingChainMap()
        config.set_mqtt_from_params(map)
        self.assertFalse(Mqtt.is_enabled())

    def test_with_host_port_but_without_topic(self):
        logging.disable(logging.WARNING)
        map = MissingChainMap({'mqtt_host': 'localhost', 'mqtt_port': 123})
        config.set_mqtt_from_params(map)
        self.assertFalse(Mqtt.is_enabled())
        self.assertEqual(Mqtt._host, 'localhost')
        self.assertEqual(Mqtt._port, 123)

    def test_with_host_port_topic(self):
        map = MissingChainMap({'mqtt_host': 'localhost', 'mqtt_port': 123, 'mqtt_topic': 'test'})
        config.set_mqtt_from_params(map)
        self.assertTrue(Mqtt.is_enabled())
        self.assertEqual(Mqtt._topic, 'test')

    def test_with_user_password(self):
        map = MissingChainMap(
            {'mqtt_host': 'localhost', 'mqtt_port': 123, 'mqtt_topic': 'test'},
            {'mqtt_user': 'user', 'mqtt_password': 'password'}
        )
        config.set_mqtt_from_params(map)
        self.assertEqual(Mqtt._user, 'user')
        self.assertEqual(Mqtt._password, 'password')

    def test_with_debug(self):
        map = MissingChainMap(
            {'mqtt_host': 'localhost', 'mqtt_port': 123, 'mqtt_topic': 'test'},
            {'mqtt_debug': 'true'}
        )
        config.set_mqtt_from_params(map)
        self.assertEqual(Mqtt._debug, True)

    @mock.patch('os.path.exists', return_value=True)
    def test_with_tls_all_exist(self, ex):
        map = MissingChainMap(
            {'mqtt_host': 'localhost', 'mqtt_port': 123, 'mqtt_topic': 'test'},
            {'mqtt_ca_certs': 'ca_certs', 'mqtt_certfile': 'certfile', 'mqtt_keyfile': 'keyfile'}
        )
        config.set_mqtt_from_params(map)
        self.assertEqual(Mqtt._ca_certs, 'ca_certs')
        self.assertEqual(Mqtt._certfile, 'certfile')
        self.assertEqual(Mqtt._keyfile, 'keyfile')

    @mock.patch('os.path.exists', side_effect=mock_exists_getter(['ca_certs']))
    def test_with_tls_ca_certs_does_not_exist(self, ex):
        logging.disable(logging.ERROR)
        map = MissingChainMap(
            {'mqtt_host': 'localhost', 'mqtt_port': 123, 'mqtt_topic': 'test'},
            {'mqtt_ca_certs': 'ca_certs', 'mqtt_certfile': 'certfile', 'mqtt_keyfile': 'keyfile'}
        )
        config.set_mqtt_from_params(map)
        self.assertIsNone(Mqtt._ca_certs)
        self.assertEqual(Mqtt._certfile, 'certfile')
        self.assertEqual(Mqtt._keyfile, 'keyfile')

    @mock.patch('os.path.exists', side_effect=mock_exists_getter(['ca_certs', 'certfile']))
    def test_with_tls_ca_certs_and_certfile_does_not_exist(self, ex):
        logging.disable(logging.ERROR)
        map = MissingChainMap(
            {'mqtt_host': 'localhost', 'mqtt_port': 123, 'mqtt_topic': 'test'},
            {'mqtt_ca_certs': 'ca_certs', 'mqtt_certfile': 'certfile', 'mqtt_keyfile': 'keyfile'}
        )
        config.set_mqtt_from_params(map)
        self.assertIsNone(Mqtt._ca_certs)
        self.assertIsNone(Mqtt._certfile)
        self.assertIsNone(Mqtt._keyfile)

    @mock.patch('os.path.exists', side_effect=mock_exists_getter(['certfile']))
    def test_with_tls_certfile_does_not_exist(self, ex):
        logging.disable(logging.ERROR)
        map = MissingChainMap(
            {'mqtt_host': 'localhost', 'mqtt_port': 123, 'mqtt_topic': 'test'},
            {'mqtt_ca_certs': 'ca_certs', 'mqtt_certfile': 'certfile', 'mqtt_keyfile': 'keyfile'}
        )
        config.set_mqtt_from_params(map)
        self.assertEqual(Mqtt._ca_certs, 'ca_certs')
        self.assertIsNone(Mqtt._certfile)
        self.assertIsNone(Mqtt._keyfile)

    @mock.patch('os.path.exists', side_effect=mock_exists_getter(['keyfile']))
    def test_with_tls_keyfile_does_not_exist(self, ex):
        logging.disable(logging.ERROR)
        map = MissingChainMap(
            {'mqtt_host': 'localhost', 'mqtt_port': 123, 'mqtt_topic': 'test'},
            {'mqtt_ca_certs': 'ca_certs', 'mqtt_certfile': 'certfile', 'mqtt_keyfile': 'keyfile'}
        )
        config.set_mqtt_from_params(map)
        self.assertEqual(Mqtt._ca_certs, 'ca_certs')
        self.assertIsNone(Mqtt._certfile)
        self.assertIsNone(Mqtt._keyfile)

    @mock.patch('os.path.exists', side_effect=mock_exists_getter(['certfile', 'keyfile']))
    def test_with_tls_certfile_and_keyfile_does_not_exist(self, ex):
        logging.disable(logging.ERROR)
        map = MissingChainMap(
            {'mqtt_host': 'localhost', 'mqtt_port': 123, 'mqtt_topic': 'test'},
            {'mqtt_ca_certs': 'ca_certs', 'mqtt_certfile': 'certfile', 'mqtt_keyfile': 'keyfile'}
        )
        config.set_mqtt_from_params(map)
        self.assertEqual(Mqtt._ca_certs, 'ca_certs')
        self.assertIsNone(Mqtt._certfile)
        self.assertIsNone(Mqtt._keyfile)

    def test_logging_info_when_enabled(self):
        map = MissingChainMap(
            {'mqtt_host': 'localhost', 'mqtt_port': 123, 'mqtt_topic': 'test'},
            {'mqtt_user': 'user', 'mqtt_password': 'password'}
        )
        with self.assertLogs(config.logger, 'INFO') as logger:
            config.set_mqtt_from_params(map)
        self.assertIn(f'INFO:{config.logger.name}:    mqtt_user : user', logger.output)
        self.assertIn(f'INFO:{config.logger.name}:    mqtt_host : localhost', logger.output)
        self.assertIn(f'INFO:{config.logger.name}:    mqtt_port : 123', logger.output)
        self.assertIn(f'INFO:{config.logger.name}:    mqtt_topic: test', logger.output)
        for output in logger.output:
            self.assertNotIn('password', output)


class SetSqlFromParamsUnitTest(TestCase):
    def tearDown(self) -> None:
        logging.disable(logging.NOTSET)
        return super().tearDown()

    def test_no_dialect(self):
        map = MissingChainMap({'sql_host': 'localhost'})
        with self.assertLogs(config.logger, 'WARNING') as logger:
            sql = config.set_sql_from_params(map)
        self.assertIn(
            f'WARNING:{config.logger.name}:Warning: with sql dialect unset, all other sql options will be ignored!',
            logger.output
        )
        self.assertIsNone(sql._engine)

    def test_no_host(self):
        map = MissingChainMap({'sql_dialect': 'localhost'})
        with self.assertLogs(config.logger, 'DEBUG') as logger:
            sql = config.set_sql_from_params(map)
        self.assertIn(
            f'DEBUG:{config.logger.name}:No sql host with dialect other than sqlite supplied. Disabling sql.',
            logger.output
        )
        self.assertIsNone(sql._engine)

    def test_no_host_and_other_optns(self):
        map = MissingChainMap({'sql_dialect': 'localhost', 'sql_user': 'test'})
        with self.assertLogs(config.logger, 'WARNING') as logger:
            sql = config.set_sql_from_params(map)
        self.assertIn((
            f'WARNING:{config.logger.name}:Warning: '
            'with sql dialect not sqlite and sql host unset, '
            'all sql options will be ignored and no data will get published to a sql database.'
        ), logger.output)
        self.assertIsNone(sql._engine)

    def test_sqlite_in_memory(self):
        logging.disable(logging.WARNING)
        map = MissingChainMap({'sql_dialect': 'sqlite', })
        sql = config.set_sql_from_params(map)
        self.assertIsNotNone(sql._engine)


@mock.patch('probemon.config.config.get_cli_params')
@mock.patch('probemon.config.config.get_dotenv_params')
@mock.patch('probemon.config.config.get_configfile_params')
class GetConfigUnitTest(TestCase):
    def test_sql_enabled(self, cli_params, dotenv, configfile):
        dotenv.return_value = configfile.return_value = {}
        cli_params.return_value = {'sql_dialect': 'sqlite', 'sql_password': 'password'}
        with self.assertLogs(config.logger, 'INFO') as logger, self.assertLogs(misc.logger, 'WARNING'):
            config.get_config('')
        self.assertIn(f'INFO:{config.logger.name}:    sql_dialect: sqlite', logger.output)
        for output in logger.output:
            self.assertNotIn('password', output)

    def test_parsed_files(self, cli_params, dotenv, configfile):
        dotenv.return_value = configfile.return_value = {}
        cli_params.return_value = {'parsed_files': ['test']}
        with self.assertLogs(config.logger, 'DEBUG') as logger:
            config.get_config('')
        self.assertIn('DEBUG:probemon.config.config:Parsed config files: test', logger.output)

    def test_maclookup_api_key(self, cli_params, dotenv, configfile):
        dotenv.return_value = configfile.return_value = {}
        cli_params.return_value = {'maclookup_api_key': 'test'}
        config.get_config('')
        self.assertEqual(ProbeRequest.maclookup_api_key, 'test')


class SetProbeRequestFromParamsUnitTest(TestCase):
    def setUp(self) -> None:
        reset_probe()
        return super().setUp()

    def test_raw(self):
        config.set_probe_request_from_params(MissingChainMap({'raw': True}))
        self.assertTrue(ProbeRequest.raw)

    def test_lower(self):
        config.set_probe_request_from_params(MissingChainMap({'lower': True}))
        self.assertTrue(ProbeRequest.lower)

    def test_get_vendor(self):
        config.set_probe_request_from_params(MissingChainMap({'vendor': True}))
        self.assertTrue(ProbeRequest.get_vendor)

    def test_vendor_offline(self):
        config.set_probe_request_from_params(MissingChainMap({'vendor_offline': True}))
        self.assertTrue(ProbeRequest.vendor_offline)
