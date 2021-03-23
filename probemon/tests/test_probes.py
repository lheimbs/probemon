import logging
from unittest import TestCase, mock

from click.testing import CliRunner

from ..probes import probes
from ..config.misc import IgnoreNoneChainMap

BASIC_CONFIG = """"""
DEBUG_CONFIG = """[APP]\nDEBUG=True"""
VERBOSE_CONFIG = """[APP]\nVERBOSE=True"""

@mock.patch('probemon.config.dot_env.load_dotenv')
@mock.patch('probemon.probes.probes.can_use_interface')
@mock.patch('probemon.probes.probes.set_wifi_channel_from_args')
@mock.patch('probemon.probes.probes.collect_probes')
class ProbesMainTest(TestCase):
    def setUp(self) -> None:
        logging.disable(logging.CRITICAL)
        return super().setUp()

    def tearDown(self) -> None:
        logging.disable(logging.NOTSET)
        return super().tearDown()

    @mock.patch('builtins.open', mock.mock_open(read_data=BASIC_CONFIG))
    def test_without_args(self, *args):
        runner = CliRunner()
        result = runner.invoke(probes.main)
        self.assertEqual(result.exit_code, 0)

    @mock.patch('builtins.open', mock.mock_open(read_data=BASIC_CONFIG))
    def test_with_debug_cli(self, collect_probes, *args):
        runner = CliRunner()
        runner.invoke(probes.main, ['--debug'])
        self.assertTrue(collect_probes.call_args[0][1]['debug'])

    @mock.patch('builtins.open', mock.mock_open(read_data=BASIC_CONFIG))
    def test_with_verbose_cli(self, collect_probes, *args):
        runner = CliRunner()
        runner.invoke(probes.main, ['--verbose'])
        self.assertTrue(collect_probes.call_args[0][1]['verbose'])

    @mock.patch('builtins.open', mock.mock_open(read_data=BASIC_CONFIG))
    def test_with_debug_dotenv(self, collect_probes, *args):
        runner = CliRunner(env={'PROBEMON_DEBUG': 'True'})
        runner.invoke(probes.main)
        self.assertTrue(collect_probes.call_args[0][1]['debug'])

    @mock.patch('builtins.open', mock.mock_open(read_data=BASIC_CONFIG))
    def test_with_verbose_dotenv(self, collect_probes, *args):
        runner = CliRunner(env={'PROBEMON_VERBOSE': 'True'})
        runner.invoke(probes.main)
        self.assertTrue(collect_probes.call_args[0][1]['verbose'])

    @mock.patch('builtins.open', mock.mock_open(read_data=DEBUG_CONFIG))
    def test_with_debug_ini(self, collect_probes, *args):
        runner = CliRunner()
        runner.invoke(probes.main)
        self.assertTrue(collect_probes.call_args[0][1]['debug'])

    @mock.patch('builtins.open', mock.mock_open(read_data=VERBOSE_CONFIG))
    def test_with_verbose_ini(self, collect_probes, *args):
        runner = CliRunner()
        runner.invoke(probes.main)
        self.assertTrue(collect_probes.call_args[0][1]['verbose'])


@mock.patch('threading.Thread.start')
@mock.patch('probemon.probes.probes.sniff')
@mock.patch.object(probes.probes_queue, 'join')
class CollectProbesTest(TestCase):
    def setUp(self) -> None:
        self.args = IgnoreNoneChainMap({
            'worker_threads': 3,
        })
        return super().setUp()

    def test_worker_with_no_threads(self, _, __, start):
        self.args['worker_threads'] = 0
        probes.collect_probes('test', self.args)
        start.assert_not_called()

    def test_worker_threads_initing(self, _, __, start):
        probes.collect_probes('test', self.args)
        self.assertEqual(start.call_count, 3)

    @mock.patch.object(probes.probes_queue, 'qsize', return_value=0)
    @mock.patch.object(probes.probes_queue, 'join', return_value=0)
    @mock.patch('probemon.probes.probes.threading.active_count', return_value=1)
    @mock.patch('probemon.probes.probes.time.perf_counter', return_value=0)
    def test_no_remaining_probes(self, *args):
        with self.assertLogs(probes.logger, 'DEBUG') as logger:
            probes.collect_probes('test', self.args)
        self.assertIn((
            f'DEBUG:{probes.logger.name}:Sniffed for 0.00 seconds. '
            'Probes in queue: 0, active worker threads: 0.'
        ), logger.output)

    @mock.patch('probemon.probes.probes.threading.active_count', return_value=1)
    @mock.patch('probemon.probes.probes.time.perf_counter', return_value=0)
    @mock.patch(
        'probemon.probes.probes.ProbeRequest.from_packet',
        return_value='example probe request'
    )
    @mock.patch.object(probes.probes_queue, 'qsize', return_value=1)
    @mock.patch.object(probes.probes_queue, 'get')
    @mock.patch.object(probes.probes_queue, 'task_done')
    @mock.patch.object(probes.probes_queue, 'empty', side_effect=(False, True))
    def test_remaining_probes_without_workers(self, queue, *args):
        with self.assertLogs(probes.logger, 'INFO') as logger:
            probes.collect_probes('test', self.args)
        self.assertIn(f'INFO:{probes.logger.name}:example probe request', logger.output)

    @mock.patch('probemon.probes.probes.threading.active_count', return_value=5)
    @mock.patch('probemon.probes.probes.queue.Queue.qsize', return_value=1)
    def test_remaining_probes(self, queue, *args):
        with self.assertLogs(probes.logger, 'INFO') as logger:
            probes.collect_probes('test', self.args)
        self.assertIn((
            f'INFO:{probes.logger.name}:'
            "Please wait while aprox. 1 remaining probes are getting processed..."
        ), logger.output)


class AddProbeToQueueTest(TestCase):
    def test_call_add_probe(self):
        probes.add_probe_to_queue(None)
        self.assertIsNone(probes.probes_queue.get())


@mock.patch.object(probes.probes_queue, 'join')
@mock.patch('probemon.probes.probes.ProbeRequest.from_packet', return_value=None)
@mock.patch('probemon.probes.probes.Sql.publish_probe', side_effect=TypeError)
@mock.patch('probemon.probes.probes.time.perf_counter', side_effect=[0, 0, TypeError])
class PacketWorkerTest(TestCase):
    def test_call_packet_worker(self, *args):
        logging.disable(logging.CRITICAL)
        mock_packet = mock.Mock()
        probes.probes_queue.put(mock_packet)
        probes.probes_queue.put(mock_packet)
        self.assertEqual(probes.probes_queue.qsize(), 2)
        with self.assertRaises(TypeError):
            probes.packet_worker()
        self.assertEqual(probes.probes_queue.qsize(), 1)
