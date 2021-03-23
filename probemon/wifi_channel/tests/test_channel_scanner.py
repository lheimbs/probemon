import os
import time
import logging
from unittest import TestCase, skipUnless, mock

from scapy.all import AsyncSniffer, get_if_list, RadioTap, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11

from ..channel_scanner import ChannelScanner, logger, FREQUENCIES, CHANNELS
from ..misc import AccessPoint

EXAMPLE_CHANNELS = """    * 2412 MHz [1] (20.0 dBm)
    * 2417 MHz [2] (20.0 dBm)
    * 5500 MHz [100] (disabled)"""
AP_PATH = 'probemon.wifi_channel.misc.AccessPoint'
OBJ_PATH = 'probemon.wifi_channel.channel_scanner.ChannelScanner.'
BEACON = RadioTap(
    version=0, pad=0, len=0, present="TSFT+Flags+Rate+Channel+dBm_AntSignal+RXFlags+RadiotapNS+Ext"
)\
    / Dot11Beacon(timestamp=1147868262790, cap="short-slot+ESS")\
    / Dot11(addr3='11:22:33:44:55:66')\
    / Dot11Elt(ID='SSID', len=13, info='some_ssid')\
    / Dot11Elt(ID='Rates', info='\x82\x84\x8b\x96\x0c\x12\x18')\
    / Dot11Elt(ID='DSset', info=chr(1))
PROBE = RadioTap(
    version=0, pad=0, len=0, present="TSFT+Flags+Rate+Channel+dBm_AntSignal+RXFlags+RadiotapNS+Ext"
)\
    / Dot11ProbeResp(timestamp=1147868262790, cap="short-slot+ESS+privacy")\
    / Dot11(addr3='aa:bb:cc:dd:ee:ff')\
    / Dot11Elt(ID='SSID', len=13, info='some_ssid')\
    / Dot11Elt(ID='Rates', info='\x82\x84\x8b\x96\x0c\x12\x18')\
    / Dot11Elt(ID='DSset', info=chr(1))
PACKET = RadioTap(
    version=0, pad=0, len=0, present="TSFT+Flags+Rate+Channel+dBm_AntSignal+RXFlags+RadiotapNS+Ext"
)
PACKET_2 = RadioTap(
    version=0, pad=0, len=0, present="TSFT+Flags+Rate+Channel+dBm_AntSignal+RXFlags+RadiotapNS+Ext"
)\
    / Dot11ProbeResp(timestamp=1147868262790, cap="short-slot+ESS+privacy")\
    / Dot11(addr3='aa:bb:cc:dd:ee:ff')\
    / Dot11Elt(ID='SSID', len=13, info='some_ssid')\
    / Dot11Elt(ID='DSset', info=chr(1))\
    / Dot11Elt(ID='Rates', info='\x82\x84\x8b\x96\x0c\x12\x18')


@skipUnless(os.getuid() == 0, "Scapy needs root to sniff packets.")
@skipUnless('mon0' in get_if_list(), "Testing interface 'mon0' has to exist for this to proceed.")
@mock.patch('probemon.wifi_channel.channel_scanner.misc.can_use_interface')
@mock.patch('probemon.wifi_channel.channel_scanner.misc.can_use_iw')
@mock.patch('threading.Thread', spec=True)
class ChannelScannerUnitTest(TestCase):
    def setUp(self) -> None:
        self.c = ChannelScanner('mon0')
        return super().setUp()

    def tearDown(self) -> None:
        mock.patch.stopall()
        logging.disable(logging.NOTSET)
        if self.c._sniffer.running:
            try:
                self.c._sniffer.stop()
            except:     # noqa
                pass
        return super().tearDown()

    def test_init_initializes_sniffer(self, *args):
        self.assertIsInstance(self.c, ChannelScanner)
        self.assertEqual(self.c._interface, 'mon0')
        self.assertIsInstance(self.c._sniffer, AsyncSniffer)

    @mock.patch(OBJ_PATH+'_sniff_packet', return_value=lambda x: None)
    def test_sniffer_start_stop(self, *args):
        c = ChannelScanner('mon0')
        self.assertFalse(c._sniffer.running)
        started = c._start_sniffer()
        self.assertTrue(started)
        # Need to sleep here because AsyncSnifferthread needs some time to set the sniffing sockets up.
        time.sleep(0.1)
        running = c._stop_sniffer()
        self.assertFalse(running)
        self.assertFalse(c._sniffer.running)

    @mock.patch(OBJ_PATH+'_sniff_packet', return_value=lambda x: None)
    def test_sniffer_start_stop_stops_program(self, *args):
        c = ChannelScanner('mon0')
        # with mock.patch.object(c._sniffer, 'thread') as thread:
        self.assertFalse(c._sniffer.running)
        started = c._start_sniffer()
        self.assertTrue(started)
        # Not sleeping now to provocate exception!
        with mock.patch('probemon.wifi_channel.channel_scanner.sys.exit') as exit, \
                self.assertLogs(logger, 'CRITICAL'):
            running = c._stop_sniffer()
        exit.assert_called_once()

        # sleep now and properly stop thread!
        time.sleep(0.1)
        running = c._stop_sniffer()
        self.assertFalse(running)
        self.assertFalse(c._sniffer.running)

    def test_sniffer_start_but_is_running(self, *args):
        c = ChannelScanner('mon0')
        self.assertFalse(c._sniffer.running)
        c._sniffer.running = True
        self.assertTrue(c._start_sniffer())

    def test_sniffer_stop_but_is_already_stopped(self, *args):
        c = ChannelScanner('mon0')
        self.assertFalse(c._sniffer.running)
        self.assertFalse(c._stop_sniffer())

    def test_getting_channels(self, *args):
        with mock.patch('probemon.wifi_channel.channel_scanner.subprocess.run') as run:
            stdout = mock.Mock(name="stdout")
            stdout.splitlines.return_value = EXAMPLE_CHANNELS.split('\n')
            m = mock.Mock(name="proc")
            type(m).stdout = stdout
            run.return_value = m
            self.assertListEqual(self.c._get_channels(), [1, 2])

    def test_getting_channels_with_channels_already_gotten_before(self, *args):
        self.c._available_channels = [1]
        self.assertListEqual(self.c._get_channels(), [1])

    @mock.patch(OBJ_PATH+'_get_channels', return_value=[1, 100])
    def test_get_channels_by_frequency_all(self, *args):
        self.assertListEqual(self.c._get_channels_by_frequency(FREQUENCIES._ALL), [1, 100])

    @mock.patch(OBJ_PATH+'_get_channels', return_value=[1, 100])
    def test_get_channels_by_frequency_2ghz(self, *args):
        self.assertListEqual(self.c._get_channels_by_frequency(FREQUENCIES._2GHz), [1])

    @mock.patch(OBJ_PATH+'_get_channels', return_value=[1, 100])
    def test_get_channels_by_frequency_5gz(self, *args):
        self.assertListEqual(self.c._get_channels_by_frequency(FREQUENCIES._5GHz), [100])

    def test_get_channels_by_frequency_all_self_supplied(self, *args):
        self.assertListEqual(
            self.c._get_channels_by_frequency(FREQUENCIES._ALL, [1, 100]),
            [1, 100]
        )

    def test_set_channel_with_invalid_channel(self, *_):
        logging.disable(logging.ERROR)
        with mock.patch.object(self.c, '_get_channels', return_value=[]):
            self.assertListEqual(self.c._available_channels, [])
            self.assertFalse(self.c.set_channel(1))

    def test_set_channel_with_valid_channel_and_succeed(self, *_):
        logging.disable(logging.CRITICAL)
        with mock.patch.object(self.c, '_get_channels', return_value=set([1])), \
                mock.patch('probemon.wifi_channel.channel_scanner.subprocess.run') as run:
            proc = mock.Mock()
            type(proc).returncode = mock.PropertyMock(return_value=0)
            run.return_value = proc
            self.assertTrue(self.c.set_channel(1))

    def test_set_channel_with_valid_channel_and_fail(self, *_):
        with mock.patch.object(self.c, '_get_channels', return_value=set([1])), \
                mock.patch('probemon.wifi_channel.channel_scanner.subprocess.run') as run:
            stdout = mock.Mock(name="stdout")
            stdout.splitlines.return_value = ['test', '123']
            proc = mock.Mock()
            type(proc).returncode = mock.PropertyMock(return_value=1)
            type(proc).stdout = stdout
            run.return_value = proc
            with self.assertLogs(logger, 'ERROR') as log:
                self.assertFalse(self.c.set_channel(1))
            self.assertListEqual(log.output, [
                f"ERROR:{logger.name}:Failed setting channel 1 on interface 'mon0': 'test 123'"
            ])

    def test_get_channels_with_count_with_empty_aps(self, *_):
        self.c._access_points = []
        self.assertDictEqual(self.c._get_channels_with_count(), {})

    def test_get_channels_with_count(self, *_):
        self.c._access_points = [
            mock.patch(AP_PATH, channel=1, count=1).start(),
            mock.patch(AP_PATH, channel=2, count=11).start(),
        ]
        self.assertDictEqual(self.c._get_channels_with_count(), {1: 1, 2: 11})

    def test_get_channels_with_count_with_dup(self, *_):
        self.c._access_points = [
            mock.patch(AP_PATH, channel=1, count=1).start(),
            mock.patch(AP_PATH, channel=1, count=1).start(),
            mock.patch(AP_PATH, channel=2, count=11).start(),
        ]
        self.assertDictEqual(self.c._get_channels_with_count(), {1: 2, 2: 11})

    @mock.patch(OBJ_PATH+'_get_channels', return_value=[1, 2, 3])
    def test_get_channels_with_count_with_zeros(self, *_):
        self.c._access_points = [
            mock.patch(AP_PATH, channel=1, count=2).start(),
            mock.patch(AP_PATH, channel=2, count=11).start(),
        ]
        self.assertDictEqual(self.c._get_channels_with_count(skip_zero=False), {1: 2, 2: 11, 3: 0})

    @mock.patch(OBJ_PATH+'_get_channels', return_value=[1, 2, 3])
    def test_get_channels_with_count_with_negative_cahnnel(self, *_):
        self.c._access_points = [
            mock.patch(AP_PATH, channel=0, count=2).start(),
            mock.patch(AP_PATH, channel=2, count=11).start(),
        ]
        self.assertDictEqual(self.c._get_channels_with_count(), {2: 11})

    def test_get_max_used_channel_with_ssid_not_found(self, *_):
        self.c._access_points = [
            mock.patch(AP_PATH, ssid='ssid', channel=1, count=3, spec=True).start(),
        ]
        self.assertTupleEqual(self.c._get_max_used_channel('test'), (0, 0))

    def test_get_max_used_channel_with_ssid_found(self, *_):
        self.c._access_points = [
            mock.patch(AP_PATH, ssid='test', channel=1, count=3, spec=True).start(),
            mock.patch(AP_PATH, ssid='test', channel=3, count=2, spec=True).start(),
            mock.patch(AP_PATH, ssid='test', channel=2, count=1, spec=True).start(),
        ]
        self.assertTupleEqual(self.c._get_max_used_channel('test'), (1, 3))

    def test_get_max_used_channel_with_empty_ssid_for_all_aps(self, *_):
        self.c._access_points = [
            mock.patch(AP_PATH, ssid='test', channel=1, count=3, spec=True).start(),
            mock.patch(AP_PATH, ssid='ssid', channel=1, count=2, spec=True).start(),
            mock.patch(AP_PATH, ssid='test', channel=3, count=2, spec=True).start(),
            mock.patch(AP_PATH, ssid='1234', channel=2, count=1, spec=True).start(),
        ]
        self.assertTupleEqual(self.c._get_max_used_channel(''), (1, 3))

    def test_print_with_console(self, *_):
        self.c._console = True
        with mock.patch('builtins.print') as print_:
            self.c._print("test")
        print_.assert_called_once_with('test', end='\n')

    def test_print_with_console_and_keep(self, *_):
        self.c._console = True
        with mock.patch('builtins.print') as print_:
            self.c._print("test", keep=True)
        print_.assert_called_once_with('test', end='\r')

    def test_print_without_console(self, *_):
        self.c._console = False
        with mock.patch('builtins.print') as print_:
            self.c._print("test", keep=True)
        print_.assert_not_called()

    @mock.patch(OBJ_PATH+'_get_max_used_channel', return_value=(2, 3))
    @mock.patch(OBJ_PATH+'_get_channels_with_count', return_value={1: 2, 2: 3, 3: 1})
    def test_print_channel_utilization(self, *_):
        c = ChannelScanner('mon0')
        with self.assertLogs(logger, 'INFO') as log:
            self.assertEqual(c.print_channel_utilization(), 2)
        self.assertListEqual(
            [(
                f'INFO:{logger.name}:'
                'Found channel 1: 2x, channel 2: 3x, channel 3: 1x. '
                'Channel 2 is the most populated (3 APs).'
            )],
            log.output
        )

    @mock.patch(OBJ_PATH+'_get_max_used_channel', return_value=(0, 0))
    @mock.patch(OBJ_PATH+'_get_channels_with_count', return_value={})
    def test_print_channel_utilization_with_no_aps(self, *_):
        c = ChannelScanner('mon0')
        with self.assertLogs(logger, 'INFO') as log:
            self.assertEqual(c.print_channel_utilization(), 0)
        self.assertListEqual(
            [(
                f'INFO:{logger.name}:'
                'Found zero APs and therefore no channel info.'
            )],
            log.output
        )

    @mock.patch(OBJ_PATH+'_get_channels_with_count', return_value={})
    def test_print_channel_graph_vertical_with_console_and_nothing_collected(self, *_):
        self.c._console = True
        with mock.patch.object(self.c, '_print') as print_:
            self.c.print_channel_graph_vertical()
        print_.assert_not_called()

    @mock.patch(OBJ_PATH+'_get_channels_with_count', return_value={1: 2, 3: 4})
    def test_print_channel_graph_vertical_with_console_and_aps(self, *_):
        self.c._console = True
        with mock.patch.object(self.c, '_print') as print_:
            self.c.print_channel_graph_vertical()
        print_.assert_has_calls([
            mock.call('Channel # 1: ██ 2x', level=20), mock.call('Channel # 3: ████ 4x', level=20)
        ])

    @mock.patch(OBJ_PATH+'_get_channels_with_count', return_value={})
    def test_print_channel_graph_vertical_with_logging_and_nothing_collected(self, *_):
        self.c._console = False
        with mock.patch.object(logger, 'info') as print_:
            self.c.print_channel_graph_vertical()
        print_.assert_not_called()

    @mock.patch(OBJ_PATH+'_get_channels_with_count', return_value={1: 2, 3: 4})
    def test_print_channel_graph_vertical_with_logging_and_aps(self, *_):
        logging.disable(logging.NOTSET)
        self.c._console = False
        with mock.patch.object(logger, 'log') as print_:
            self.c.print_channel_graph_vertical()
        print_.assert_has_calls([
            mock.call(20, 'Channel # 1: ██ 2x'), mock.call(20, 'Channel # 3: ████ 4x')
        ])

    @mock.patch(OBJ_PATH+'_get_channels_with_count', return_value={})
    def test_print_channel_graph_horizontal_with_console_and_nothing_collected(self, *_):
        self.c._console = True
        with mock.patch.object(self.c, '_print') as print_:
            self.c.print_channel_graph_horizontal()
        print_.assert_not_called()

    @mock.patch(OBJ_PATH+'_get_channels_with_count', return_value={1: 2, 3: 4})
    def test_print_channel_graph_horizontal_with_console_and_aps(self, *_):
        self.c._console = True
        with mock.patch.object(self.c, '_print') as print_:
            self.c.print_channel_graph_horizontal()
        print_.assert_has_calls([
            mock.call('                ', level=20),
            mock.call('   4:      ██   ', level=20),
            mock.call('   3:      ██   ', level=20),
            mock.call('   2:  ██  ██   ', level=20),
            mock.call('   1:  ██  ██   ', level=20),
            mock.call('        1   3   ', level=20)
        ])

    @mock.patch(OBJ_PATH+'_get_channels_with_count', return_value={})
    def test_print_channel_graph_horizontal_with_logging_and_nothing_collected(self, *_):
        self.c._console = False
        with mock.patch.object(logger, 'info') as print_:
            self.c.print_channel_graph_horizontal()
        print_.assert_not_called()

    @mock.patch(OBJ_PATH+'_get_channels_with_count', return_value={1: 2, 3: 4})
    def test_print_channel_graph_horizontal_with_logging_and_aps(self, *_):
        logging.disable(logging.NOTSET)
        self.c._console = False
        with mock.patch.object(logger, 'log') as print_:
            self.c.print_channel_graph_horizontal()
        print_.assert_has_calls([
            mock.call(20, '                '),
            mock.call(20, '   4:      ██   '),
            mock.call(20, '   3:      ██   '),
            mock.call(20, '   2:  ██  ██   '),
            mock.call(20, '   1:  ██  ██   '),
            mock.call(20, '        1   3   ')
        ])


@skipUnless(os.getuid() == 0, "Scapy needs root to sniff packets.")
@skipUnless('mon0' in get_if_list(), "Testing interface 'mon0' has to exist for this to proceed.")
@mock.patch('probemon.wifi_channel.channel_scanner.misc.can_use_interface')
@mock.patch('probemon.wifi_channel.channel_scanner.misc.can_use_iw')
class ChannelScannerRunnersUnitTest(TestCase):
    def setUp(self) -> None:
        self.c = ChannelScanner('mon0')
        return super().setUp()

    def tearDown(self) -> None:
        logging.disable(logging.NOTSET)
        if self.c._sniffer.running:
            try:
                self.c._sniffer.stop()
            except:     # noqa
                pass
        return super().tearDown()

    @mock.patch(OBJ_PATH+'_start_sniffer', return_value=False)
    def test_channel_scanner_with_failed_start_sniffing(self, *_):
        self.assertEqual(self.c.channel_scanner(), 0)

    @mock.patch(OBJ_PATH+'_get_channels', return_value=[])
    def test_channel_scanner_with_no_channels(self, *_):
        self.assertEqual(self.c.channel_scanner(), 0)

    @mock.patch(OBJ_PATH+'_start_sniffer', return_value=True)
    @mock.patch(OBJ_PATH+'_stop_sniffer')
    @mock.patch(OBJ_PATH+'_get_channels', return_value=[1])
    @mock.patch(OBJ_PATH+'set_channel')
    @mock.patch('probemon.wifi_channel.channel_scanner.time.sleep')
    def test_channel_scanner_with_channels(self, *_):
        with self.assertLogs(logger, 'DEBUG') as log:
            self.assertEqual(self.c.channel_scanner(), 0)
        self.assertListEqual(log.output, [
            f'INFO:{logger.name}:Start channel scan...',
            f'INFO:{logger.name}:Found zero APs and therefore no channel info.'
        ])

    @mock.patch(OBJ_PATH+'_start_sniffer', return_value=True)
    @mock.patch(OBJ_PATH+'_stop_sniffer')
    @mock.patch(OBJ_PATH+'_get_channels', return_value=[1])
    @mock.patch(OBJ_PATH+'set_channel')
    @mock.patch('probemon.wifi_channel.channel_scanner.time.sleep', side_effect=KeyboardInterrupt)
    def test_channel_scanner_with_keyboard_interrupt(self, sleep, *_):
        with self.assertLogs(logger, 'DEBUG') as log:
            self.assertEqual(self.c.channel_scanner(), 0)
        sleep.assert_called_once()
        self.assertListEqual(log.output, [
            f'INFO:{logger.name}:Start channel scan...',
            f'INFO:{logger.name}:Found zero APs and therefore no channel info.'
        ])

    @mock.patch(OBJ_PATH+'_start_sniffer', return_value=False)
    def test_channel_hopper_with_failed_start_sniffing(self, *_):
        self.assertEqual(self.c.channel_hopper(), 0)

    @mock.patch(OBJ_PATH+'_get_channels', return_value=[])
    def test_channel_hopper_with_no_channels(self, *_):
        self.assertEqual(self.c.channel_hopper(), 0)

    @mock.patch(OBJ_PATH+'_start_sniffer', return_value=True)
    @mock.patch(OBJ_PATH+'_stop_sniffer')
    @mock.patch(OBJ_PATH+'_get_channels', return_value=[1])
    @mock.patch(OBJ_PATH+'set_channel')
    @mock.patch('probemon.wifi_channel.channel_scanner.time.sleep', side_effect=KeyboardInterrupt)
    def test_channel_hopper_with_channels(self, *_):
        with self.assertLogs(logger, 'DEBUG') as log:
            self.assertEqual(self.c.channel_hopper(), 0)
        self.assertListEqual(log.output, [
            f'INFO:{logger.name}:Start channel hopping...',
            f'INFO:{logger.name}:Found zero APs and therefore no channel info.'
        ])

    @mock.patch(OBJ_PATH+'_get_channels', return_value=[1, 10, 100])
    @mock.patch('probemon.wifi_channel.channel_scanner.threading.Thread.start')
    @mock.patch(OBJ_PATH+'_async_hopper')
    def test_channel_hopper_async_no_sniff_all_channels(self, hopper, *args):
        logging.disable(logging.CRITICAL)
        self.c.channel_hopper_async_no_sniff(CHANNELS._ALL, FREQUENCIES._ALL)
        hopper.assert_called_with([1, 10, 100], True)

    @mock.patch(OBJ_PATH+'_get_channels', return_value=[1, 10, 100])
    @mock.patch('probemon.wifi_channel.channel_scanner.threading.Thread.start')
    @mock.patch(OBJ_PATH+'_async_hopper')
    def test_channel_hopper_async_no_sniff_2ghz(self, hopper, *args):
        logging.disable(logging.CRITICAL)
        self.c.channel_hopper_async_no_sniff(CHANNELS._ALL, FREQUENCIES._2GHz)
        hopper.assert_called_with([1, 10], True)

    @mock.patch(OBJ_PATH+'_get_channels', return_value=[1, 10, 100])
    @mock.patch('probemon.wifi_channel.channel_scanner.threading.Thread.start')
    @mock.patch(OBJ_PATH+'_async_hopper')
    def test_channel_hopper_async_no_sniff_5ghz(self, hopper, *args):
        logging.disable(logging.CRITICAL)
        self.c.channel_hopper_async_no_sniff(CHANNELS._ALL, FREQUENCIES._5GHz)
        hopper.assert_called_with([100], True)

    @mock.patch(OBJ_PATH+'channel_scanner')
    @mock.patch(OBJ_PATH+'_get_channels_with_count', return_value={1: 1, 10: 1, 100: 1})
    @mock.patch('probemon.wifi_channel.channel_scanner.threading.Thread.start')
    @mock.patch(OBJ_PATH+'_async_hopper')
    def test_channel_hopper_async_no_sniff_populated_channels(self, hopper, *args):
        logging.disable(logging.CRITICAL)
        self.c.channel_hopper_async_no_sniff(CHANNELS._POPULATED)
        hopper.assert_called_with([1, 10, 100], True)

    @mock.patch(OBJ_PATH+'_get_channels', return_value=[1, 10, 100])
    @mock.patch('probemon.wifi_channel.channel_scanner.threading.Thread.start')
    @mock.patch(OBJ_PATH+'_async_hopper')
    def test_channel_hopper_async_no_sniff_popular_channels(self, hopper, *args):
        logging.disable(logging.CRITICAL)
        self.c.channel_hopper_async_no_sniff(CHANNELS._POPULAR)
        hopper.assert_called_with([1, 6, 12], True)

    @mock.patch(OBJ_PATH+'channel_scanner', return_value=1)
    @mock.patch(OBJ_PATH+'set_channel')
    def test_set_auto_channel(self, setter, *args):
        logging.disable(logging.CRITICAL)
        self.c.set_auto_channel()
        setter.assert_called_with(1)

    @mock.patch(OBJ_PATH+'_get_channels_by_frequency', return_value=[2])
    @mock.patch(OBJ_PATH+'_start_sniffer')
    @mock.patch(OBJ_PATH+'_stop_sniffer')
    @mock.patch(OBJ_PATH+'_get_max_used_channel', return_value=(1, 2))
    @mock.patch('probemon.wifi_channel.channel_scanner.time.sleep')
    @mock.patch(OBJ_PATH+'set_channel')
    def test_ssid_searcher_aps_for_ssid_found(self, channel_setter, *args):
        logging.disable(logging.CRITICAL)
        self.c.ssid_searcher('test')
        channel_setter.assert_called_with(1)

    @mock.patch(OBJ_PATH+'_get_channels_by_frequency', return_value=[])
    @mock.patch(OBJ_PATH+'_start_sniffer')
    @mock.patch(OBJ_PATH+'_stop_sniffer')
    @mock.patch(OBJ_PATH+'_get_max_used_channel', return_value=(0, 0))
    @mock.patch('probemon.wifi_channel.channel_scanner.time.sleep', side_effect=KeyboardInterrupt)
    @mock.patch(OBJ_PATH+'set_channel')
    def test_ssid_searcher_aps_for_ssid_not_found_with_kbd_int(self, channel_setter, *args):
        logging.disable(logging.CRITICAL)
        self.c.ssid_searcher('test')
        channel_setter.assert_not_called()


@skipUnless(os.getuid() == 0, "Scapy needs root to sniff packets.")
@skipUnless('mon0' in get_if_list(), "Testing interface 'mon0' has to exist for this to proceed.")
class ChannelScannerCallbacksUnitTest(TestCase):
    def setUp(self) -> None:
        self.c = ChannelScanner('mon0')
        return super().setUp()

    def test_sniff_packet_with_beacon(self):
        self.c._sniff_packet()(BEACON)
        self.assertListEqual(self.c._access_points, [AccessPoint(BEACON)])

    def test_sniff_packet_with_beacon_twice(self):
        ap = AccessPoint(BEACON)
        ap.count += 1
        self.c._sniff_packet()(BEACON)
        self.c._sniff_packet()(BEACON)
        self.assertListEqual(self.c._access_points, [ap])

    def test_sniff_packet_with_probe_and_beacon(self):
        self.c._sniff_packet()(BEACON)
        self.c._sniff_packet()(PROBE)
        self.assertListEqual(self.c._access_points, [AccessPoint(BEACON), AccessPoint(PROBE)])

    def test_sniff_packet_with_non_beacon_probe(self):
        self.c._sniff_packet()(PACKET)
        self.assertListEqual(self.c._access_points, [])

    @mock.patch('probemon.wifi_channel.channel_scanner.time.sleep', side_effect=[0, 0, KeyboardInterrupt])
    @mock.patch(OBJ_PATH+'set_channel')
    def test_async_hopper_not_random_three_cycles(self, set_channel, sleep):
        with self.assertRaises(KeyboardInterrupt):
            self.c._async_hopper([1, 2], False)()
        set_channel.assert_has_calls([mock.call(1), mock.call(2), mock.call(1)])

    @mock.patch('probemon.wifi_channel.channel_scanner.time.sleep', side_effect=[0, 0, KeyboardInterrupt])
    @mock.patch(OBJ_PATH+'set_channel')
    def test_async_hopper_not_random_three_cycles_random(self, set_channel, sleep):
        with self.assertRaises(KeyboardInterrupt):
            self.c._async_hopper([1, 2], True)()
        self.assertEqual(set_channel.call_count, 3)
