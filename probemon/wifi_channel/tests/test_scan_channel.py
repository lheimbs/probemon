import logging
import sys
from unittest import TestCase, mock

from .. import scan_channel
from ..channel_scanner import CHANNELS, FREQUENCIES

class ParseArgsUnitTest(TestCase):
    @mock.patch('argparse.ArgumentParser._print_message')
    def test_args_help(self, _):
        self.assertRaises(SystemExit, scan_channel.parse_args, ['--help'])

    def test_args_interface(self):
        args = scan_channel.parse_args(['mon0'])
        self.assertEqual(args.interface, 'mon0')

    @mock.patch('argparse.ArgumentParser._print_message')
    def test_args_with_exit_false(self, _):
        self.assertIsNone(scan_channel.parse_args([], False))


class ScanChannelsUnitTest(TestCase):
    @mock.patch('argparse.ArgumentParser._print_message')
    def test_scan_channels_with_sys_args(self, _):
        sys.argv = ['123']
        with self.assertRaises(SystemExit):
            scan_channel.scan_channels()

    def test_scan_channels_with_args_and_bad_interface(self):
        with self.assertRaises(ValueError):
            scan_channel.scan_channels(args=['bad_iface'])

    def test_scan_channels_with_debug(self):
        with self.assertRaises(ValueError), self.assertLogs(scan_channel.logger, 'DEBUG'):
            scan_channel.scan_channels(args=['bad_iface', '--debug'])

    def test_scan_channels_with_verbose(self):
        with self.assertRaises(ValueError):
            scan_channel.scan_channels(args=['bad_iface', '--verbose'])
        self.assertEqual(scan_channel.logger.level, logging.INFO)

    def test_scan_channels_with_console(self):
        with self.assertRaises(ValueError):
            scan_channel.scan_channels(args=['bad_iface', '--console'])
        self.assertEqual(scan_channel.logger.level, logging.ERROR)

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.set_channel')
    def test_set(self, set_channel, *_):
        scan_channel.scan_channels(args=['mon0', 'set', '1'])
        set_channel.assert_called_once_with(1)

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.__init__', return_value=None)
    def test_ChannelScanner_args(self, ChannelScanner, *_):
        scan_channel.scan_channels(args=['mon0', '--time', '2'])
        ChannelScanner.assert_called_once_with('mon0', wait_time=2.0, console=False)

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.channel_scanner')
    def test_scan(self, channel_scanner, *_):
        scan_channel.scan_channels(args=['mon0', 'scan'])
        channel_scanner.assert_called_once()

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.channel_hopper')
    def test_hop(self, channel_hopper, *_):
        scan_channel.scan_channels(args=['mon0', 'hop'])
        channel_hopper.assert_called_once()

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.set_auto_channel')
    def test_auto(self, set_auto_channel, *_):
        scan_channel.scan_channels(args=['mon0', 'auto'])
        set_auto_channel.assert_called_once()

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.ssid_searcher')
    def test_search(self, ssid_searcher, *_):
        scan_channel.scan_channels(args=['mon0', 'search', 'test'])
        ssid_searcher.assert_called_with('test', FREQUENCIES._ALL)

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.ssid_searcher')
    def test_search_2ghz(self, ssid_searcher, *_):
        scan_channel.scan_channels(args=['mon0', 'search', 'test', '--2ghz'])
        ssid_searcher.assert_called_with('test', FREQUENCIES._2GHz)

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.ssid_searcher')
    def test_search_5ghz(self, ssid_searcher, *_):
        scan_channel.scan_channels(args=['mon0', 'search', 'test', '--5ghz'])
        ssid_searcher.assert_called_with('test', FREQUENCIES._5GHz)

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.channel_hopper_async_no_sniff')
    def test_hop_async_no_sniff(self, channel_hopper_async_no_sniff, *_):
        scan_channel.scan_channels(args=['mon0', 'hop_async_no_sniff'])
        channel_hopper_async_no_sniff.assert_called_with(CHANNELS._ALL, FREQUENCIES._ALL, False)

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.channel_hopper_async_no_sniff')
    def test_hop_async_no_sniff_popular(self, channel_hopper_async_no_sniff, *_):
        scan_channel.scan_channels(args=['mon0', 'hop_async_no_sniff', '--popular'])
        channel_hopper_async_no_sniff.assert_called_with(CHANNELS._POPULAR, FREQUENCIES._ALL, False)

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.channel_hopper_async_no_sniff')
    def test_hop_async_no_sniff_populated(self, channel_hopper_async_no_sniff, *_):
        scan_channel.scan_channels(args=['mon0', 'hop_async_no_sniff', '--populated'])
        channel_hopper_async_no_sniff.assert_called_with(CHANNELS._POPULATED, FREQUENCIES._ALL, False)

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.channel_hopper_async_no_sniff')
    def test_hop_async_no_sniff_2ghz(self, channel_hopper_async_no_sniff, *_):
        scan_channel.scan_channels(args=['mon0', 'hop_async_no_sniff', '--2ghz'])
        channel_hopper_async_no_sniff.assert_called_with(CHANNELS._ALL, FREQUENCIES._2GHz, False)

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.channel_hopper_async_no_sniff')
    def test_hop_async_no_sniff_5ghz(self, channel_hopper_async_no_sniff, *_):
        scan_channel.scan_channels(args=['mon0', 'hop_async_no_sniff', '--5ghz'])
        channel_hopper_async_no_sniff.assert_called_with(CHANNELS._ALL, FREQUENCIES._5GHz, False)

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.channel_hopper_async_no_sniff')
    def test_hop_async_no_sniff_random(self, channel_hopper_async_no_sniff, *_):
        scan_channel.scan_channels(args=['mon0', 'hop_async_no_sniff', '--random'])
        channel_hopper_async_no_sniff.assert_called_with(CHANNELS._ALL, FREQUENCIES._ALL, True)

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.print_channel_graph_vertical')
    def test_graph_vertical(self, print_channel_graph_vertical, *_):
        scan_channel.scan_channels(args=['mon0', '--console', '--graph-type', 'vertical'])
        print_channel_graph_vertical.assert_called_once()

    @mock.patch('probemon.wifi_channel.misc.can_use_interface')
    @mock.patch('probemon.wifi_channel.misc.can_use_iw')
    @mock.patch('probemon.wifi_channel.channel_scanner.ChannelScanner.print_channel_graph_horizontal')
    def test_graph_horizontal(self, print_channel_graph_horizontal, *_):
        scan_channel.scan_channels(args=['mon0', '--console', '--graph-type', 'horizontal'])
        print_channel_graph_horizontal.assert_called_once()

    @mock.patch.object(scan_channel.logger, 'hasHandlers', return_value=False)
    def test_debug_no_handlers(self, has):
        logging.disable(logging.CRITICAL)
        with self.assertRaises(ValueError):
            scan_channel.scan_channels(args=['bad_iface', '--debug'])
        has.assert_called_once()

    @mock.patch.object(scan_channel.logger, 'hasHandlers', return_value=False)
    def test_verbose_no_handlers(self, has):
        logging.disable(logging.CRITICAL)
        with self.assertRaises(ValueError):
            scan_channel.scan_channels(args=['bad_iface', '--verbose'])
        has.assert_called_once()
