from unittest import TestCase, mock

from .test_channel_scanner import BEACON, PROBE, PACKET_2
from ..misc import AccessPoint, can_use_interface, can_use_iw

class AccessPointUnitTest(TestCase):
    def test_init(self):
        a = AccessPoint(BEACON)
        self.assertEqual(a.ssid, 'some_ssid')
        self.assertEqual(a.bssid, '11:22:33:44:55:66')
        self.assertEqual(a.channel, 1)
        self.assertEqual(a.enc, 'n')
        self.assertEqual(a.count, 1)

    def test_init_encrypted(self):
        a = AccessPoint(PROBE)
        self.assertEqual(a.enc, 'y')

    def test_equal_same_two(self):
        a1 = AccessPoint(BEACON)
        a2 = AccessPoint(BEACON)
        self.assertTrue(a1 == a2)

    def test_not_equal_probe_beacon(self):
        a1 = AccessPoint(BEACON)
        a2 = AccessPoint(PROBE)
        self.assertFalse(a1 == a2)

    def test_not_equal_probe_str(self):
        a1 = AccessPoint(BEACON)
        self.assertFalse(a1 == 'True')

    def test_with_bad_channel(self):
        a1 = AccessPoint(PACKET_2)
        self.assertEqual(a1.channel, -1)

    def test_str(self):
        a = AccessPoint(BEACON)
        a_str = '<AccessPoint(bssid="11:22:33:44:55:66", channel=1, enc="n", ssid="some_ssid", count=1)>'
        self.assertEqual(str(a), a_str)


class CanUseInterfaceUnitTest(TestCase):
    @mock.patch('probemon.wifi_channel.misc.get_if_list', return_value=['mon0', 'eno0', 'lo'])
    @mock.patch('probemon.wifi_channel.misc.socket')
    def test_can_use_interface_with_valid_interface(self, socket, _):
        can_use_interface('mon0')
        socket.assert_called_once()

    @mock.patch('probemon.wifi_channel.misc.get_if_list', return_value=['mon0', 'eno0', 'lo'])
    def test_can_use_interface_with_bad_interface_raises_value_error(self, _):
        with self.assertRaises(ValueError):
            can_use_interface('asdasd')


class CanUseIwUnitTest(TestCase):
    @mock.patch('probemon.wifi_channel.misc.subprocess.run')
    def test_can_use_iw(self, run):
        self.assertTrue(can_use_iw())
        run.assert_called_once()

    @mock.patch('probemon.wifi_channel.misc.subprocess.run', side_effect=FileNotFoundError)
    def test_can_use_iw_raises_exception(self, run):
        self.assertRaises(FileNotFoundError, can_use_iw)
