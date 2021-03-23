from unittest import TestCase, mock

from .. import set_channel

class IsFloatTest(TestCase):
    def test_float(self):
        self.assertTrue(set_channel.is_float('1.0'))

    def test_non_float(self):
        self.assertFalse(set_channel.is_float('1.0asd'))


class IsIntTest(TestCase):
    def test_int_str(self):
        self.assertTrue(set_channel.is_int('1'))

    def test_non_int_str(self):
        self.assertFalse(set_channel.is_int('1.0asd'))


class IsArgValidTest(TestCase):
    def test_bad_str(self):
        self.assertFalse(set_channel.is_arg_valid('test'))

    def test_integer_str(self):
        self.assertTrue(set_channel.is_arg_valid('12'))

    def test_float_str(self):
        self.assertTrue(set_channel.is_arg_valid('12.123'))

    def test_allowed_arg_str(self):
        self.assertTrue(set_channel.is_arg_valid('hop'))


class SetWifiChannelFromArgsTest(TestCase):
    def test_args_without_channel(self):
        self.assertFalse(set_channel.set_wifi_channel_from_args('mon0', {}))

    @mock.patch('probemon.wifi_channel.set_channel.scan_channels')
    def test_args_with_channel_but_iface_only(self, scan_channels):
        self.assertTrue(set_channel.set_wifi_channel_from_args('mon0', {'channel': 'test'}))
        scan_channels.assert_called_once_with(args=['mon0'])

    @mock.patch('probemon.wifi_channel.set_channel.scan_channels')
    def test_args_with_channel_and_ssid(self, scan_channels):
        self.assertTrue(set_channel.set_wifi_channel_from_args('mon0', {'channel': 'search SSID:Test'}))
        scan_channels.assert_called_once_with(args=['mon0', 'search', 'Test'])


# class GetChannelSettingUnitTest(TestCase):
#     def test_settings_with_no_channel_settings(self):
#         res = get_channel_setting({'test': 1})
#         self.assertDictEqual(res, {})

#     def test_settings_with_tuple(self):
#         res = get_channel_setting({'channel_hop': ('Yes', 1)})
#         self.assertDictEqual(res, {'hop': [('Yes', 1)]})
