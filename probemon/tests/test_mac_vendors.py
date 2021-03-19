import re
import logging
from unittest import TestCase, mock

import responses
import requests
from maclookup.exceptions.authorization_required_exception \
    import AuthorizationRequiredException
from maclookup.exceptions.not_enough_credits_exception \
    import NotEnoughCreditsException

from ..mac import Mac
from ..mac_vendor import vendor

ALL_URLS = re.compile('http*.?')

class GetVendorUnitTest(TestCase):
    def setUp(self) -> None:
        self.mac_with_valid_oui = Mac('58CB52aaaaaa')  # Google oui
        self.mac_with_invalid_oui = Mac('ffffffffffff')
        return super().setUp()

    def test_no_mac_with_unknown_vendor(self):
        res = vendor.get_mac_vendor(None, unknown_vendor='UNKNOWN')
        self.assertEqual(res, 'UNKNOWN')

    def test_valid_mac_oui_in_offline_mode(self):
        res = vendor.get_mac_vendor(self.mac_with_valid_oui.oui, offline=True)
        self.assertEqual(res, 'Google, Inc.')

    def test_valid_mac_oui_in_online_mode_with_lower(self):
        res = vendor.get_mac_vendor(self.mac_with_valid_oui.oui, lower=True)
        self.assertEqual(res, 'Google, Inc.'.lower())

    @responses.activate
    def test_invalid_mac(self):
        responses.add(responses.GET, url=ALL_URLS, status=500)
        res = vendor.get_mac_vendor(self.mac_with_invalid_oui.oui)
        self.assertEqual(res, '')


class NetaddrVendorUnitTest(TestCase):
    def setUp(self) -> None:
        self.mac_with_valid_oui = Mac('58CB52aaaaaa')  # Google oui
        self.mac_with_invalid_oui = Mac('ffffffffffff')
        return super().setUp()

    def test_mac_with_valid_oui(self):
        res = vendor.get_netaddr_vendor(str(self.mac_with_valid_oui))
        self.assertEqual(res, 'Google, Inc.')

    def test_mac_with_invalid_oui(self):
        res = vendor.get_netaddr_vendor(str(self.mac_with_invalid_oui))
        self.assertEqual(res, '')

    def test_oui_with_valid_oui(self):
        res = vendor.get_netaddr_vendor(self.mac_with_valid_oui.oui)
        self.assertEqual(res, 'Google, Inc.')

    def test_oui_with_invalid_oui(self):
        res = vendor.get_netaddr_vendor(self.mac_with_invalid_oui.oui)
        self.assertEqual(res, '')


class MaclookupUnitTest(TestCase):
    def setUp(self) -> None:
        self.mac_with_valid_oui = Mac('58CB52aaaaaa')  # Google oui

    def tearDown(self) -> None:
        return super().tearDown()

    def test_without_api_key(self):
        with self.assertLogs(vendor.logger, 'DEBUG') as log:
            vendor.get_maclookup_vendor(self.mac_with_valid_oui.oui, '')
        self.assertIn('DEBUG:probemon.mac_vendor.vendor:No api key for maclookup supplied.', log.output)

    @mock.patch('maclookup.requester.urlopen')
    def test_with_api_key(self, url_open):
        mock_resp = mock.Mock()
        mock_resp.info.return_value = ''
        mock_resp.read.return_value = b'google'
        mock_resp.getheaders.return_value = {}
        url_open.return_value = mock_resp
        type(url_open.return_value).code = mock.PropertyMock(return_value=200)
        res = vendor.get_maclookup_vendor(self.mac_with_valid_oui.oui, 'key')
        self.assertEqual(res, 'google')

    @mock.patch(
        'maclookup.api_client.ApiClient.get_vendor',
        mock.Mock(side_effect=AuthorizationRequiredException())
    )
    def test_authorisation_required(self):
        with self.assertLogs(vendor.logger, 'DEBUG') as log:
            res = vendor.get_maclookup_vendor(self.mac_with_valid_oui.oui, 'key')
        self.assertEqual(res, '')
        self.assertIn(
            'WARNING:probemon.mac_vendor.vendor:Given api key for maclookup is invalid.',
            log.output
        )

    @mock.patch(
        'maclookup.api_client.ApiClient.get_vendor',
        mock.Mock(side_effect=NotEnoughCreditsException())
    )
    def test_limit_reached(self):
        with self.assertLogs(vendor.logger, 'DEBUG') as log:
            res = vendor.get_maclookup_vendor(self.mac_with_valid_oui.oui, 'PROBEMON_MACLOOKUP_API_KEY')
        self.assertEqual(res, '')
        self.assertIn(
            'INFO:probemon.mac_vendor.vendor:Maclookups free 1000 daily requests limit reached.',
            log.output
        )


class MacvendorlookupComUnitTest(TestCase):
    def setUp(self) -> None:
        self.mac_with_valid_oui = Mac('58CB52aaaaaa')  # Google oui
        self.url = 'http://www.macvendorlookup.com/api/v2/{mac}'.format(mac=self.mac_with_valid_oui.oui)

    @responses.activate
    def test_request_timeout(self):
        logging.disable(logging.WARNING)
        responses.add(responses.GET, url=self.url, status=200, body=requests.exceptions.ConnectTimeout())
        res = vendor.get_macvendorlookup_com_vendor(self.mac_with_valid_oui.oui)
        self.assertEqual(res, '')
        logging.disable(logging.NOTSET)

    @responses.activate
    def test_result_status_code_ok(self):
        responses.add(responses.GET, url=self.url, status=200, json=[{'company': 'test'}])
        res = vendor.get_macvendorlookup_com_vendor(self.mac_with_valid_oui.oui)
        self.assertEqual(res, 'test')

    @responses.activate
    def test_result_status_code_ok_but_result_not_in_json(self):
        responses.add(responses.GET, url=self.url, status=200, json={})
        res = vendor.get_macvendorlookup_com_vendor(self.mac_with_valid_oui.oui)
        self.assertEqual(res, '')

    @responses.activate
    def test_result_status_code_rate_limit_reached(self):
        responses.add(responses.GET, url=self.url, status=429)
        with self.assertLogs(vendor.logger, 'INFO') as log:
            res = vendor.get_macvendorlookup_com_vendor(self.mac_with_valid_oui.oui)
        self.assertEqual(res, '')
        self.assertIn('Rate limit reached for ', log.output[0])

    @responses.activate
    def test_error_debug_message_if_vendor_is_empty(self):
        responses.add(responses.GET, url=self.url, status=500)
        with self.assertLogs(vendor.logger, 'DEBUG') as log:
            vendor.get_macvendorlookup_com_vendor(self.mac_with_valid_oui.oui)
        self.assertIn('DEBUG:probemon.mac_vendor.vendor:Error getting vendor from macvendorlookup.com.', log.output)


class MacvendorsCoUnitTest(TestCase):
    def setUp(self) -> None:
        self.mac_with_valid_oui = Mac('58CB52aaaaaa')  # Google oui
        self.url = 'https://macvendors.co/api/{mac}'.format(mac=self.mac_with_valid_oui.oui)

    @responses.activate
    def test_request_timeout(self):
        logging.disable(logging.WARNING)
        responses.add(responses.GET, url=self.url, status=200, body=requests.exceptions.ConnectTimeout())
        res = vendor.get_macvendors_co_vendor(self.mac_with_valid_oui.oui)
        self.assertEqual(res, '')
        logging.disable(logging.NOTSET)

    @responses.activate
    def test_result_status_code_ok(self):
        responses.add(responses.GET, url=self.url, status=200, json={'result': {'company': 'test'}})
        res = vendor.get_macvendors_co_vendor(self.mac_with_valid_oui.oui)
        self.assertEqual(res, 'test')

    @responses.activate
    def test_result_status_code_ok_but_result_not_in_json(self):
        responses.add(responses.GET, url=self.url, status=200, json={})
        res = vendor.get_macvendors_co_vendor(self.mac_with_valid_oui.oui)
        self.assertEqual(res, '')

    @responses.activate
    def test_result_status_code_rate_limit_reached(self):
        responses.add(responses.GET, url=self.url, status=429)
        with self.assertLogs(vendor.logger, 'INFO') as log:
            res = vendor.get_macvendors_co_vendor(self.mac_with_valid_oui.oui)
        self.assertEqual(res, '')
        self.assertIn('Rate limit reached for ', log.output[0])

    @responses.activate
    def test_error_debug_message_if_vendor_is_empty(self):
        responses.add(responses.GET, url=self.url, status=500)
        with self.assertLogs(vendor.logger, 'DEBUG') as log:
            vendor.get_macvendors_co_vendor(self.mac_with_valid_oui.oui)
        self.assertIn('DEBUG:probemon.mac_vendor.vendor:Error getting vendor from macvendors.co.', log.output)


class MacvendorsComUnitTest(TestCase):
    def setUp(self) -> None:
        self.mac_with_valid_oui = Mac('58CB52aaaaaa')  # Google oui
        self.url = 'https://api.macvendors.com/{mac}'.format(mac=self.mac_with_valid_oui.oui)

    @responses.activate
    def test_request_timeout(self):
        logging.disable(logging.WARNING)
        responses.add(responses.GET, url=self.url, status=200, body=requests.exceptions.ConnectTimeout())
        res = vendor.get_macvendors_com_vendor(self.mac_with_valid_oui.oui)
        self.assertEqual(res, '')
        logging.disable(logging.NOTSET)

    @responses.activate
    def test_result_status_code_ok(self):
        responses.add(responses.GET, url=self.url, status=200, body='test')
        res = vendor.get_macvendors_com_vendor(self.mac_with_valid_oui.oui)
        self.assertEqual(res, 'test')

    @responses.activate
    def test_result_status_code_ok_but_multiline_in_body(self):
        responses.add(responses.GET, url=self.url, status=200, body='test\ntest')
        res = vendor.get_macvendors_com_vendor(self.mac_with_valid_oui.oui)
        self.assertEqual(res, '')

    @responses.activate
    def test_result_status_code_rate_limit_reached(self):
        responses.add(responses.GET, url=self.url, status=429)
        with self.assertLogs(vendor.logger, 'INFO') as log:
            res = vendor.get_macvendors_com_vendor(self.mac_with_valid_oui.oui)
        self.assertEqual(res, '')
        self.assertIn('Rate limit reached for ', log.output[0])

    @responses.activate
    def test_error_debug_message_if_vendor_is_empty(self):
        responses.add(responses.GET, url=self.url, status=500)
        with self.assertLogs(vendor.logger, 'DEBUG') as log:
            vendor.get_macvendors_com_vendor(self.mac_with_valid_oui.oui)
        self.assertIn('DEBUG:probemon.mac_vendor.vendor:Error getting vendor from api.macvendors.com.', log.output)
