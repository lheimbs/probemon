import json
import logging
from datetime import datetime
from probemon.mac.mac_address import Mac
from unittest import TestCase, mock

from ..probe_request import ProbeRequest, ProbeRequestModel

def reset_probe():
    ProbeRequest.lower = False
    ProbeRequest.raw = False
    ProbeRequest.get_vendor = False
    ProbeRequest.vendor_offline = False
    ProbeRequest.maclookup_api_key = ""


class ProbeRequestUnitTest(TestCase):
    def setUp(self) -> None:
        reset_probe()
        return super().setUp()

    def tearDown(self) -> None:
        logging.disable(logging.NOTSET)
        return super().tearDown()

    def test_init_with_nothing_set(self):
        self.assertRaises(ValueError, ProbeRequest)

    @mock.patch('probemon.probe_request.probe_request.datetime')
    def test_init_with_mac_as_str(self, dt):
        now = datetime(year=2021, month=3, day=1, hour=10, minute=0, second=0, microsecond=0)
        dt.now.return_value = now
        probe = ProbeRequest(mac='112233445566')
        self.assertEqual(probe.time, now)
        self.assertIsInstance(probe.mac, Mac)
        self.assertEqual(probe.ssid, '')
        self.assertEqual(probe.rssi, 0)
        self.assertEqual(probe.raw, '')
        self.assertEqual(probe.vendor, '')

    def test_init_with_mac_as_mac(self):
        probe = ProbeRequest(mac=Mac('112233445566'))
        self.assertIsInstance(probe.mac, Mac)

    def test_init_ssid_with_lower_set(self):
        ProbeRequest.lower = True
        probe = ProbeRequest(mac='112233445566', ssid="TEST")
        self.assertEqual(probe.ssid, 'test')

    def test_init_ssid_with_lower_not_set(self):
        probe = ProbeRequest(mac='112233445566', ssid="TEST")
        self.assertEqual(probe.ssid, 'TEST')

    def test_init_raw_with_raw_set(self):
        ProbeRequest.raw = True
        probe = ProbeRequest(mac='112233445566', raw="test")
        self.assertEqual(probe.raw, 'test')

    def test_init_raw_with_raw_not_set(self):
        probe = ProbeRequest(mac='112233445566', raw="test")
        self.assertEqual(probe.raw, '')

    @mock.patch('probemon.sql.Sql')
    def test_init_with_get_vendor(self, sql_obj):
        ProbeRequest.get_vendor = True
        sql_obj.get_vendor.return_value = 'test'
        probe = ProbeRequest(mac='112233445566')
        self.assertEqual(probe.vendor, 'test')

    @mock.patch('probemon.sql.Sql')
    def test_set_vendor_from_mac_vendor(self, sql_obj):
        ProbeRequest.get_vendor = True
        sql_obj.get_vendor.return_value = ''
        probe = ProbeRequest(mac='112233445566')
        self.assertEqual(probe.vendor, 'Schneider Electric')

    @mock.patch('probemon.sql.Sql')
    def test_set_vendor_from_mac_vendor_with_lower_set(self, sql_obj):
        ProbeRequest.lower = True
        ProbeRequest.get_vendor = True
        sql_obj.get_vendor.return_value = ''
        probe = ProbeRequest(mac='112233445566')
        self.assertEqual(probe.vendor, 'Schneider Electric'.lower())

    def test_from_packet_with_timestamp_and_raw(self):
        ProbeRequest.raw = True
        packet = mock.Mock()
        type(packet).time = mock.PropertyMock(return_value=1614589200.0)
        type(packet).addr2 = mock.PropertyMock(return_value='112233445566')
        type(packet).info = mock.PropertyMock(return_value=b'test')
        type(packet).dBm_AntSignal = mock.PropertyMock(return_value=-10)
        type(packet).original = mock.PropertyMock(return_value=b'\x00\x01')

        probe = ProbeRequest.from_packet(packet)
        self.assertEqual(
            probe.time,
            datetime(year=2021, month=3, day=1, hour=10, minute=0, second=0, microsecond=0)
        )
        self.assertIsInstance(probe.mac, Mac)
        self.assertEqual(probe.ssid, 'test')
        self.assertEqual(probe.rssi, -10)
        self.assertEqual(probe.raw, '0001')

    @mock.patch('probemon.probe_request.probe_request.datetime')
    def test_from_packet_without_timestamp(self, dt):
        dt.now.return_value = datetime(year=2021, month=3, day=1, hour=10, minute=0, second=0, microsecond=0)
        packet = mock.Mock()
        del packet.time
        type(packet).addr2 = mock.PropertyMock(return_value='112233445566')

        probe = ProbeRequest.from_packet(packet)
        self.assertEqual(
            probe.time,
            datetime(year=2021, month=3, day=1, hour=10, minute=0, second=0, microsecond=0)
        )

    def test_model_with_good_values(self):
        probe = ProbeRequest(mac='112233445566')
        probe_model = probe.model()
        self.assertIsInstance(probe_model, ProbeRequestModel)
        self.assertEqual(probe_model.mac, str(probe.mac))

    @mock.patch('probemon.probe_request.probe_request.ProbeRequestModel')
    def test_model_with_attr_error(self, model):
        model.side_effect = AttributeError
        probe = ProbeRequest(mac='112233445566')
        probe_model = probe.model()
        self.assertIsNone(probe_model)

    def test_repr(self):
        probe = ProbeRequest(mac='112233445566', time=datetime.now())
        self.assertEqual(repr(probe), (
            "<ProbeRequest("
            f"time='{probe.time.isoformat()}', "
            f"mac='{probe.mac}', "
            f"ssid='{probe.ssid}', "
            f"rssi={probe.rssi}, "
            f"vendor='{probe.vendor}', "
            f"raw='{probe.raw}', "
            ")>"
        ))

    def test_str(self):
        probe = ProbeRequest(mac='112233445566')
        self.assertEqual(str(probe), json.dumps({
            'time': probe.time.isoformat(),
            'mac': str(probe.mac),
            'vendor': probe.vendor,
            'ssid': probe.ssid,
            'rssi': probe.rssi,
            'raw': probe.raw,
        }))

    def test_str_without_time(self):
        probe = ProbeRequest(mac='112233445566')
        probe.time = None
        self.assertEqual(str(probe), json.dumps({
            'time': None,
            'mac': str(probe.mac),
            'vendor': probe.vendor,
            'ssid': probe.ssid,
            'rssi': probe.rssi,
            'raw': probe.raw,
        }))
