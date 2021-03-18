from unittest import TestCase

import netaddr

from ..mac import Mac

class MacUnitTest(TestCase):
    def setUp(self) -> None:
        self.mac_str_with_valid_oui = '58CB52aaaaaa'
        self.mac_str_with_invalid_oui = 'a1b2c3d4e5f6'
        self.inalid_mac_str = 'a1b2c3d4e'

    def tearDown(self) -> None:
        Mac.dialect = netaddr.mac_unix_expanded

    def test_mac_init_with_bad_mac_str(self):
        self.assertRaises(netaddr.core.AddrFormatError, Mac, self.inalid_mac_str)

    def test_mac_init_without_dialect(self):
        mac = Mac(self.mac_str_with_valid_oui)
        self.assertIsInstance(mac, Mac)

    def test_mac_init_with_dialect(self):
        Mac(self.mac_str_with_valid_oui, dialect=netaddr.mac_bare)
        self.assertEqual(Mac.dialect, netaddr.mac_bare)

    def test_mac_str_with_default_dialect(self):
        mac = Mac(self.mac_str_with_valid_oui)
        self.assertEqual(str(mac), '58:cb:52:aa:aa:aa')

    def test_mac_str_with_dialect(self):
        mac = Mac(self.mac_str_with_valid_oui, dialect=netaddr.mac_bare)
        self.assertEqual(str(mac), '58CB52AAAAAA')

    def test_mac_repr_with_default_dialect(self):
        mac = Mac(self.mac_str_with_valid_oui)
        self.assertEqual(
            repr(mac),
            "<Mac: 58:cb:52:aa:aa:aa, dialect=<class 'netaddr.strategy.eui48.mac_unix_expanded'>>"
        )

    def test_mac_repr_with_dialect(self):
        mac = Mac(self.mac_str_with_valid_oui, dialect=netaddr.mac_bare)
        self.assertEqual(
            repr(mac),
            "<Mac: 58CB52AAAAAA, dialect=<class 'netaddr.strategy.eui48.mac_bare'>>"
        )

    def test_mac_getitem(self):
        mac = Mac(self.mac_str_with_valid_oui)
        self.assertEqual(mac[0], self.mac_str_with_valid_oui[0])

    def test_mac_oui_with_valid_oui(self):
        mac = Mac(self.mac_str_with_valid_oui)
        self.assertEqual(mac.oui, '58-CB-52')

    def test_mac_oui_with_invalid_oui(self):
        mac = Mac(self.mac_str_with_invalid_oui)
        self.assertEqual(mac.oui, 'A1-B2-C3')
