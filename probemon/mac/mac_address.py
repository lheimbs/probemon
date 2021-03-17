from typing import Type
import netaddr
from netaddr.strategy.eui48 import mac_unix_expanded


class Mac:
    dialect = mac_unix_expanded

    def __init__(self, mac: str, dialect: Type = None):
        if dialect:
            Mac.dialect = dialect
        self._mac_obj = netaddr.EUI(mac, dialect=Mac.dialect)

    @property
    def oui(self):
        try:
            oui = self._mac_obj.oui
            oui = str(oui).replace('-', ':')
        except netaddr.core.NotRegisteredError:
            oui = self._mac_obj.format(dialect=netaddr.mac_unix_expanded)[:8]
        return oui

    def __str__(self):
        return self._mac_obj.format(dialect=Mac.dialect)

    def __repr__(self):
        return self._mac_obj.format(dialect=Mac.dialect)

    def __getitem__(self, key):
        mac = self.__str__()
        return mac.__getitem__(key)
