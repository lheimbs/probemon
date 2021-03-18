from typing import Type
import netaddr
from netaddr import mac_unix_expanded


class Mac:
    dialect = mac_unix_expanded

    def __init__(self, mac: str, dialect: Type = None) -> None:
        if dialect:
            Mac.dialect = dialect
        self._mac_obj = netaddr.EUI(mac, dialect=Mac.dialect)

    @property
    def oui(self) -> str:
        """Get OUI of MAC (first 24-bit) as string.

        Since all APIs accept the format aa:bb:cc, format accordingly."""
        try:
            oui = self._mac_obj.oui
            oui = str(oui)
        except netaddr.core.NotRegisteredError:
            oui = self._mac_obj.format(dialect=netaddr.mac_eui48)[:8]
        return oui

    def __str__(self) -> str:
        return self._mac_obj.format(dialect=Mac.dialect)

    def __repr__(self) -> str:
        return (
            f"<Mac: {self._mac_obj.format(dialect=Mac.dialect)}, "
            f"dialect={Mac.dialect}>"
        )

    def __getitem__(self, key) -> str:
        mac = self.__str__()
        return mac.__getitem__(key)
