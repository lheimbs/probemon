import json
import logging
from datetime import datetime

from scapy.layers.dot11 import RadioTap
from sqlalchemy import Column, Integer, String, DateTime, Sequence
from sqlalchemy.ext.declarative import declarative_base

from ..mac import Mac
from ..mac_vendor import get_mac_vendor

logger = logging.getLogger(__name__)
Base = declarative_base()


class ProbeRequest:
    raw: bool = False
    lower: bool = False
    get_vendor: bool = False
    maclookup_api_key: str = ""

    def __init__(
        self,
        time: datetime = None,
        mac: str = "",
        ssid: str = "",
        rssi: int = 0,
        raw: str = "",
    ):
        if isinstance(mac, str):
            self.mac = Mac(mac)
        elif isinstance(mac, Mac):
            self.mac = mac
        else:
            raise ValueError(
                "Mac address has to be either of type "
                f"<str> or type {Mac.__mro__[0]}!"
            )
        self.time = time
        self.ssid = ssid if not ProbeRequest.lower else ssid.lower()
        self.rssi = rssi
        self.raw = raw if ProbeRequest.raw else ""
        self._set_vendor()

    def _set_vendor(self):
        from ..sql import Sql
        vendor = ''
        if ProbeRequest.get_vendor:
            vendor = Sql.get_vendor(self.mac)
            if vendor:
                logger.debug(
                    f"Got vendor {vendor} for mac {self.mac} from database."
                )
            else:
                vendor = get_mac_vendor(
                    self.mac.oui,
                    maclookup_api_key=ProbeRequest.maclookup_api_key,
                    lower=ProbeRequest.lower,
                )
        self.vendor = vendor.lower() if ProbeRequest.lower else vendor

    @classmethod
    def from_packet(cls, packet: RadioTap, **kwargs: dict):
        if hasattr(packet, 'time'):
            time = datetime.fromtimestamp(packet.time)
        else:
            time = datetime.now()
        mac = packet.addr2
        ssid = packet.info.decode('utf8')
        rssi = packet.dBm_AntSignal
        raw = packet.original.hex()
        return cls(
            time=time,
            mac=mac,
            ssid=ssid,
            rssi=rssi,
            raw=raw,
            **kwargs,
        )

    def model(self):
        try:
            model = ProbeRequestModel(
                time=self.time,
                mac=str(self.mac),
                ssid=self.ssid,
                rssi=self.rssi,
                vendor=self.vendor,
                raw=self.raw,
            )
        except AttributeError:
            logger.debug(
                "Could not make model because sql is not initialized."
            )
            model = None
        return model

    def __repr__(self):
        return (
            "<ProbeRequest("
            f"time='{self.time.isoformat()}', "
            f"mac='{self.mac}', "
            f"ssid='{self.ssid}', "
            f"rssi={self.rssi}, "
            f"vendor='{self.vendor}', "
            f"raw='{self.raw}', "
            ")>"
        )

    def __str__(self):
        self_dict = self.__dict__()
        self_dict['mac'] = str(self_dict['mac'])
        if self_dict['time']:
            self_dict['time'] = self_dict['time'].isoformat()
        else:
            self_dict['time'] = None
        return json.dumps(self_dict)

    def __dict__(self):
        return {
            'time': self.time,
            'mac': self.mac,
            'vendor': self.vendor,
            'ssid': self.ssid,
            'rssi': self.rssi,
            'raw': self.raw,
        }


class ProbeRequestModel(Base, ProbeRequest):
    __tablename__ = "probe_requests"

    id = Column(Integer, Sequence('probe_request_id_seq'), primary_key=True)
    time = Column(DateTime)
    mac = Column(String(20))
    vendor = Column(String(200))
    ssid = Column(String(200))
    rssi = Column(Integer)
    raw = Column(String(1000))
