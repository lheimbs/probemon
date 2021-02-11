import json
import logging
from datetime import datetime

from scapy.layers.dot11 import RadioTap
from sqlalchemy import Column, Integer, String, DateTime, Sequence
from sqlalchemy.ext.declarative import declarative_base

from ..mac_vendor import get_mac_vendor

logger = logging.getLogger('ProbeRequest')
Base = declarative_base()

class ProbeRequest:
    raw = False
    lower = False

    def __init__(
        self,
        time: datetime = None,
        mac: str = "",
        ssid: str = "",
        rssi: int = 0,
        raw: str = "",
        vendor: str = "",
        maclookup_api_key: str = "",
        get_vendor: bool = False,
    ):
        self.time = time
        self.mac = mac if not self.lower else mac.lower()
        self.ssid = ssid if not self.lower else ssid.lower()
        self.rssi = rssi
        self.raw = raw if self.raw else ""
        if get_vendor and not vendor:
            self.vendor = get_mac_vendor(
                mac[:8],
                maclookup_api_key=maclookup_api_key,
                lower=self.lower,
            )
        elif not get_vendor and vendor:
            self.vendor = vendor
        else:
            self.vendor = ""

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

    @classmethod
    def from_packet(cls, packet: RadioTap, get_vendor: bool):
        time = datetime.fromtimestamp(packet.time)
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
            get_vendor=get_vendor
        )

    def model(self):
        try:
            model = ProbeRequestModel(
                time=self.time,
                mac=self.mac,
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


class ProbeRequestModel(Base, ProbeRequest):
    __tablename__ = "probe_requests"

    id = Column(Integer, Sequence('probe_request_id_seq'), primary_key=True)
    time = Column(DateTime)
    mac = Column(String(20))
    vendor = Column(String(200))
    ssid = Column(String(200))
    rssi = Column(Integer)
    raw = Column(String(1000))
