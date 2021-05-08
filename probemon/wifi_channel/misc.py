import re
import subprocess
from socket import socket, AF_PACKET, SOCK_RAW

from scapy.all import get_if_list, RadioTap, Dot11, Dot11Elt


class AccessPoint:
    """Class to represent a recorded AccessPoints Beacon/ProbeResp.

    Supports equality comparison to allow counting of multiple same packets.
    """
    def __init__(self, packet: RadioTap) -> None:
        capability = packet.sprintf(
            "{Dot11Beacon:%Dot11Beacon.cap%}"
            "{Dot11ProbeResp:%Dot11ProbeResp.cap%}"
        )
        self.bssid = packet[Dot11].addr3
        try:
            channel = int(ord(packet[Dot11Elt:3].info))
        except TypeError:
            channel = -1
        self.channel = channel
        self.enc = 'y' if re.search("privacy", capability) else 'n'
        self.ssid = packet[Dot11Elt].info.decode('utf-8')
        self.count = 1

    def __eq__(self, other):
        if isinstance(other, AccessPoint):
            return all([
                self.bssid == other.bssid,
                self.channel == other.channel,
                self.enc == other.enc,
                self.ssid == other.ssid
            ])
        return False

    def __repr__(self):
        return (
            f'<AccessPoint(bssid="{self.bssid}", '
            f'channel={self.channel}, '
            f'enc="{self.enc}", '
            f'ssid="{self.ssid}", '
            f"count={self.count})>"
        )


def can_use_interface(interface: str) -> True:
    """ Make sure the supplied interface exists and can be used.

    Raise ValueError if it does not exist.
    Raise PermissionError if it cant get used.
    """
    available_interfaces = get_if_list()
    if interface not in available_interfaces:
        raise ValueError(f"Interface {interface} does not exist!")
    socket(AF_PACKET, SOCK_RAW).close()
    return True

def can_use_iw() -> True:
    """Test if iw is accessible to the user."""
    try:
        subprocess.run(
            ['iw'], check=True,
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise FileNotFoundError(
            "Can not access 'iw'. "
            "Please make sure iw is installed and accessible by sudo."
        )
