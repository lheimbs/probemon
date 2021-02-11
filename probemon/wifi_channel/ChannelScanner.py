import re
import json
import time
import shlex
import random
import logging
import subprocess
from typing import Callable, Union
from scapy.error import Scapy_Exception
from scapy.layers.dot11 import RadioTap
from scapy.all import (
    Dot11Beacon, Dot11ProbeResp, Dot11, Dot11Elt, AsyncSniffer
)
logger = logging.getLogger('ChannelScanner')

class ChannelScanner:
    def __init__(self, interface: str, wait_time: int = 1, console: bool = False):
        self._interface = interface
        self.__sniffer = AsyncSniffer(iface=self._interface, prn=self.sniff_packet())
        self.__available_channels = []
        self.__access_points = []
        self.__wait_time = wait_time
        self.__console = console

    def _start_sniffer(self) -> bool:
        self.__sniffer.start()
        return True

    def _stop_sniffer(self) -> bool:
        try:
            self.__sniffer.stop()
            return True
        except Scapy_Exception:
            logger.error("Something failed stopping scapy sniffer. Try running as root.")
            return False

    def _get_channels(self) -> list:
        if not self.__available_channels:
            logger.debug("Getting channels for local wifi adapter.")
            CHANNEL_REGEX = re.compile(r"\*\s(?P<frequency>\d{4})\sMHz\s\[(?P<channel>\d{1,3})\]")
            proc = subprocess.run(['iw', 'list'], stdout=subprocess.PIPE, encoding='utf-8')
            for line in proc.stdout.splitlines():
                m = CHANNEL_REGEX.search(line)
                if m and '(disabled)' not in line:
                    self.__available_channels.append(int(m.group('channel')))
        return self.__available_channels

    def set_channel(self, channel: int) -> bool:
        """ Change the channel on the specified wifi interface """
        if channel not in self._get_channels():
            logger.error(f"Channel {channel} not available for this device!")
            return False

        cmd = "iw dev {} set channel {}".format(self._interface, channel)
        proc = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8')
        if proc.returncode == 0:
            ret_val = True
            logger.info(f"Interface '{self._interface}' set to channel {channel}.")
        else:
            ret_val = False
            stdout = " ".join(proc.stdout.splitlines())
            logger.error(
                f"Failed setting channel {channel} on interface '{self._interface}': "
                f"'{stdout}'"
            )

        self._print(
            f"Scan channel {channel:2}...",
            f"{len(set(self._get_scanned_channels())):3} distinct channels found..."
        )
        return ret_val

    def sniff_packet(self) -> Callable:
        """ process unique sniffed Beacons and ProbeResponses """
        def parse_sniffed_packet(packet: RadioTap):
            if (
                (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp))
                and packet[Dot11].addr3 not in [ap['bssid'] for ap in self.__access_points]
            ):
                capability = packet.sprintf(
                    "{Dot11Beacon:%Dot11Beacon.cap%}"
                    "{Dot11ProbeResp:%Dot11ProbeResp.cap%}"
                )
                ap = {
                    'bssid': packet[Dot11].addr3,
                    'channel': int(ord(packet[Dot11Elt:3].info)),
                    'enc': 'y' if re.search("privacy", capability) else 'n',
                    'ssid': packet[Dot11Elt].info.decode('utf-8')
                }

                # Save discovered AP
                self.__access_points.append(ap)
                # Display discovered AP
                logger.debug(f"Detected AP {json.dumps(ap)}")
        return parse_sniffed_packet

    def channel_scanner(self) -> int:
        """ Channel scanner """
        if not self._start_sniffer():
            return 0
        for channel in self._get_channels():
            try:
                self.set_channel(channel)
                time.sleep(self.__wait_time)
            except KeyboardInterrupt:
                break
        self._stop_sniffer()
        return self.get_channel_utilization()

    def channel_hopper(self) -> int:
        """ Channel hopper """
        if not self._start_sniffer():
            return 0
        try:
            while True:
                try:
                    channel = random.choice(self._get_channels())
                    self.set_channel(channel)
                    time.sleep(self.__wait_time)
                except KeyboardInterrupt:
                    break
        finally:
            self._stop_sniffer()
        return self.get_channel_utilization()

    def set_auto_channel(self) -> bool:
        logger.info("Scanning for available channels...")
        max_used_channel = self.channel_scanner()
        return self.set_channel(max_used_channel)

    def get_channel_utilization(self) -> int:
        counts = self._get_channel_count(skip_zero=True)
        max_used_channel, max_used_channel_amount = self._get_max_used_channel()
        channel_info = (
            f"Found {', '.join([f'channel {ch}: {num}x' for ch, num in counts.items()])}. "
            f"Channel {max_used_channel} is the most populated ({max_used_channel_amount} APs)."
        ) if counts else "Found zero aps and therefore zero channel info."

        logger.info(channel_info)
        self._print(channel_info, keep=True)
        return max_used_channel

    def _get_scanned_channels(self) -> list:
        return [ap['channel'] for ap in self.__access_points if 'channel' in ap.keys()]

    def _get_channel_count(self, skip_zero: bool = False) -> dict:
        scanned_channels = self._get_scanned_channels()
        counted_channels = {}
        for channel in self._get_channels():
            count = scanned_channels.count(channel)
            if skip_zero and count <= 0:
                continue
            counted_channels.update({channel: count})
        return counted_channels

    def _get_max_used_channel(self) -> Union[int, int]:
        counts = self._get_channel_count(skip_zero=True)
        if not counts:
            logger.warning("No channels detected!")
            return 0, 0
        max_channel = max(counts, key=counts.get)
        return max_channel, counts[max_channel]

    def print_channel_graph_vertical(self) -> None:
        for channel in self._get_channels():
            count = [ap['channel'] for ap in self.__access_points].count(int(channel))
            if count:
                bar = "█" * count if count else '▏'
                logger.info(f"Channel #{channel:2}: {bar} {count}x")

    def print_channel_graph_horizontal(self) -> None:
        counts = self._get_channel_count()
        _, max_channel_amount = self._get_max_used_channel()
        for i in reversed(range(max_channel_amount+2)):
            chars = []
            for channel in sorted(self._get_channels()):
                if i > counts[channel]:
                    char = '    '
                elif i == 0:
                    char = f" {channel:2} "
                elif i == counts[channel]:
                    char = ' ██ '
                elif i < counts[channel] and i > 1:
                    char = ' ██ '
                else:
                    char = ' ██ '
                chars.append(char)
            print(f"  {str(i)+':' if 0 < i <= max_channel_amount else '  '} {''.join(chars)}  ")

    def _print(self, *args, **kwargs) -> None:
        if 'keep' in kwargs:
            end = ''
        else:
            end = '\r'
        if self.__console:
            print(''.join(args), end=end)
