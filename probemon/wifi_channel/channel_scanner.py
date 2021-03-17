import re
import json
import time
import shlex
import random
import logging
import threading
import subprocess
from typing import Callable, Sequence, Tuple
from scapy.error import Scapy_Exception
from scapy.layers.dot11 import RadioTap
from scapy.all import (
    Dot11Beacon, Dot11ProbeResp, Dot11, Dot11Elt, AsyncSniffer
)
logger = logging.getLogger(__name__)

class ChannelScanner:
    def __init__(
        self, interface: str, wait_time: int = 1, console: bool = False,
    ):
        self._interface = interface
        self.__sniffer = AsyncSniffer(
            iface=self._interface, prn=self.sniff_packet()
        )
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
            logger.error(
                "Something failed stopping scapy sniffer. "
                "Try running as root."
            )
            return False

    def _get_channels(self) -> list:
        if not self.__available_channels:
            logger.debug("Getting channels for local wifi adapter.")
            CHANNEL_REGEX = re.compile(
                r"\*\s(?P<frequency>\d{4})\sMHz\s\[(?P<channel>\d{1,3})\]"
            )
            proc = subprocess.run(
                ['iw', 'list'], stdout=subprocess.PIPE, encoding='utf-8',
            )
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
        proc = subprocess.run(
            shlex.split(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding='utf-8',
        )
        if proc.returncode == 0:
            ret_val = True
            logger.info(
                f"Interface '{self._interface}' set to channel {channel}."
            )
        else:
            ret_val = False
            stdout = " ".join(proc.stdout.splitlines())
            logger.error(
                f"Failed setting channel {channel} on "
                f"interface '{self._interface}': '{stdout}'"
            )

        self._print(
            f"Scan channel {channel:2}...",
            f"{len(set(self._get_scanned_channels())):3}"
            " distinct channels found..."
        )
        return ret_val

    def sniff_packet(self) -> Callable:
        """ process unique sniffed Beacons and ProbeResponses """
        def parse_sniffed_packet(packet: RadioTap):
            if (
                (packet.haslayer(Dot11Beacon)
                    or packet.haslayer(Dot11ProbeResp))
                and packet[Dot11].addr3 not in [
                    ap['bssid'] for ap in self.__access_points
                ]
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

    def get_channel_utilization(self) -> int:
        counts = self._get_channel_count(skip_zero=True)
        (
            max_used_channel, max_used_channel_amount
        ) = self._get_max_used_channel()
        found_channels = ', '.join(
            [f'channel {ch}: {num}x' for ch, num in counts.items()]
        )
        channel_info = (
            f"Found {found_channels}. Channel {max_used_channel} "
            f"is the most populated ({max_used_channel_amount} APs)."
        ) if counts else "Found zero aps and therefore zero channel info."

        logger.info(channel_info)
        self._print(channel_info, keep=True)
        return max_used_channel

    def _async_hopper(
        self, channels_list: Sequence, hop_time: float, random_hops: bool,
    ):
        def hopper():
            channel_nr = 0
            while True:
                if random_hops:
                    channel = random.choice(channels_list)
                else:
                    if channel_nr >= len(channels_list):
                        channel_nr = 0
                    channel = channels_list[channel_nr]
                    channel_nr += 1
                self.set_channel(channel)
                time.sleep(hop_time)
        return hopper

    def _get_scanned_channels(self) -> list:
        return [
            ap['channel'] for ap in self.__access_points
            if 'channel' in ap.keys()
        ]

    def _get_scanned_ssids(self) -> set:
        return {
            ap['ssid'] for ap in self.__access_points
            if 'ssid' in ap.keys()
        }

    def _get_scanned_ssid_channels(self) -> dict:
        ssid_dict = {}
        for ap in self.__access_points:
            if 'ssid' in ap.keys() and 'channel' in ap.keys():
                if ap['ssid'] in ssid_dict.keys():
                    if ap['channel'] in ssid_dict[ap['ssid']].keys():
                        ssid_dict[ap['ssid']][ap['channel']] += 1
                    else:
                        ssid_dict[ap['ssid']][ap['channel']] = 1
                else:
                    ssid_dict.update({ap['ssid']: {ap['channel']: 1}})
        return ssid_dict

    def _get_channel_count(self, skip_zero: bool = False) -> dict:
        scanned_channels = self._get_scanned_channels()
        counted_channels = {}
        for channel in self._get_channels():
            count = scanned_channels.count(channel)
            if skip_zero and count <= 0:
                continue
            counted_channels.update({channel: count})
        return counted_channels

    def _get_max_used_channel(self) -> Tuple[int, int]:
        """Count and rank occurence of each channel per AP in recived beacons.
        returns: most used channel, number of times the channel is used
        """
        counts = self._get_channel_count(skip_zero=True)
        if not counts:
            logger.warning("No channels detected!")
            return 0, 0
        max_channel = max(counts, key=counts.get)
        return max_channel, counts[max_channel]

    def _get_max_scanned_channel(self, scanned: dict) -> Tuple[int, int]:
        """Sort channels by their occurence ascending.
        return: <channel number>, <number channel occurences>"""
        return sorted(scanned.items(), key=lambda item: item[1])[-1]

    def print_channel_graph_vertical(self) -> None:
        for channel in self._get_channels():
            count = [
                ap['channel'] for ap in self.__access_points
            ].count(int(channel))
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
            spaceholder = str(i)+':' if 0 < i <= max_channel_amount else '  '
            print(f"  {spaceholder} {''.join(chars)}  ")

    def _print(self, *args, **kwargs) -> None:
        if 'keep' in kwargs:
            end = ''
        else:
            end = '\r'
        if self.__console:
            print(''.join(args), end=end)

    def channel_scanner(self) -> int:
        """ Channel scanner """
        if not self._start_sniffer():
            return 0
        logger.info("Start channel scan...")
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

    def channel_hopper_async_no_sniff(
        self, only_populated_channels: bool,
        hop_time: float = 1.0,
        random_hops: bool = True,
    ) -> None:
        if only_populated_channels:
            self.channel_scanner()
            channels = self._get_channel_count(skip_zero=True)
            channels_list = list(channels.keys())
        else:
            channels_list = self._get_channels()

        logger.info("Starting channel hopper thread...")
        threading.Thread(
            target=self._async_hopper(channels_list, hop_time, random_hops),
            daemon=True
        ).start()

    def channel_hopper_async_no_sniff_2GHz(
        self, hop_time: float = 1.0, random_hops: bool = True,
    ) -> None:
        channels_list = [chan for chan in self._get_channels() if chan < 14]

        logger.info("Starting channel hopper thread...")
        threading.Thread(
            target=self._async_hopper(channels_list, hop_time, random_hops),
            daemon=True
        ).start()

    def channel_hopper_async_no_sniff_2GHz_most_common(
        self, hop_time: float = 1.0, random: bool = False
    ) -> None:
        channels_list = [1, 6, 12]

        logger.info("Starting channel hopper thread...")
        threading.Thread(
            target=self._async_hopper(channels_list, hop_time, random),
            daemon=True
        ).start()

    def set_auto_channel(self) -> bool:
        logger.info("Scanning for available channels...")
        max_used_channel = self.channel_scanner()
        return self.set_channel(max_used_channel)

    def ssid_searcher(self, ssid: str, only_2ghz: bool = True) -> None:
        start = time.perf_counter()
        if only_2ghz:
            max_chan = 15
        else:
            max_chan = 9999
        channels_list = [
            chan for chan in self._get_channels() if chan < max_chan
        ]
        self._start_sniffer()
        while time.perf_counter() - start < 30:
            # 30s max for scanning
            for channel in channels_list:
                self.set_channel(channel)
                time.sleep(self.__wait_time)
            if ssid in self._get_scanned_ssids():
                break
        scanned = self._get_scanned_ssid_channels()
        if ssid in scanned:
            channel, n_channel = self._get_max_scanned_channel(scanned[ssid])
            logger.info(
                f"Channel {channel} found {n_channel}x for SSID {ssid}."
            )
            pass
        else:
            channel, n_channel = self._get_max_used_channel()
            logger.info(
                f"SSID {ssid} not found. "
                f"Setting most used channel: {channel} (used {n_channel}x)."
            )
        self.set_channel(channel)
