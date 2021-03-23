import re
import sys
import json
import time
import shlex
import random
import logging
import threading
import subprocess
from enum import Enum
from typing import Callable, List, Tuple
from scapy.error import Scapy_Exception
from scapy.layers.dot11 import RadioTap, Dot11Beacon, Dot11ProbeResp
from scapy.all import AsyncSniffer
from . import misc
from . import LOGGER_NAME

logger = logging.getLogger(LOGGER_NAME)

class FREQUENCIES(Enum):
    _ALL = None
    _2GHz = True
    _5GHz = False


class CHANNELS(Enum):
    _ALL = None
    _POPULAR = True
    _POPULATED = False


class ChannelScanner:
    def __init__(self,
                 interface: str,
                 wait_time: int = 1,
                 console: bool = False) -> None:
        misc.can_use_interface(interface)
        misc.can_use_iw()
        self._interface: str = interface
        self._sniffer: AsyncSniffer = AsyncSniffer(
            iface=self._interface, prn=self._sniff_packet()
        )
        self._available_channels: List[int] = []
        self._access_points: list[misc.AccessPoint] = []
        self._wait_time: float = wait_time
        self._console: bool = console

    """ ---------- SNIFFER CONTROL ---------- """
    def _start_sniffer(self) -> bool:
        """Try to start scapy AsyncSniffer if it is not already running.

        Returns the sniffers running state.
        """
        if not self._sniffer.running:
            self._sniffer.start()
        return self._sniffer.running

    def _stop_sniffer(self) -> bool:
        """Try to stop the sniffer.

        If the sniffer can't be stopped, terminate the program
        in order to release all daemon threads which could potentially
        turn into memory hogs.
        Returns the runing state of the sniffer.
        """
        try:
            if self._sniffer.running:
                self._sniffer.stop()
            return self._sniffer.running
        except Scapy_Exception:
            logger.critical(
                "ERROR stopping scapy AsyncSniffer! Terminating program.",
                exc_info=True
            )
            sys.exit("ERROR stopping scapy AsyncSniffer! Terminating program.")

    """ ---------- AVAILABLE CHANNELS ---------- """
    def _get_channels(self) -> list:
        """Call 'iw list' and parse channels listed channels of iface.

        This is definitely not optimal, because of iw-dependency and
        because ist based on only one 'phy' entry.
        But since I have not found a better solution yet...
        """
        if not self._available_channels:
            logger.debug("Getting channels for local wifi adapter.")
            CHANNEL_REGEX = re.compile(
                r"\*\s(?P<frequency>\d{4})\sMHz\s\[(?P<channel>\d{1,3})\]"
            )
            proc = subprocess.run(
                ['iw', 'list'], stdout=subprocess.PIPE, encoding='utf-8',
            )
            channels = set()
            for line in proc.stdout.splitlines():
                m = CHANNEL_REGEX.search(line)
                if m and '(disabled)' not in line:
                    channels.add(int(m.group('channel')))
            self._available_channels = sorted(list(channels))
        return self._available_channels

    def _get_channels_by_frequency(
            self,
            frequency: FREQUENCIES = FREQUENCIES._ALL,
            channels: list = None) -> list:
        """Get available channels by frequency.

        Keyword arguments:
        frequency -- True: return the 2GHz spectrum.
                     False: return the 5GHz spectrum.
                     None: return all frequencies.
        channels -- List of preselected channels to use instead of all
                    available.
        """
        channels_list = channels if channels else self._get_channels()
        if frequency is FREQUENCIES._2GHz:
            channels_list = list(filter(lambda x: x < 15, channels_list))
        elif frequency is FREQUENCIES._5GHz:
            channels_list = list(filter(lambda x: x > 14, channels_list))
        return channels_list

    """ ---------- CALLBACKS ---------- """
    def _sniff_packet(self) -> Callable:
        """Process and save unique sniffed Beacons and ProbeResponses.

        Returns a Callable that has access to 'self' where the
        recorded data is saved.
        APs that use the same channel/bssid/ssid/encryption are counted.
        """
        def parse_sniffed_packet(packet: RadioTap):
            if packet.haslayer(Dot11Beacon) \
                    or packet.haslayer(Dot11ProbeResp):
                # Save discovered AP
                ap = misc.AccessPoint(packet)
                for found_ap in self._access_points:
                    if ap == found_ap:
                        found_ap.count += 1
                        break
                else:
                    self._access_points.append(ap)
                # Display discovered AP
                logger.debug(f"Detected AP {json.dumps(ap.__dict__)}")
        return parse_sniffed_packet

    def _async_hopper(self,
                      channels_list: List,
                      random_hops: bool) -> Callable:
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
                time.sleep(self._wait_time)
        return hopper

    """ ---------- RECORDING ANALYSIS ---------- """
    def _get_max_used_channel(self, ssid: str = '') -> Tuple[int, int]:
        """Get the most used channel along with its count.

        If ssid is supplied, consider only those entries with that ssid.
        Returns: <channel>, <count of channel>
        """
        channel, channel_used_max = 0, 0
        for ap in self._access_points:
            if (ssid == ap.ssid or not ssid) and ap.channel > 0:
                if ap.count > channel_used_max:
                    channel, channel_used_max = ap.channel, ap.count
        return channel, channel_used_max

    def _get_channels_with_count(self, skip_zero: bool = True) -> dict:
        """Get the scanned channels along with their count.

        Add missing channels with count=0 if skip_zero is False.
        """
        channels = {}
        for ap in self._access_points:
            if ap.channel > 0:
                if ap.channel in channels:
                    channels[ap.channel] += 1
                else:
                    channels.update({ap.channel: ap.count})

        if not skip_zero:
            for channel in self._get_channels():
                if channel not in channels:
                    channels.update({channel: 0})
        return channels

    """ ---------- OUTPUT HELPERS ---------- """
    def _print(self, *args, **kwargs) -> None:
        if self._console:
            end = '\r' if 'keep' in kwargs and kwargs['keep'] else '\n'
            print(''.join(args), end=end)
        else:
            if 'level' in kwargs:
                logger.log(kwargs['level'], ''.join(args))

    def print_channel_utilization(self) -> int:
        counts = self._get_channels_with_count()
        (
            max_used_channel, max_used_channel_amount
        ) = self._get_max_used_channel()
        found_channels = ', '.join(
            [f'channel {ch}: {num}x' for ch, num in counts.items()]
        )
        channel_info = (
            f"Found {found_channels}. Channel {max_used_channel} "
            f"is the most populated ({max_used_channel_amount} APs)."
        ) if counts else "Found zero APs and therefore no channel info."

        self._print(channel_info, level=logging.INFO)
        return max_used_channel

    def print_channel_graph_vertical(self) -> None:
        """Print vertical graph for amount of collected APs per channel"""
        channels = self._get_channels_with_count()
        for channel, count in channels.items():
            bar = "█" * count if count else '▏'
            line = f"Channel #{channel:2}: {bar} {count}x"
            self._print(line, level=logging.INFO)

    def print_channel_graph_horizontal(self) -> None:
        """Print horizontal graph for amount of collected APs per channel"""
        counts = self._get_channels_with_count()
        if not counts:
            return
        max_channel_amount = max(counts.values())
        for i in reversed(range(max_channel_amount+2)):
            chars = []
            for channel in counts:
                if i == 0:
                    char = f" {channel:2} "
                elif i > counts[channel]:
                    char = '    '
                else:
                    char = ' ██ '
                chars.append(char)
            spaceholder = f'{i:2}:' if 0 < i <= max_channel_amount else '   '
            line = f"  {spaceholder} {''.join(chars)}  "
            self._print(line, level=logging.INFO)

    """ ---------- RUNNERS ---------- """
    def set_channel(self, channel: int) -> bool:
        """Set the channel on the specified wifi interface."""
        if channel not in self._get_channels():
            logger.error(f"Channel {channel} not available!")
            return False

        cmd = "iw dev {} set channel {}".format(self._interface, channel)
        proc = subprocess.run(
            shlex.split(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding='utf-8',
        )
        if proc.returncode == 0:
            self._print(
                f"Interface '{self._interface}' set to channel {channel:4}.",
                keep=True, level=logging.INFO
            )
            return True
        # else:
        stdout = " ".join(proc.stdout.splitlines())
        logger.error(
            f"Failed setting channel {channel} on "
            f"interface '{self._interface}': '{stdout}'"
        )
        return False

    def channel_scanner(self) -> int:
        """Scan all available channels, collect all APs and report usage.

        Sequentially iterate over avaliable channels, waiting between
        every step. At the end print the detected channel usage.
        Returns the most used channel.
        """
        channels = self._get_channels()
        if not channels or not self._start_sniffer():
            return 0
        self._print("Start channel scan...", level=logging.INFO)
        try:
            for channel in channels:
                try:
                    self.set_channel(channel)
                    time.sleep(self._wait_time)
                except KeyboardInterrupt:
                    break
        finally:
            self._stop_sniffer()
        return self.print_channel_utilization()

    def channel_hopper(self) -> int:
        """Randomly jump between avaliable channels forever.

        Randomly jump between avaliable channels, waiting after
        every jump unit Interrupted by Keyboard.
        At the end print the detected channel usage.
        Returns the most used channel.
        """
        channels = self._get_channels()
        if not channels or not self._start_sniffer():
            return 0
        self._print("Start channel hopping...", level=logging.INFO)
        try:
            while True:
                try:
                    channel = random.choice(list(channels))
                    self.set_channel(channel)
                    time.sleep(self._wait_time)
                except KeyboardInterrupt:
                    break
        finally:
            self._stop_sniffer()
        return self.print_channel_utilization()

    def channel_hopper_async_no_sniff(
            self,
            channels: CHANNELS = CHANNELS._ALL,
            frequency: FREQUENCIES = FREQUENCIES._ALL,
            random_hops: bool = True) -> None:
        """Start a Thread that changes the channel asynchronously.

        The Thread is a daemon, so it runs as long as the calling
        Program is running.
        It can either use all available channels, only the 2GHz or 5GHz
        spectrum, the most popular or run the channel_scanner
        before launching the Thread, which selects only the recorded channels
        as channels to choose from.

        Keyword arguments:
        channels -- True: Use most popular 2GHz channels 1, 6 and 12.
                    False: Run channel_scanner and use only populated channels.
                    None: Use all available channels (default).
        frequency -- True: return the 2GHz spectrum.
                     False: return the 5GHz spectrum.
                     None: return all frequencies (default).
        random_hops -- True: Hop randomly between available channels.
                       False: Run sequentially through the avaiable channels.
        """
        if channels is CHANNELS._POPULAR:
            channels_list = [1, 6, 12]
        elif channels is CHANNELS._POPULATED:
            self.channel_scanner()
            channels = self._get_channels_with_count()
            channels_list = list(channels.keys())
        else:
            channels_list = self._get_channels()

        channels_list = self._get_channels_by_frequency(
            frequency, channels_list
        )

        self._print("Starting channel hopper thread...", level=logging.INFO)
        threading.Thread(
            target=self._async_hopper(channels_list, random_hops),
            daemon=True
        ).start()

    def set_auto_channel(self) -> bool:
        """Set NICs channel to the most used one."""
        self._print("Scanning for available channels...", level=logging.INFO)
        max_used_channel = self.channel_scanner()
        return self.set_channel(max_used_channel)

    def ssid_searcher(self,
                      ssid: str,
                      frequency: FREQUENCIES = FREQUENCIES._ALL) -> int:
        """Scan channels sequentially and set channel to AP with ssid.

        Iterate over available channels, wait an amount of time during
        which time all beacons and probes are getting collected.
        After the loop check if the ssid exists among the recorded APs:

        Select the channel under which the ssid was recieved.
        If the ssid is used within multiple channels, select the channel
        under which the most beacons/probes got recieved.
        If its a tie beween channel counts, the lowest channel is selected.
        If the ssid does not appear in the recorded beacons/probes,
        select the most used channel regardless of ssid.

        When a channel is determined, set the selected interfaces channel
        accordingly.

        Keyword arguments:
        frequency -- True: return the 2GHz spectrum.
                     False: return the 5GHz spectrum.
                     None: return all frequencies.
        Returns:
        The channel that was set - regardless of a found ssid.
        0 if no channels at all were found/set.
        """
        channels_list = self._get_channels_by_frequency(frequency)
        self._start_sniffer()
        try:
            for channel in channels_list:
                self.set_channel(channel)
                time.sleep(self._wait_time)
        finally:
            self._stop_sniffer()
        channel, channel_amount = self._get_max_used_channel(ssid)
        if channel_amount:
            self._print(
                f"Channel {channel} used {channel_amount}x for SSID {ssid}.",
                level=logging.INFO
            )
        else:
            # Get max used channel for all ssids.
            channel, channel_amount = self._get_max_used_channel()
            self._print(
                f"SSID {ssid} not found. "
                f"Setting most used channel {channel} ({channel_amount}x).",
                level=logging.INFO
            )
        if channel:
            self.set_channel(channel)
        return channel
