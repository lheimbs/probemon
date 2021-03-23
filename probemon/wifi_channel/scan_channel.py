import sys
import logging
import argparse
from typing import Union

from . import LOGGER_NAME
# from .misc import can_use_interface
from .channel_scanner import ChannelScanner, CHANNELS, FREQUENCIES

logger = logging.getLogger(LOGGER_NAME)
SUBCMD_ARGS = {
    'action': 'store_const',
    'const': True,
    'default': True,
    'help': argparse.SUPPRESS
}


def parse_args(args: list,
               exit: bool = True) -> Union[argparse.Namespace, None]:
    """Arguments to control the ChannelScanner.

    usage: [-h] [--time TIME] [--graph-type {horizontal,vertical}]
           ... [--verbose | --debug | --console] interface
           ... {set,scan,hop,auto,search,hop_async_no_sniff} ...

    Channel scanner.

    positional arguments:
    interface             Interface to sniff on.

    optional arguments:
    -h, --help            show this help message and exit
    --time TIME, -t TIME  Time in seconds between switching channels.
    --graph-type {horizontal,vertical}
                            If console output is enabled, prints
                            channel graph either horizontally or vertically.
    --verbose, -v         Increase verbosity.
    --debug, -d           Enable debugging output.
    --console, -c         Program runs in console mode,
                          utilising spinners and graphs.

    Modes:
    {set,scan,hop,auto,search,hop_async_no_sniff}
        set                 Set a certain channel.
        scan                Scan channels.
        hop                 Hop between channels
        auto                Scan channels and set current
                            channel to most utilised channel.
        search              Scan channel and search for an AccessPoint
                            with a specific ssid.
                            Set the current channel to that APs channel.
        hop_async_no_sniff  Start a new thread that hops asynchronously
                            and does not sniff data.
    """
    parser = argparse.ArgumentParser(description='Channel scanner.')
    parser.add_argument('interface', help='Interface to sniff on.')

    # ---------- MODES ----------
    # 'set', 'scan', 'hop', 'auto' 'search', 'hop_async_no_sniff'
    modes = parser.add_subparsers(title="Modes", dest='mode')
    setter = modes.add_parser('set', help="Set a certain channel.")
    setter.add_argument(
        'channel',
        type=int, help="Channel number of channel that is supposed to be set."
    )

    modes.add_parser('scan', help="Scan channels.")

    modes.add_parser('hop', help="Hop between channels")

    modes.add_parser(
        'auto',
        help="Scan channels and set current channel to most utilised channel."
    )

    searcher = modes.add_parser('search', help=(
        "Scan channel and search for an AccessPoint with a specific ssid. "
        "Set the current channel to that APs channel."
    ))
    searcher.add_argument('ssid', help="SSID in question.")
    freqs = searcher.add_mutually_exclusive_group()
    freqs.add_argument(
        '--all',
        action="store_const", const=FREQUENCIES._ALL, dest='freq',
        default=FREQUENCIES._ALL, help='Use all available frequencies (default).'
    )
    freqs.add_argument(
        '--2ghz', action="store_const", const=FREQUENCIES._2GHz, dest='freq',
        help='Use only 2GHz frequency channels.'
    )
    freqs.add_argument(
        '--5ghz', action="store_const", const=FREQUENCIES._5GHz, dest='freq',
        help='Use only 5GHz frequency channels.'
    )

    hop_async_no_sniff = modes.add_parser(
        'hop_async_no_sniff',
        help=(
            "Start a new thread that hops "
            "asynchronously and does not sniff data."
        )
    )
    channels = hop_async_no_sniff.add_mutually_exclusive_group()
    channels.add_argument(
        '--all-channels',
        action="store_const", const=CHANNELS._ALL, dest='channels',
        default=CHANNELS._ALL, help='Use all available channels'
    )
    channels.add_argument(
        '--popular',
        action="store_const", const=CHANNELS._POPULAR, dest='channels',
        help='Use most popular 2GHz channels 1, 6 and 12.'
    )
    channels.add_argument(
        '--populated',
        action="store_const", const=CHANNELS._POPULATED, dest='channels',
        help=(
            'Run scan available channels beforehand '
            'and use only populated channels.'
        )
    )
    freqs = hop_async_no_sniff.add_mutually_exclusive_group()
    freqs.add_argument(
        '--all',
        action="store_const", const=FREQUENCIES._ALL, dest='freq',
        default=FREQUENCIES._ALL, help='Use all available frequencies (default).'
    )
    freqs.add_argument(
        '--2ghz', action="store_const", const=FREQUENCIES._2GHz, dest='freq',
        help='Use only 2GHz frequency channels.'
    )
    freqs.add_argument(
        '--5ghz', action="store_const", const=FREQUENCIES._5GHz, dest='freq',
        help='Use only 5GHz frequency channels.'
    )
    hop_async_no_sniff.add_argument(
        '--random', action='store_true', help="Hop randomly between channels."
    )

    parser.add_argument(
        '--time', '-t', type=float, default=1,
        help="Time in seconds between switching channels."
    )
    parser.add_argument(
        '--graph-type', choices=['horizontal', 'vertical'],
        help=(
            "If console output is enabled, "
            "prints channel graph either horizontally or vertically."
        )
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '--verbose', '-v', action='store_true', help="Increase verbosity.",
    )
    group.add_argument(
        '--debug', '-d', action='store_true', help='Enable debugging output.'
    )
    group.add_argument(
        '--console', '-c', action='store_true',
        help='Program runs in console mode. Utilising spinners and graphs.'
    )
    if exit:
        parsed_args = parser.parse_args(args)
    else:
        try:
            parsed_args = parser.parse_args(args)
        except SystemExit:
            parsed_args = None
    return parsed_args


def scan_channels(args=None):        # noqa
    args = parse_args(args if args is not None else sys.argv[1:])
    if args.debug:
        if not logger.hasHandlers():
            logger.addHandler(logging.StreamHandler())
        logger.setLevel(logging.DEBUG)
        logger.debug("Debugging output enabled.")
    elif args.verbose:
        if not logger.hasHandlers():
            logger.addHandler(logging.StreamHandler())
        logger.setLevel(logging.INFO)
    elif args.console:
        logger.setLevel(logging.ERROR)

    channel_scanner = ChannelScanner(
        args.interface, wait_time=args.time, console=args.console,
    )
    # 'set', 'scan', 'hop', 'auto' 'search', 'hop_async_no_sniff'
    if args.mode == 'set':
        channel_scanner.set_channel(args.channel)
    elif args.mode == 'scan':
        channel_scanner.channel_scanner()
    elif args.mode == 'hop':
        channel_scanner.channel_hopper()
    elif args.mode == 'auto':
        channel_scanner.set_auto_channel()
    elif args.mode == 'search':
        channel_scanner.ssid_searcher(args.ssid, args.freq)
    elif args.mode == 'hop_async_no_sniff':
        channel_scanner.channel_hopper_async_no_sniff(
            args.channels,
            args.freq,
            args.random
        )

    if args.console and args.graph_type == 'vertical':
        channel_scanner.print_channel_graph_vertical()
    elif args.console and args.graph_type == 'horizontal':
        channel_scanner.print_channel_graph_horizontal()


if __name__ == '__main__':      # pragma: no cover
    scan_channels()
