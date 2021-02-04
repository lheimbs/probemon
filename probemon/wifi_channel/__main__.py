#!/usr/bin/env python
# airoscapy.py - Wireless AP scanner based on scapy
# version: 0.2
# Author: iphelix

import logging
import argparse
from ChannelScanner import ChannelScanner

# logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger('channel_scan')

def parse_args():
    parser = argparse.ArgumentParser(description='Channel scanner.')
    parser.add_argument('interface', help='Interface to sniff on.')
    parser.add_argument('mode', choices=['scan', 'hop'], help='Interface to sniff on.')
    parser.add_argument('--time', '-t', type=int, default=1, help="Time in seconds between switching channels.")
    parser.add_argument(
        '--graph-type', choices=['horizontal', 'vertical'],
        help="If console output is enabled, prints channel graph either horizontally or vertically."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--verbose', '-v', action='store_true', help="Increase verbosity.")
    group.add_argument('--debug', '-d', action='store_true', help='Enable debugging output.')
    group.add_argument(
        '--console', '-c', action='store_true',
        help='Program runs in console mode. Utilising spinners and graphs.'
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logger.debug("Debugging output enabled.")
    elif args.verbose:
        logging.basicConfig(level=logging.INFO)
    elif args.console:
        logger.disabled = True
    else:
        logging.basicConfig(level=logging.WARNING)

    channel_scanner = ChannelScanner(args.interface, wait_time=args.time, console=args.console)
    if args.mode == 'scan':
        channel_scanner.channel_scanner()
    else:
        channel_scanner.channel_hopper()

    if args.console:
        if args.graph_type == 'vertical':
            channel_scanner.print_channel_graph_vertical()
        else:
            channel_scanner.print_channel_graph_horizontal()


main()
