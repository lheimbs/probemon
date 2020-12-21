#!/usr/bin/env python3

import sys
import time
import json
import struct
import logging
import argparse
import paho.mqtt.client as mqtt
from datetime import datetime
from scapy.all import sniff

from mac_vendor import get_mac_vendor

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(format='File "%(pathname)-75s", line %(lineno)-3d, in %(funcName)-20s: %(levelname)-8s : %(message)s', level=logging.INFO)
logger = logging.getLogger()

client = mqtt.Client()
sensor_data = {'macaddress': "", 'time': "", 'make': "", 'ssid': "", 'rssi': 0}

def parse_rssi(packet):
    # parse dbm_antsignal from radiotap header
    # borrowed from python-radiotap module
    radiotap_header_fmt = '<BBHI'
    radiotap_header_len = struct.calcsize(radiotap_header_fmt)
    version, pad, radiotap_len, present = struct.unpack_from(
        radiotap_header_fmt, packet)

    start = radiotap_header_len
    bits = [int(b) for b in bin(present)[2:].rjust(32, '0')]
    bits.reverse()
    if bits[5] == 0:
        return 0

    while present & (1 << 31):
        present, = struct.unpack_from('<I', packet, start)
        start += 4
    offset = start
    if bits[0] == 1:
        offset = (offset + 8 - 1) & ~(8 - 1)
        offset += 8
    if bits[1] == 1:
        offset += 1
    if bits[2] == 1:
        offset += 1
    if bits[3] == 1:
        offset = (offset + 2 - 1) & ~(2 - 1)
        offset += 4
    if bits[4] == 1:
        offset += 2
    dbm_antsignal, = struct.unpack_from('<b', packet, offset)
    return dbm_antsignal


def build_packet_callback(logger, mqtt_topic):
    def packet_callback(packet):

        # we are looking for management frames with a probe subtype
        # if neither match we are done here
        if packet.type != 0 or packet.subtype != 0x04 or packet.type is None:
            return

        if sys.version_info > (3,):
            rssi_val = parse_rssi(memoryview(bytes(packet)))
        else:
            rssi_val = parse_rssi(buffer(str(packet)))

        sensor_data['macaddress'] = packet.addr2
        sensor_data['time'] = datetime.now().isoformat()
        sensor_data['ssid'] = packet.info.decode(encoding='utf-8', errors='replace')
        sensor_data['rssi'] = rssi_val

        logger.info(sensor_data)
        if client.is_connected():
            client.publish(mqtt_topic, json.dumps(sensor_data), 1)
    return packet_callback


def main():
    parser = argparse.ArgumentParser(description="Command line tool for logging 802.11 probe request frames")
    parser.add_argument('-i', '--interface', help="capture interface")
    parser.add_argument('-x', '--mqtt-broker', default='',
                        help="mqtt broker server")
    parser.add_argument('-o', '--mqtt-port', default='1883',
                        help="mqtt broker port")
    parser.add_argument('-u', '--mqtt-user', default='', help="mqtt user")
    parser.add_argument('-p', '--mqtt-password',
                        default='', help="mqtt password")
    parser.add_argument('-m', '--mqtt-topic',
                        default='probemon/request', help="mqtt topic")
    args = parser.parse_args()

    if not args.interface:
        logger.error("Capture interface missing. Add an interface using -i <interface> or try --help")
        sys.exit(-1)

    logger.info("Script started...")

    if args.mqtt_user and args.mqtt_password:
        logger.info(f"Set mqtt username to {args.mqtt_user} and set mqtt password.")
        client.username_pw_set(args.mqtt_user, args.mqtt_password)

    if args.mqtt_broker:
        logger.info(f"Connect to mqtt broker {args.mqtt_broker} on port {int(args.mqtt_port)}.")
        client.connect(args.mqtt_broker, int(args.mqtt_port), 1)
        client.loop_start()

    built_packet_cb = build_packet_callback(logger, args.mqtt_topic)
    sniff(iface=args.interface, prn=built_packet_cb, store=0, monitor=True)


if __name__ == '__main__':
    main()
