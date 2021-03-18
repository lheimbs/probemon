import sys
import logging
from socket import socket, AF_PACKET, SOCK_RAW

import netifaces

logger = logging.getLogger(__name__)

def check_interface(interface: str) -> None:
    """ Make sure the supplied interface exists and can be used.

    Exit if not.
    """
    available_interfaces = netifaces.interfaces()
    if interface not in available_interfaces:
        logger.error(
            f"Network interface {interface} does not exist! "
            f"Available interfaces: {', '.join(available_interfaces)}."
        )
        sys.exit("Bad network interface")

    try:
        socket(AF_PACKET, SOCK_RAW)
        return True
    except PermissionError:
        logger.error(
            "Missing permissions to run channel sniffer. Try running as root."
        )
        sys.exit("Root required for scapy to work.")
