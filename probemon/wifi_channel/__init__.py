import logging
from .ChannelScanner import ChannelScanner

logger = logging.getLogger('wifi_channel')

def set_channel(interface: str, params: dict) -> None:
    channel_scanner = ChannelScanner(interface)
    if 'channel_set' in params:
        channel_scanner.set_channel(params['channel_set'])
    elif 'channel_auto' in params:
        channel_scanner.set_auto_channel()
