import logging
from .ChannelScanner import ChannelScanner

logger = logging.getLogger('wifi_channel')

def set_wifi_channel(interface: str, app_cfg: dict) -> None:
    if app_cfg['channel'] or app_cfg['channel_set'] or app_cfg['channel_auto']:
        channel_scanner = ChannelScanner(interface)
        if app_cfg['channel_set']:
            channel_scanner.set_channel(app_cfg['channel_set'])
        elif app_cfg['channel_auto'] or app_cfg['channel'].lower() == 'auto':
            channel_scanner.set_auto_channel()
