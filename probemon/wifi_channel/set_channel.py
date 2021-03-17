import logging
from .channel_scanner import ChannelScanner

logger = logging.getLogger(__name__)

def set_wifi_channel(interface: str, app_cfg: dict) -> None:
    channel = app_cfg['channel'] if 'channel' in app_cfg.keys() else ""
    if channel or app_cfg['channel_set'] \
            or app_cfg['channel_auto'] or app_cfg['channel_hop']:
        channel_scanner = ChannelScanner(interface)
        if app_cfg['channel_set']:
            channel_scanner.set_channel(app_cfg['channel_set'])
        elif app_cfg['channel_auto'] or channel.lower() == 'auto':
            channel_scanner.set_auto_channel()
        elif app_cfg['channel_hop'] or channel.lower() == 'hop':
            if app_cfg['channel_hop']:
                hop_time = app_cfg['channel_hop']
            elif 'channel_hop_time' in app_cfg.keys() and \
                    app_cfg['channel_hop_time']:
                hop_time = float(app_cfg['channel_hop_time'])
            else:
                hop_time = 1
            channel_scanner.channel_hopper_async_no_sniff_2GHz_most_common(
                hop_time=hop_time
            )
