import logging
from typing import Tuple, TypeVar
from .channel_scanner import ChannelScanner

logger = logging.getLogger(__name__)


def get_channel_setting(app_cfg: dict) -> Tuple[str, TypeVar]:
    for setting, value in app_cfg.items():
        if setting.startswith('channel'):
            setting = setting.replace('channel_', '')
            if isinstance(value, tuple):
                if all([val is not None for val in value]):
                    return setting, value
            else:
                if value is not None:
                    return setting, value
    return '', None


def set_wifi_channel(interface: str, app_cfg: dict) -> None:
    setting, value = get_channel_setting(app_cfg)
    logger.debug(f"Channel setting: '{setting}' with args: '{value}'.")

    if not setting:
        return

    channel_scanner = ChannelScanner(interface)
    if setting == 'auto':
        channel_scanner.set_auto_channel()
    elif setting == 'set':
        channel_scanner.set_channel(value)
    elif setting == 'hop':
        channel_scanner.channel_hopper_async_no_sniff_2GHz_most_common(
            hop_time=value[0], random=value[1]
        )
    elif setting == 'ssid_select':
        channel_scanner.ssid_searcher(ssid=value)
