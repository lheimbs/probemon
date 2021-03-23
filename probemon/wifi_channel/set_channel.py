import logging
from . import LOGGER_NAME
from .scan_channel import scan_channels

logger = logging.getLogger(LOGGER_NAME)


def is_float(n: str) -> bool:
    try:
        float(n)
        return True
    except ValueError:
        return False


def is_int(n: str) -> bool:
    try:
        int(n)
        return True
    except ValueError:
        return False


def is_arg_valid(arg):
    allowed_args = [
        'set', 'scan', 'hop', 'auto', 'search', 'hop_async_no_sniff',
        '--all', '--2ghz', '--5ghz',
        '--all-channels', '--popular', '--populated',
        '--time', '--random', '--help'
    ]
    if arg in allowed_args:
        return True
    if is_int(arg):
        return True
    if is_float(arg):
        return True
    return False


def set_wifi_channel_from_args(interface: str, app_cfg: dict) -> bool:
    if 'channel' in app_cfg and app_cfg['channel']:
        args = app_cfg['channel'].split(' ')

        vaild_args = [interface]
        for arg in args:
            if arg.startswith('SSID:'):
                vaild_args.append(arg.replace('SSID:', ''))
            elif is_arg_valid(arg):
                vaild_args.append(arg)

        scan_channels(args=vaild_args)
        return True
    return False


# def get_channel_setting(app_cfg: dict) -> Tuple[str, TypeVar]:
#     settings = {}
#     for setting, value in app_cfg.items():
#         if setting.startswith('channel'):
#             setting = setting.replace('channel_', '')
#             if setting not in settings:
#                 settings.update({setting: []})
#             if isinstance(value, tuple):
#                 if all([val is not None for val in value]):
#                     settings[setting].append(value)
#             else:
#                 if value is not None:
#                     settings[setting].append(value)
#     return settings


# def set_wifi_channel(interface: str, app_cfg: dict) -> None:
#     setting, value = get_channel_setting(app_cfg)
#     logger.debug(f"Channel setting: '{setting}' with args: '{value}'.")

#     if not setting:
#         return

#     channel_scanner = ChannelScanner(interface)
#     if setting == 'auto':
#         channel_scanner.set_auto_channel()
#     elif setting == 'set':
#         channel_scanner.set_channel(value)
#     elif setting == 'hop':
#         channel_scanner.channel_hopper_async_no_sniff(
#             channels=False, frequency=False,
#             hop_time=value[0], random=value[1]
#         )
#     elif setting == 'ssid_select':
#         channel_scanner.ssid_searcher(ssid=value)
