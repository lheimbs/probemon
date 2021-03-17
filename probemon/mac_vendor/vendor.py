#!/usr/bin/env python3

import os
import json
import logging
import netaddr
import requests
from maclookup import ApiClient
from maclookup.exceptions.authorization_required_exception \
    import AuthorizationRequiredException
from maclookup.exceptions.not_enough_credits_exception \
    import NotEnoughCreditsException

logger = logging.getLogger(__name__)
logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
logging.getLogger('maclookup-requester').setLevel(logging.WARNING)
REQUEST_TIMEOUT = 2.0

def get_mac_vendor(
    mac: str,
    maclookup_api_key: str = "",
    unknown_vendor: str = "",
    lower: bool = False,
    offline: bool = False,
):
    if not mac:
        logger.debug("Empty mac! Skipping vendor search.")
        return unknown_vendor or os.environ.get('MAC_VENDOR_UNKNOWN', '')

    vendor_funcs = [get_netaddr_vendor]
    if not offline:
        vendor_funcs += [
            get_maclookup_vendor,
            get_macvendors_co_vendor,
            get_macvendorlookup_com_vendor,
            get_macvendors_com_vendor
        ]

    for vendor_func in vendor_funcs:
        vendor = vendor_func(mac, maclookup_api_key)
        if vendor:
            logger.debug(f"Vendor '{vendor}' found for mac '{mac}'")
            return vendor if not lower else vendor.lower()
    return unknown_vendor or os.environ.get('MAC_VENDOR_UNKNOWN', '')


def get_netaddr_vendor(mac: str, *_):
    vendor = ''
    logger.debug("Trying module netaddr (fastest, but few entries).")
    if not mac:
        return vendor

    try:
        parsed_mac = netaddr.EUI(mac)
        vendor = parsed_mac.oui.registration().org
    except netaddr.core.NotRegisteredError:
        logger.debug(f"netaddr could not find vendor for mac '{mac}'.")
    return vendor


def get_maclookup_vendor(mac: str, maclookup_api_key: str):
    """ macaddress.io maclookup api """
    logger.debug("Trying module maclookup (needs api key).")
    vendor = ''
    if not maclookup_api_key:
        maclookup_api_key = os.environ.get('MACLOOKUP_API_KEY', '')

    if maclookup_api_key:
        try:
            client = ApiClient(maclookup_api_key)
            vendor = client.get_vendor(mac).decode()
        except AuthorizationRequiredException:
            logger.warning("Given api key for maclookup is invalid.")
        except NotEnoughCreditsException:
            logger.warning(
                "Maclookups free 1000 daily requests limit reached."
            )
    else:
        logger.debug("No api key for maclookup supplied.")
    return vendor


def get_macvendorlookup_com_vendor(mac: str, *_):
    vendor = ''
    url = 'http://www.macvendorlookup.com/api/v2/{mac}'.format(mac=mac)
    logger.debug(f"Trying macvendorlookup api ('{url}').")

    try:
        result = requests.get(url, timeout=REQUEST_TIMEOUT)
    except (
        requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout,
    ):
        logger.warning(f"Request to {url} timed out.")
        return vendor

    if result.status_code == 200:
        try:
            result = result.json()
        except json.decoder.JSONDecodeError:
            logger.warning("Could not json decode macvendorlookup response.")

        if isinstance(result, list) and result and 'company' in result[0]:
            vendor = result[0]['company']
    elif result.status_code == 429:
        logger.warning(f"Rate limit reached for '{url}'.")
    if not vendor:
        logger.debug("Error getting vendor from macvendorlookup.")
    return vendor


def get_macvendors_co_vendor(mac: str, *_):
    vendor = ''
    url = 'https://macvendors.co/api/{mac}'.format(mac=mac)
    logger.debug(f"Trying macvendors.co api ('{url}').")
    try:
        result = requests.get(url, timeout=REQUEST_TIMEOUT)
    except (
        requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout,
    ):
        logger.warning(f"Request to {url} timed out.")
        return vendor

    if result.status_code == 200:
        try:
            result = result.json()
        except json.decoder.JSONDecodeError:
            logger.warning("Could not json decode macvendors.co response.")

        if 'result' in result and 'company' in result['result']:
            vendor = result['result']['company']
    elif result.status_code == 429:
        logger.warning(f"Rate limit reached for '{url}'.")
    if not vendor:
        logger.debug("Error getting vendor from macvendors.co.")
    return vendor


def get_macvendors_com_vendor(mac: str, *_):
    vendor = ''
    url = 'https://api.macvendors.com/{mac}'.format(mac=mac)
    logger.debug(f"Trying macvendors.co api ('{url}').")

    try:
        result = requests.get(url, timeout=REQUEST_TIMEOUT)
    except (
        requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout,
    ):
        logger.warning(f"Request to {url} timed out.")
        return vendor

    if result.status_code == 200:
        if '\n' not in result.text and len(result.text) < 100:
            # bit paranoid that the api returns anything
            # other than a simple vendor string
            vendor = result.text
    elif result.status_code == 429:
        logger.warning(f"Rate limit reached for '{url}'.")
    if not vendor:
        logger.debug("Error getting vendor from macvendors.co.")
    return vendor
