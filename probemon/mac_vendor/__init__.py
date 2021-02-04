#!/usr/bin/env python3

import os
import json
import logging
import netaddr
import requests
from maclookup import ApiClient
from maclookup.exceptions.authorization_required_exception import AuthorizationRequiredException

logger = logging.getLogger('mac_vendor')

def get_mac_vendor(mac: str, maclookup_api_key: str = "", unknown_vendor: str = ""):
    vendor = get_netaddr_vendor(mac)
    if vendor:
        return vendor

    vendor = get_maclookup_vendor(mac, maclookup_api_key)
    if vendor:
        return vendor

    vendor = get_macvendors_co_vendor(mac)
    if vendor:
        return vendor

    vendor = get_macvendorlookup_com_vendor(mac)
    if vendor:
        return vendor

    vendor = get_macvendors_com_vendor(mac)
    if vendor:
        return vendor
    return unknown_vendor


def get_netaddr_vendor(mac: str):
    vendor = ''
    logger.debug("Trying module netaddr (fastest, but few entries).")
    try:
        parsed_mac = netaddr.EUI(mac)
        vendor = parsed_mac.oui.registration().org
    except netaddr.core.NotRegisteredError:
        logger.debug(f"netaddr could not find vendor for mac '{mac}'.")
    return vendor


def get_maclookup_vendor(mac: str, maclookup_api_key: str):
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
    else:
        logger.debug("No api key for maclookup supplied.")
    return vendor


def get_macvendorlookup_com_vendor(mac: str):
    vendor = ''
    url = 'http://www.macvendorlookup.com/api/v2/{mac}'.format(mac=mac)
    logger.debug(f"Trying macvendorlookup api ('{url}').")

    try:
        result = requests.get(url, timeout=1.0)
    except requests.exceptions.ConnectTimeout:
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


def get_macvendors_co_vendor(mac: str):
    vendor = ''
    url = 'https://macvendors.co/api/{mac}'.format(mac=mac)
    logger.debug(f"Trying macvendors.co api ('{url}').")
    try:
        result = requests.get(url, timeout=1.0)
    except requests.exceptions.ConnectTimeout:
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


def get_macvendors_com_vendor(mac: str):
    vendor = ''
    url = 'https://api.macvendors.com/{mac}'.format(mac=mac)
    logger.debug(f"Trying macvendors.co api ('{url}').")

    try:
        result = requests.get(url, timeout=1.0)
    except requests.exceptions.ConnectTimeout:
        logger.warning(f"Request to {url} timed out.")
        return vendor

    if result.status_code == 200:
        if '\n' not in result.text and len(result.text) < 100:
            # bit paranoid that the api returns anything other than a simple vendor string
            vendor = result.text
    elif result.status_code == 429:
        logger.warning(f"Rate limit reached for '{url}'.")
    if not vendor:
        logger.debug("Error getting vendor from macvendors.co.")
    return vendor
