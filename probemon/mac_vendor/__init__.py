#!/usr/bin/env python3

import json
import logging
import netaddr
import requests

logger = logging.getLogger()

def get_mac_vendor(mac):        # noqa: C901
    URLs = ['http://macvendors.co/api/%s', 'http://www.macvendorlookup.com/api/v2/%s', 'https://api.macvendors.com/%s',]
    vendor = 'UNKNOWN'

    try:
        parsed_mac = netaddr.EUI(mac)
        vendor = parsed_mac.oui.registration().org
    except netaddr.core.NotRegisteredError:
        for url in URLs:
            try:
                r = requests.get(url % mac)
            except Exception:
                r = None
                logger.exception("Request to '{url}' with mac '{mac}' failed.")
            if r and r.status_code == 200:
                try:
                    # print(r.json())
                    res = r.json()
                    if 'error' in res:
                        continue
                    if 'result' in res.keys() and 'company' in res['result'].keys():
                        vendor = res['result']['company']
                        break
                except json.JSONDecodeError:
                    if r.text:
                        vendor = r.text
                        break
    return vendor
