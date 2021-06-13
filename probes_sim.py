import time
from datetime import datetime, timedelta

import pytz

from probemon.url_publish import UrlDaemon
from probemon.probe_request import ProbeRequest

SOURCE = "11:22:33:44:55:66"
DEST = "ff:ff:ff:ff:ff:ff"
RSSI = -50

def get_probe(now: datetime) -> ProbeRequest:
    if not now.tzinfo:
        now = pytz.timezone("Europe/Berlin").localize(now)
    return ProbeRequest(
        time=now,
        mac=SOURCE
    )

def main():
    intervals = [0, 30, 10, 500, 500, 500, 60*60-20, ((60*60)//2)+2, 60*60+1]

    UrlDaemon(url="http://127.0.0.1:8000/control/probes/add", token="0d4cde798fbe959ac34687bf8d41120ed204ed1c").start()

    now = datetime.now()
    for interval in intervals:
        print("Publish ", interval)
        UrlDaemon.add(get_probe(now + timedelta(seconds=interval)))
        time.sleep(1)


if __name__ == '__main__':
    main()
