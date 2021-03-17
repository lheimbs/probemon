import time
import queue
import logging
import threading
from typing import TypeVar
from collections import ChainMap

from scapy.all import sniff

from .sql import Sql
from .mqtt import Mqtt
from .config import get_config
from .probe_request import ProbeRequest
from .config.cli_options import cli_options
from .wifi_channel import set_wifi_channel
from .wifi_channel.misc import check_interface

logging.basicConfig(
    format=(
        '[%(threadName)-10s] %(name)-30s: '
        '%(funcName)-20s: %(levelname)-8s : %(message)s'
    ),
)
logger = logging.getLogger(__name__)
Session = TypeVar('Session')


@cli_options
def main(
    interface: str, config: str, debug: bool, verbose: bool, **params: dict
):
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif verbose:
        logging.getLogger().setLevel(logging.INFO)

    logger.info(f"Using interface {interface}.")

    app = get_config(config=config, debug=debug, **params)
    check_interface(interface)
    set_wifi_channel(interface, app)

    collect_probes(interface, app)

def collect_probes(interface: str, app_cfg: ChainMap):
    probes_queue = queue.Queue()

    def add_probe_to_queue(packet):
        probes_queue.put_nowait(packet)

    def packet_worker():
        with Mqtt() as mqtt_client:
            while True:
                # Get a probe request packet out of the queue and process it
                probe_time = time.perf_counter()
                packet = probes_queue.get()
                try:
                    probe = ProbeRequest.from_packet(packet)
                    logger.debug(probe)
                    mqtt_client.publish_probe(probe)
                    Sql.publish_probe(probe)
                except BaseException:
                    logger.debug(
                        "Raw packet exception occured on: "
                        f"{packet.original.hex()}"
                    )
                    logger.exception("Exception occured processing packet:")
                finally:
                    logger.debug(
                        f"{threading.currentThread().getName()} "
                        "processed probe request in "
                        f"{time.perf_counter() - probe_time:.2f}s."
                    )
                    # Notify the queue that the probe has been processed.
                    probes_queue.task_done()

    logger.debug(
        f"Spawning {app_cfg['worker_threads']} "
        f"daemon thread{'s' if app_cfg['worker_threads'] > 1 else ''} "
        "to process collected probes."
    )
    for _ in range(app_cfg['worker_threads']):
        t = threading.Thread(target=packet_worker, daemon=True)
        t.start()

    logger.info("Start collecting probe requests...")
    s = time.perf_counter()
    try:
        sniff(
            iface='mon0',
            count=app_cfg['count'] if app_cfg['count'] else 0,
            filter='subtype probe-req',
            prn=add_probe_to_queue,
        )
    finally:
        remaining_probes = probes_queue.qsize()
        logger.debug(
            f"Sniffed for {time.perf_counter() - s:.2f} seconds. "
            f"Probes in queue: {remaining_probes}, active worker threads: "
            f"{threading.active_count() - 1}."
        )
        s = time.perf_counter()
        if remaining_probes > 0:
            if threading.active_count() < 2:
                logger.error(
                    "Error occured processing probes. "
                    f"Manually printing {remaining_probes} probes."
                )
                while not probes_queue.empty():
                    packet = probes_queue.get()
                    probe = ProbeRequest.from_packet(packet, get_vendor=False)
                    logger.info(str(probe))
                    probes_queue.task_done()
            else:
                logger.info(
                    f"Please wait while aprox. {remaining_probes} remaining "
                    "probes are getting processed..."
                )
        logger.debug("Joining queue...")
        probes_queue.join()
        logger.debug(
            f"Processing took {time.perf_counter() - s:.2f} seconds."
            " Bye."
        )
