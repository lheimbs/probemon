import time
import queue
import logging
import threading
from typing import TypeVar

import click
from scapy.all import sniff

from probemon.sql import SqlDaemon
from probemon.mqtt import MqttDaemon
from probemon.url_publish import UrlDaemon
from probemon.config import get_config
from probemon.probe_request import ProbeRequest
from probemon.config.cli_options import cli_options, cli_mqtt_options, cli_server_publish_options, cli_sql_options
from probemon.wifi_channel import set_wifi_channel_from_args
from probemon.wifi_channel.misc import can_use_interface
from probemon.config.misc import MissingChainMap

logging.basicConfig(
    format=(
        '[%(threadName)-10s] %(name)-30s: '
        '%(funcName)-30s: %(levelname)-8s : %(message)s'
    ),
)
logger = logging.getLogger(__name__)
Session = TypeVar('Session')

@click.command()
@cli_options
@cli_mqtt_options
@cli_sql_options
@cli_server_publish_options
def main(interface: str,
         config: str,
         debug: bool,
         verbose: bool,
         **params: dict) -> None:
    app = get_config(config=config, debug=debug, verbose=verbose, **params)
    logger.info(f"Using interface {interface}.")
    can_use_interface(interface)
    set_wifi_channel_from_args(interface, app)
    collect_probes(interface, app)


packet_queue = queue.Queue()

def add_packet_to_queue(packet):     # pragma: no cover
    packet_queue.put_nowait(packet)


def packet_worker():
    while True:
        # Get a probe request packet out of the queue and process it
        probe_time = time.perf_counter()
        packet = packet_queue.get()
        try:
            probe = ProbeRequest.from_packet(packet)
            logger.debug(probe)
            MqttDaemon.add(probe)
            SqlDaemon.add(probe)
            UrlDaemon.add(probe)
        except BaseException:
            logger.exception(
                "Exception occured processing packet: "
                f'"{packet.original.hex()}"'
            )
        finally:
            logger.debug(
                f"{threading.currentThread().getName()} "
                "processed probe request in "
                f"{time.perf_counter() - probe_time:.2f}s."
            )
            # Notify the queue that the probe has been processed.
            packet_queue.task_done()        # pragma: no cover


def collect_probes(interface: str, cfg: MissingChainMap):
    n_worker_threads = cfg['worker_threads'] if cfg['worker_threads'] else 1
    logger.debug(
        f"Spawning {n_worker_threads} "
        "daemon thread/s to process collected probes."
    )
    for _ in range(n_worker_threads):
        t = threading.Thread(target=packet_worker, daemon=True)
        t.start()

    logger.info("Start publisher daemons...")
    MqttDaemon(daemon=True).start()
    SqlDaemon(daemon=True).start()
    UrlDaemon(url=cfg['url_publish_url'], token=cfg['url_publish_token']).start()

    logger.info("Start collecting probe requests...")
    s = time.perf_counter()

    try:
        sniff(
            iface='mon0',
            count=cfg['count'] if cfg['count'] else 0,
            filter='subtype probe-req',
            prn=add_packet_to_queue,
        )
    finally:
        remaining_probes = packet_queue.qsize()
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
                while not packet_queue.empty():
                    packet = packet_queue.get()
                    probe = ProbeRequest.from_packet(packet, get_vendor=False)
                    logger.info(str(probe))
                    packet_queue.task_done()
            else:
                logger.info(
                    f"Please wait while aprox. {remaining_probes} remaining "
                    "probes are getting processed..."
                )
        logger.debug("Joining queue...")
        packet_queue.join()
        logger.debug(
            f"Processing took {time.perf_counter() - s:.2f} seconds."
            " Bye."
        )
    logger.debug(f"Active Threads: {threading.enumerate()}")
