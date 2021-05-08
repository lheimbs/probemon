import logging
from queue import Queue
from threading import Thread

import requests

ProbeRequest = 'ProbeRequest'
logger = logging.getLogger(__name__)

class UrlDaemon(Thread):
    queue = Queue()
    running = True

    @classmethod
    def add(cls: 'UrlDaemon', probe: ProbeRequest):
        if cls.running:
            cls.queue.put(probe)

    def __init__(self, **kwargs):
        self.url = kwargs.pop('url') if 'url' in kwargs else ''
        self.token = kwargs.pop('token') if 'token' in kwargs else ''
        self.session = requests.Session()
        self.session.headers.update({'Authorization': f'Bearer {self.token}'})
        kwargs['daemon'] = True
        super().__init__(**kwargs)

    def run(self):
        UrlDaemon.running = True
        while self.url and self.token:
            self.handle_probe()
        UrlDaemon.running = False

    def handle_probe(self):
        probe = UrlDaemon.queue.get()
        response = self.session.post(self.url, data=dict(probe))
        UrlDaemon.queue.task_done()
        if response.status_code == 200:
            logger.debug(f"Published probe {probe!r} to {self.url}.")
        else:
            logger.error(
                f"Failed to publish {probe!r} to {self.url} with "
                f"status code {response.status_code}: {response.reason}."
            )
            UrlDaemon.queue.put(probe)
