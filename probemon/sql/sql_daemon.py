from queue import Queue
from typing import TypeVar
from threading import Thread

from probemon.sql.sql import Sql

ProbeRequest = TypeVar('ProbeRequest')

class SqlDaemon(Thread):
    queue = Queue()
    running = False

    @classmethod
    def add(cls: 'SqlDaemon', probe: ProbeRequest):
        if cls.running:
            cls.queue.put(probe)

    def run(self):
        SqlDaemon.running = True
        while Sql.is_enabled():
            probe = SqlDaemon.queue.get()
            Sql.publish_probe(probe)
            SqlDaemon.queue.task_done()
        SqlDaemon.running = False
