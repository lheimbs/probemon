from queue import Queue
from typing import TypeVar
from threading import Thread

from probemon.mqtt.mqtt import Mqtt

ProbeRequest = TypeVar('ProbeRequest')

class MqttDaemon(Thread):
    queue = Queue()
    running = False

    @classmethod
    def add(cls: 'MqttDaemon', probe: ProbeRequest):
        if cls.running:
            cls.queue.put_nowait(probe)

    def run(self):
        with Mqtt() as mqtt_client:
            MqttDaemon.running = True
            while Mqtt.is_enabled():
                probe = MqttDaemon.queue.get()
                mqtt_client.publish_probe(probe)
                MqttDaemon.queue.task_done()
        MqttDaemon.running = False
