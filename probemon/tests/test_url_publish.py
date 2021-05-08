import logging
from queue import Queue
from unittest import TestCase, mock

from ..url_publish import url_publish

class UrlDaemonUnitTest(TestCase):
    def setUp(self) -> None:
        logging.disable(logging.NOTSET)
        url_publish.UrlDaemon.running = False
        url_publish.UrlDaemon.queue = Queue()
        return super().setUp()

    def test_add_probe_not_running(self):
        url_publish.UrlDaemon.running = False
        url_publish.UrlDaemon.add(None)
        self.assertTrue(url_publish.UrlDaemon.queue.empty())

    def test_add_probe_running(self):
        url_publish.UrlDaemon.running = True
        url_publish.UrlDaemon.add(None)
        self.assertIsNone(url_publish.UrlDaemon.queue.get())

    def test_run_without_url(self):
        url = url_publish.UrlDaemon()
        url.run()
        self.assertFalse(url_publish.UrlDaemon.running)

    def test_run_with_url_without_token(self):
        url = url_publish.UrlDaemon(url='test')
        url.run()
        self.assertFalse(url_publish.UrlDaemon.running)

    @mock.patch.object(url_publish.UrlDaemon, 'handle_probe', side_effect=[True, InterruptedError])
    def test_run_with_url_with_token_and_good_response(self, _):
        url = url_publish.UrlDaemon(url='url', token='token')
        with self.assertRaises(InterruptedError):
            url.run()

    def test_handle_probe_successful(self):
        url_publish.UrlDaemon.running = True
        url_publish.UrlDaemon.queue.put({})
        url = url_publish.UrlDaemon(url='url', token='token')
        mock_response = mock.Mock(name='resp', status_code=200)
        obj_patch = {'target': url.session, 'attribute': 'post', 'return_value': mock_response}
        log = {'logger': url_publish.logger, 'level': 'DEBUG'}
        with mock.patch.object(**obj_patch), self.assertLogs(**log) as logger:
            url.handle_probe()
        self.assertTrue(url_publish.UrlDaemon.queue.empty())
        self.assertIn(f'DEBUG:{url_publish.logger.name}:Published probe {{}} to url.', logger.output)

    def test_handle_probe_post_fail(self):
        url_publish.UrlDaemon.running = True
        url_publish.UrlDaemon.queue.put({})
        url = url_publish.UrlDaemon(url='url', token='token')
        mock_response = mock.Mock(name='resp', status_code=404, reason='')
        obj_patch = {
            'target': url.session, 'attribute': 'post',
            'return_value': mock_response,
        }
        log = {'logger': url_publish.logger, 'level': 'DEBUG'}
        with mock.patch.object(**obj_patch), self.assertLogs(**log) as logger:
            url.handle_probe()
        self.assertEqual(url_publish.UrlDaemon.queue.get(), {})
        self.assertIn(
            f'ERROR:{url_publish.logger.name}:Failed to publish {{}} to url with status code 404: .',
            logger.output
        )
