import logging
import importlib
from datetime import datetime
from unittest import TestCase, mock

import sqlalchemy
# from sqlalchemy.orm import session

from ..sql import Sql
from ..probe_request import ProbeRequest, ProbeRequestModel

class SqlUnitTest(TestCase):
    def setUp(self) -> None:
        logging.disable(logging.ERROR)
        Sql._enabled = False
        Sql._Session = None
        return super().setUp()

    def tearDown(self) -> None:
        logging.disable(logging.NOTSET)
        return super().tearDown()

    def test_enable(self):
        Sql.enable()
        self.assertTrue(Sql._enabled)

    def test_disable(self):
        Sql.disable()
        self.assertFalse(Sql._enabled)

    def test_is_enabled(self):
        Sql.enable()
        self.assertTrue(Sql.is_enabled())
        Sql.disable()
        self.assertFalse(Sql.is_enabled())

    def test_init(self):
        sql = Sql()
        self.assertIsNone(sql._engine)

    def test_set_url_sqlite(self):
        sql = Sql()
        sql.set_url('sqlite://')
        self.assertIsInstance(sql._engine, sqlalchemy.engine.Engine)
        self.assertTrue(Sql.is_enabled())

    def test_set_url_postgres(self):
        sql = Sql()
        psql_driver = importlib.util.find_spec('psycopg2') is not None
        sql.set_url('postgresql://')
        if psql_driver:
            self.assertIsInstance(sql._engine, sqlalchemy.engine.Engine)
            self.assertTrue(Sql.is_enabled())
        else:
            self.assertIsNone(sql._engine)
            self.assertFalse(Sql.is_enabled())

    def test_set_url_with_bad_dialect(self):
        sql = Sql()
        sql.set_url('asdasd://')
        self.assertIsNone(sql._engine)
        self.assertFalse(Sql.is_enabled())

    def test_register_with_set_engine_and_sql_enabled(self):
        sql = Sql()
        sql.set_url('sqlite://')
        sql.register()
        self.assertIsNotNone(Sql._Session)

    def test_register_without_engine_and_sql_enabled(self):
        sql = Sql()
        Sql.enable()
        sql.register()
        self.assertIsNone(Sql._Session)

    def test_register_with_engine_and_sql_disabled(self):
        sql = Sql()
        sql.set_url('sqlite://')
        Sql.disable()
        sql.register()
        self.assertIsNone(Sql._Session)


class SqlWithDatabaseInMemoryUnitTest(TestCase):
    def setUp(self) -> None:
        sql = Sql()
        sql.set_url('sqlite:///:memory:')
        sql.register()

    def test_publish_probe(self):
        probe = ProbeRequest(datetime.now(), 'aa:bb:cc:dd:ee:ff')
        probe_model = Sql.publish_probe(probe)
        self.assertIsInstance(probe_model, ProbeRequestModel)

    @mock.patch('probemon.probe_request.probe_request.ProbeRequestModel', side_effect=AttributeError)
    def test_publish_probe_with_bad_model(self, _):
        probe = ProbeRequest(mac='aa:bb:cc:dd:ee:ff')
        probe_model = Sql.publish_probe(probe)
        self.assertIsNone(probe_model)

    def test_publish_probe_with_sql_disabled(self):
        Sql.disable()
        probe = ProbeRequest(datetime.now(), 'aa:bb:cc:dd:ee:ff')
        probe_model = Sql.publish_probe(probe)
        self.assertIsNone(probe_model)

    def test_publish_probe_with_exception_at_add(self):
        logging.disable(logging.ERROR)
        with mock.patch.object(Sql, '_Session') as mocked_session:
            mocked_session.return_value.add.side_effect = TypeError()
            probe = ProbeRequest(datetime.now(), 'aa:bb:cc:dd:ee:ff')
            self.assertRaises(TypeError, Sql.publish_probe, probe)

    @mock.patch.object(ProbeRequest, '_set_vendor', return_value="test")
    def test_get_vendor(self, _):
        mac = 'aa:bb:cc:dd:ee:f0'
        Sql.publish_probe(ProbeRequest(datetime.now(), mac))
        vendor = Sql.get_vendor(mac)
        self.assertEqual(vendor, 'test')

    @mock.patch.object(ProbeRequest, '_set_vendor', return_value="test")
    def test_get_vendor_with_sql_disabled(self, _):
        Sql.disable()
        mac = 'aa:bb:cc:dd:ee:f1'
        Sql.publish_probe(ProbeRequest(datetime.now(), mac))
        vendor = Sql.get_vendor(mac)
        self.assertEqual(vendor, '')

    def test_get_vendor_with_multiple_vendors(self):
        mac = 'aa:bb:cc:dd:ee:f2'
        with mock.patch.object(ProbeRequest, '_set_vendor', return_value=""):
            Sql.publish_probe(ProbeRequest(datetime.now(), mac))
        with mock.patch.object(ProbeRequest, '_set_vendor', return_value="test"):
            Sql.publish_probe(ProbeRequest(datetime.now(), mac))
        vendor = Sql.get_vendor(mac)
        self.assertEqual(vendor, 'test')

    def test_get_vendor_with_no_vendors(self):
        mac = 'aa:bb:cc:dd:ee:f2'
        vendor = Sql.get_vendor(mac)
        self.assertEqual(vendor, '')

    def test_get_vendor_with_exception_at_query(self):
        logging.disable(logging.ERROR)
        with mock.patch.object(Sql, '_Session') as mocked_session:
            mocked_session.return_value.query.side_effect = TypeError()
            self.assertRaises(TypeError, Sql.get_vendor, '112233445566')
