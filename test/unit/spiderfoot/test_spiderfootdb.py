import unittest
import os
import time
from unittest.mock import patch, MagicMock
from spiderfoot.db import SpiderFootDb
from spiderfoot import SpiderFootHelpers, SpiderFootEvent
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


# Skip the entire module if PostgreSQL is not available for testing.
PG_TEST_DSN = os.environ.get('ASMNG_TEST_DATABASE_URL', '')


@unittest.skipUnless(PG_TEST_DSN, "ASMNG_TEST_DATABASE_URL not set")
class TestSpiderFootDb(SpiderFootTestBase):

    def setUp(self):
        super().setUp()
        self.opts = {
            '__database': PG_TEST_DSN,
        }
        self.db = SpiderFootDb(self.opts)
        # Register event emitters if they exist
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def test_init_invalid_opts_type(self):
        with self.assertRaises(TypeError):
            SpiderFootDb("invalid_opts")

    def test_init_empty_opts(self):
        with self.assertRaises(ValueError):
            SpiderFootDb({})

    def test_init_missing_database_key(self):
        with self.assertRaises(ValueError):
            SpiderFootDb({'__dbtype': 'postgresql'})

    def test_create(self):
        # Test that create can be called without errors in a fresh database
        result = False
        test_db = None
        try:
            test_opts = self.opts.copy()
            test_db = SpiderFootDb(test_opts, init=False)
            # Verify that the essential tables exist
            test_db.dbh.execute('SELECT COUNT(*) FROM tbl_event_types')
            event_types_count = test_db.dbh.fetchone()[0]
            test_db.dbh.execute('SELECT COUNT(*) FROM tbl_scan_config')
            result = True
        except Exception as e:
            print(f"Database creation failed: {e}")
            result = False
        finally:
            if test_db is not None:
                try:
                    test_db.close()
                except:
                    pass
        self.assertTrue(result)

    def test_close(self):
        try:
            self.db.close()
            result = True
        except Exception:
            result = False
        self.assertTrue(result)

    def test_vacuumDB(self):
        try:
            self.db.vacuumDB()
            result = True
        except Exception:
            result = False
        self.assertTrue(result)

    def test_search_invalid_criteria_type(self):
        with self.assertRaises(TypeError):
            self.db.search("invalid_criteria")

    def test_search_empty_criteria(self):
        with self.assertRaises(ValueError):
            self.db.search({})

    def test_search_single_criteria(self):
        criteria = {'scan_id': 'test_instance', 'type': 'IP_ADDRESS'}
        try:
            result = self.db.search(criteria)
            self.assertIsInstance(result, list)
        except Exception:
            self.fail("Search with multiple criteria raised an exception")

    def tearDown(self):
        """Clean up after each test."""
        if hasattr(self, 'db') and self.db:
            try:
                self.db.close()
            except:
                pass
        if hasattr(self, 'module'):
            self.unregister_event_emitter(self.module)
        super().tearDown()
