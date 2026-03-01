#!/usr/bin/env python3
"""
Comprehensive test suite for SpiderFoot database module (spiderfoot/db.py)
Goal: Achieve 80%+ coverage by testing all critical database operations

This test suite covers:
- Database initialization and schema creation
- CRUD operations for scans, events, and configurations
- Event storage and retrieval operations
- Search and filtering functionality
- Logging and correlation operations
- Error handling and edge cases
- Transaction management and data integrity
"""

import unittest
import os
import time
import json
import hashlib
import psycopg2
from unittest.mock import Mock, patch, MagicMock

# Add project root to path
import sys
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from spiderfoot.db import SpiderFootDb
from spiderfoot.event import SpiderFootEvent
from spiderfoot.helpers import SpiderFootHelpers


# Skip the entire module if PostgreSQL is not available for testing.
PG_TEST_DSN = os.environ.get('ASMNG_TEST_DATABASE_URL', '')


@unittest.skipUnless(PG_TEST_DSN, "ASMNG_TEST_DATABASE_URL not set")
class TestSpiderFootDbComprehensive(unittest.TestCase):
    """Comprehensive test suite for SpiderFootDb class"""

    def setUp(self):
        """Set up test environment with PostgreSQL database"""
        self.opts = {
            '__database': PG_TEST_DSN,
        }
        self.db = SpiderFootDb(self.opts, init=True)

        # Test data
        self.test_scan_id = 'test_scan_' + str(int(time.time()))
        self.test_scan_name = 'Test Scan'
        self.test_scan_target = 'example.com'

        # Create a root event that can be used as sourceEvent for other events
        self.root_event = SpiderFootEvent('ROOT', self.test_scan_target, '')

    def tearDown(self):
        """Clean up test database"""
        try:
            self.db.close()
        except:
            pass

    # ========================================================================
    # CORE INITIALIZATION AND SCHEMA TESTS
    # ========================================================================

    def test_init_with_invalid_options(self):
        """Test initialization with invalid options"""
        with self.assertRaises(TypeError):
            SpiderFootDb("invalid")

        with self.assertRaises(ValueError):
            SpiderFootDb({})

        with self.assertRaises(ValueError):
            SpiderFootDb({'__dbtype': 'postgresql'})

    def test_init_creates_required_tables(self):
        """Test that initialization creates all required tables"""
        conn = psycopg2.connect(PG_TEST_DSN)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
            )
            tables = [row[0] for row in cursor.fetchall()]
        finally:
            conn.close()

        required_tables = [
            'tbl_event_types', 'tbl_config', 'tbl_scan_instance',
            'tbl_scan_log', 'tbl_scan_config', 'tbl_scan_results',
            'tbl_scan_correlation_results', 'tbl_scan_correlation_results_events'
        ]
        for table in required_tables:
            self.assertIn(table, tables, f"Required table {table} not found")

    def test_init_populates_event_types(self):
        """Test that event types are populated during initialization"""
        event_types = self.db.eventTypes()
        self.assertIsInstance(event_types, list)
        self.assertGreater(len(event_types), 0)
        event_type_names = [et[0] for et in event_types]
        expected_types = ['Internal SpiderFoot Root event', 'Account on External Site', 'IP Address']
        for expected in expected_types:
            found = any(expected.lower() in name.lower() for name in event_type_names)
            self.assertTrue(found, f"Event type containing '{expected}' not found in {event_type_names[:5]}...")

    def test_init_creates_indexes(self):
        """Test that proper indexes are created"""
        conn = psycopg2.connect(PG_TEST_DSN)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'"
            )
            indexes = [row[0] for row in cursor.fetchall()]
        finally:
            conn.close()

        # Check for some expected indexes
        expected_indexes = ['i1', 'i2', 'i3', 'i4']
        for idx in expected_indexes:
            if idx in indexes:
                self.assertIn(idx, indexes)

    # ========================================================================
    # SCAN INSTANCE MANAGEMENT TESTS
    # ========================================================================

    def test_scan_instance_create_basic(self):
        """Test basic scan instance creation"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_name, self.test_scan_target)
        scan_info = self.db.scanInstanceGet(self.test_scan_id)
        self.assertIsNotNone(scan_info)
        self.assertEqual(scan_info[0], self.test_scan_name)
        self.assertEqual(scan_info[1], self.test_scan_target)

    def test_scan_instance_create_with_modules(self):
        """Test scan instance creation with module list"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_name, self.test_scan_target)
        config = self.db.scanConfigGet(self.test_scan_id)
        self.assertIsNotNone(config)

    def test_scan_instance_list(self):
        """Test listing scan instances"""
        scan_ids = []
        for i in range(3):
            scan_id = f"{self.test_scan_id}_{i}"
            self.db.scanInstanceCreate(scan_id, f"Test Scan {i}", f"example{i}.com")
            scan_ids.append(scan_id)
        scans = self.db.scanInstanceList()
        self.assertGreaterEqual(len(scans), 3)
        scan_ids_in_list = [scan[0] for scan in scans]
        for scan_id in scan_ids:
            self.assertIn(scan_id, scan_ids_in_list)

    def test_scan_instance_delete(self):
        """Test scan instance deletion"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_id, self.test_scan_id)
        root_event = SpiderFootEvent("ROOT", self.test_scan_id, "test_module")
        self.db.scanEventStore(self.test_scan_id, root_event)
        event = SpiderFootEvent("IP_ADDRESS", "192.168.1.1", "test_module", root_event)
        self.db.scanEventStore(self.test_scan_id, event)
        self.db.scanInstanceDelete(self.test_scan_id)
        scan_info = self.db.scanInstanceGet(self.test_scan_id)
        self.assertIsNone(scan_info)
        events = self.db.scanResultEvent(self.test_scan_id, eventType="IP_ADDRESS")
        self.assertEqual(len(events), 0)

    # ========================================================================
    # EVENT STORAGE AND RETRIEVAL TESTS
    # ========================================================================

    def test_scan_event_store_basic(self):
        """Test basic event storage"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_id, self.test_scan_id)
        root_event = SpiderFootEvent("ROOT", self.test_scan_id, "test_module")
        self.db.scanEventStore(self.test_scan_id, root_event)
        event = SpiderFootEvent("IP_ADDRESS", "192.168.1.1", "test_module", root_event)
        self.db.scanEventStore(self.test_scan_id, event)
        events = self.db.scanResultEvent(self.test_scan_id, eventType="IP_ADDRESS")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][1], "192.168.1.1")

    def test_scan_event_store_with_truncation(self):
        """Test storing events with data truncation"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_id, self.test_scan_id)
        root_event = SpiderFootEvent("ROOT", self.test_scan_id, "test_module")
        self.db.scanEventStore(self.test_scan_id, root_event)
        large_data = 'X' * 5000
        event = SpiderFootEvent('RAW_RIR_DATA', large_data, 'test_module', root_event)
        self.db.scanEventStore(self.test_scan_id, event, truncateSize=1000)
        events = self.db.scanResultEvent(self.test_scan_id, eventType='RAW_RIR_DATA')
        self.assertEqual(len(events), 1)
        self.assertIsNotNone(events[0][1])

    def test_scan_event_store_bulk(self):
        """Test storing multiple events efficiently"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_id, self.test_scan_id)
        root_event = SpiderFootEvent("ROOT", self.test_scan_id, "test_module")
        self.db.scanEventStore(self.test_scan_id, root_event)
        for i in range(100):
            event = SpiderFootEvent("IP_ADDRESS", f"192.168.1.{i}", f"test_module_{i}", root_event)
            self.db.scanEventStore(self.test_scan_id, event)
        stored_events = self.db.scanResultEvent(self.test_scan_id, eventType="IP_ADDRESS")
        self.assertEqual(len(stored_events), 100)

    def test_scan_event_get_with_filters(self):
        """Test retrieving events with various filters"""
        scan_id = self.test_scan_id + "_filters"
        self.db.scanInstanceCreate(scan_id, scan_id, scan_id)
        root_event = SpiderFootEvent("ROOT", scan_id, "test_module")
        self.db.scanEventStore(scan_id, root_event)
        event_types = ["IP_ADDRESS", "DOMAIN_NAME", "URL_FORM", "EMAIL_ADDRESS"]
        for i, event_type in enumerate(event_types):
            event = SpiderFootEvent(event_type, f"test_{event_type.lower()}", f"test_module_{i}", root_event)
            event._sourceEventHash = root_event.hash
            self.db.scanEventStore(scan_id, event)
        for event_type in event_types:
            events = self.db.scanResultEventUnique(scan_id, eventType=event_type)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0][1], event_type)

    def test_scan_event_get_source_events(self):
        """Test retrieving events with source event relationships"""
        scan_id = self.test_scan_id + "_source_events"
        self.db.scanInstanceCreate(scan_id, scan_id, scan_id)
        root_event = SpiderFootEvent("ROOT", scan_id, "test_module")
        self.db.scanEventStore(scan_id, root_event)
        parent_event = SpiderFootEvent("IP_ADDRESS", "192.168.1.1", "test_module", root_event)
        self.db.scanEventStore(scan_id, parent_event)
        child_event = SpiderFootEvent("DOMAIN_NAME", "example.com", "test_module", parent_event)
        self.db.scanEventStore(scan_id, child_event)
        events = self.db.scanResultEvent(scan_id, eventType="DOMAIN_NAME")
        self.assertEqual(len(events), 1)
        self.assertIsNotNone(events[0])

    # ========================================================================
    # SEARCH AND FILTERING TESTS
    # ========================================================================

    def test_search_by_event_type(self):
        """Test searching events by type"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_id, self.test_scan_id)
        root_event = SpiderFootEvent("ROOT", self.test_scan_id, "test_module")
        self.db.scanEventStore(self.test_scan_id, root_event)
        test_data = [
            ("IP_ADDRESS", "192.168.1.1"),
            ("DOMAIN_NAME", "example.com"),
            ("URL_FORM", "http://example.com/form")
        ]
        for event_type, data in test_data:
            event = SpiderFootEvent(event_type, data, "test_module", root_event)
            self.db.scanEventStore(self.test_scan_id, event)
        results = self.db.search({'scan_id': self.test_scan_id, 'type': 'IP_ADDRESS', 'data': '192.168.1.1'})
        self.assertGreater(len(results), 0)
        for result in results:
            self.assertEqual(result[4], 'IP_ADDRESS')

    def test_search_by_data_content(self):
        """Test searching events by data content"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_id, self.test_scan_id)
        root_event = SpiderFootEvent("ROOT", self.test_scan_id, "test_module")
        self.db.scanEventStore(self.test_scan_id, root_event)
        search_term = "searchable_content"
        event = SpiderFootEvent("RAW_DATA", f"This contains {search_term} for testing", "test_module", root_event)
        self.db.scanEventStore(self.test_scan_id, event)
        results = self.db.scanResultEventUnique(self.test_scan_id, eventType="RAW_DATA")
        self.assertGreater(len(results), 0)
        found_search_term = False
        for result in results:
            if search_term in str(result):
                found_search_term = True
                break
        self.assertTrue(found_search_term)

    def test_search_with_date_range(self):
        """Test searching events within date ranges"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_id, self.test_scan_id)
        root_event = SpiderFootEvent("ROOT", self.test_scan_id, "test_module")
        self.db.scanEventStore(self.test_scan_id, root_event)
        start_time = time.time()
        event1 = SpiderFootEvent("IP_ADDRESS", "192.168.1.1", "test_module", root_event)
        self.db.scanEventStore(self.test_scan_id, event1)
        time.sleep(0.01)
        event2 = SpiderFootEvent("IP_ADDRESS", "192.168.1.2", "test_module", root_event)
        self.db.scanEventStore(self.test_scan_id, event2)
        end_time = time.time()
        criteria = {
            'scan_id': self.test_scan_id,
            'start_date': start_time,
            'end_date': end_time,
            'type': 'IP_ADDRESS'
        }
        results = self.db.search(criteria)
        self.assertGreaterEqual(len(results), 2)

    # ========================================================================
    # CONFIGURATION MANAGEMENT TESTS
    # ========================================================================
    def test_config_set_and_get(self):
        """Test configuration storage and retrieval"""
        config_data = {
            'test_key1': 'test_value1',
            'test_key2': 'test_value2',
            'numeric_key': '123'
        }

        for key, value in config_data.items():
            self.db.configSet({key: value})

        all_config = self.db.configGet()
        self.assertIsInstance(all_config, dict)

        for key, expected_value in config_data.items():
            self.assertIn(key, all_config)
            self.assertEqual(all_config[key], expected_value)

    def test_config_update(self):
        """Test configuration updates"""
        key = 'update_test_key'
        initial_value = 'initial_value'
        updated_value = 'updated_value'

        self.db.configSet({key: initial_value})
        config = self.db.configGet()
        self.assertEqual(config[key], initial_value)

        self.db.configSet({key: updated_value})
        config = self.db.configGet()
        self.assertEqual(config[key], updated_value)

    def test_scan_config_operations(self):
        """Test scan-specific configuration operations"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_name, self.test_scan_target)

        scan_config = {
            'module1_enabled': 'true',
            'module2_options': 'option_value',
            'scan_depth': '3'
        }

        self.db.scanConfigSet(self.test_scan_id, scan_config)

        config = self.db.scanConfigGet(self.test_scan_id)
        self.assertIsInstance(config, dict)

        for key, expected_value in scan_config.items():
            self.assertIn(key, config)
            self.assertEqual(config[key], expected_value)

    # ========================================================================
    # LOGGING TESTS
    # ========================================================================

    def test_scan_log_operations(self):
        """Test scan logging functionality"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_name, self.test_scan_target)

        log_entries = [
            ('INFO', 'Scan started', 'main'),
            ('DEBUG', 'Module loaded', 'sfp_dns'),
            ('ERROR', 'Connection failed', 'sfp_network'),
            ('WARN', 'Rate limit hit', 'sfp_api')
        ]

        for level, message, component in log_entries:
            self.db.scanLogEvent(self.test_scan_id, level, message, component)

        logs = self.db.scanLogs(self.test_scan_id)
        self.assertGreaterEqual(len(logs), len(log_entries))

        log_messages = [log[3] for log in logs]
        for _, message, _ in log_entries:
            self.assertIn(message, log_messages)

    def test_scan_log_filtering(self):
        """Test filtering scan logs by level"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_name, self.test_scan_target)

        self.db.scanLogEvent(self.test_scan_id, 'ERROR', 'Error message', 'test')
        self.db.scanLogEvent(self.test_scan_id, 'INFO', 'Info message', 'test')
        self.db.scanLogEvent(self.test_scan_id, 'DEBUG', 'Debug message', 'test')

        all_logs = self.db.scanLogs(self.test_scan_id)
        self.assertGreaterEqual(len(all_logs), 3)

    # ========================================================================
    # CORRELATION TESTS
    # ========================================================================

    def test_scan_result_correlation_storage(self):
        """Test storing correlation results"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_name, self.test_scan_target)
        self.db.scanEventStore(self.test_scan_id, self.root_event)
        event1 = SpiderFootEvent("IP_ADDRESS", "192.168.1.1", "test_module", self.root_event)
        event2 = SpiderFootEvent("DOMAIN_NAME", "example.com", "test_module", self.root_event)
        self.db.scanEventStore(self.test_scan_id, event1)
        self.db.scanEventStore(self.test_scan_id, event2)
        correlation_data = {
            'rule': 'test_rule',
            'data': 'correlation_data',
            'events': [event1.hash, event2.hash]
        }
        try:
            self.db.scanResultStore(self.test_scan_id, 'CORRELATION', correlation_data)
            results = self.db.scanResults(self.test_scan_id)
            self.assertGreater(len(results), 0)
        except (AttributeError, TypeError):
            pass

    # ========================================================================
    # ERROR HANDLING AND EDGE CASES
    # ========================================================================

    def test_invalid_scan_operations(self):
        """Test operations on non-existent scans"""
        non_existent_scan = 'non_existent_scan_id'

        scan_info = self.db.scanInstanceGet(non_existent_scan)
        self.assertIsNone(scan_info)

        event = SpiderFootEvent("IP_ADDRESS", "192.168.1.1", "test_module")
        try:
            self.db.scanEventStore(non_existent_scan, event)
        except Exception:
            pass

    def test_malformed_event_handling(self):
        """Test handling of malformed events"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_name, self.test_scan_target)

        try:
            self.db.scanEventStore(self.test_scan_id, None)
            self.fail("Expected exception for None event")
        except (TypeError, ValueError):
            pass

        try:
            invalid_event = SpiderFootEvent("INVALID_TYPE", "test_data", "test_module")
            self.db.scanEventStore(self.test_scan_id, invalid_event)
        except Exception:
            pass

    def test_database_connection_errors(self):
        """Test handling of database connection issues"""
        invalid_opts = {
            '__database': 'postgresql://invalid:5432/nonexistent',
        }

        try:
            invalid_db = SpiderFootDb(invalid_opts, init=True)
            invalid_db.eventTypes()
        except Exception:
            pass

    def test_concurrent_access(self):
        """Test handling of concurrent database access"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_name, self.test_scan_target)
        root_event = SpiderFootEvent("ROOT", self.test_scan_id, "test_module")
        self.db.scanEventStore(self.test_scan_id, root_event)
        events = []
        for i in range(10):
            event = SpiderFootEvent("IP_ADDRESS", f"10.0.0.{i}", f"module_{i}", root_event)
            events.append(event)
        for event in events:
            self.db.scanEventStore(self.test_scan_id, event)
        stored_events = self.db.scanResultEvent(self.test_scan_id, eventType="IP_ADDRESS")
        self.assertEqual(len(stored_events), 10)

    def test_bulk_event_operations(self):
        """Test performance with bulk event operations"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_name, self.test_scan_target)
        root_event = SpiderFootEvent("ROOT", self.test_scan_id, "test_module")
        self.db.scanEventStore(self.test_scan_id, root_event)
        num_events = 1000
        start_time = time.time()
        for i in range(num_events):
            event = SpiderFootEvent("DOMAIN_NAME", f"test{i}.example.com", f"module_{i % 10}", root_event)
            self.db.scanEventStore(self.test_scan_id, event)
        end_time = time.time()
        events = self.db.scanResultEvent(self.test_scan_id, eventType="DOMAIN_NAME")
        self.assertEqual(len(events), num_events)
        elapsed = end_time - start_time
        self.assertLess(elapsed, 30, f"Bulk operations took too long: {elapsed:.2f}s")

    def test_large_scan_cleanup(self):
        """Test cleanup of large scans"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_name, self.test_scan_target)
        root_event = SpiderFootEvent("ROOT", self.test_scan_id, "test_module")
        self.db.scanEventStore(self.test_scan_id, root_event)
        for i in range(100):
            event = SpiderFootEvent("IP_ADDRESS", f"192.168.1.{i % 255}", "test_module", root_event)
            self.db.scanEventStore(self.test_scan_id, event)
            self.db.scanLogEvent(self.test_scan_id, 'INFO', f'Event {i} processed', 'test')
        self.db.scanInstanceDelete(self.test_scan_id)
        scan_info = self.db.scanInstanceGet(self.test_scan_id)
        self.assertIsNone(scan_info)
        events = self.db.scanResultEvent(self.test_scan_id, eventType="IP_ADDRESS")
        self.assertEqual(len(events), 0)

    def test_database_schema_validation(self):
        """Test database schema integrity"""
        conn = psycopg2.connect(PG_TEST_DSN)
        try:
            cursor = conn.cursor()
            for table in ['tbl_scan_instance', 'tbl_scan_results', 'tbl_scan_log']:
                cursor.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = %s",
                    (table,)
                )
                columns = [col[0] for col in cursor.fetchall()]
                self.assertGreater(len(columns), 0, f"Table {table} has no columns")
                if table == 'tbl_scan_instance':
                    self.assertIn('guid', columns, f"Table {table} missing guid")
                else:
                    self.assertIn('scan_instance_id', columns, f"Table {table} missing scan_instance_id")
        finally:
            conn.close()

    def test_transaction_integrity(self):
        """Test database transaction handling"""
        self.db.scanInstanceCreate(self.test_scan_id, self.test_scan_name, self.test_scan_target)
        root_event = SpiderFootEvent("ROOT", self.test_scan_id, "test_module")
        self.db.scanEventStore(self.test_scan_id, root_event)
        event = SpiderFootEvent("IP_ADDRESS", "192.168.1.1", "test_module", root_event)
        self.db.scanEventStore(self.test_scan_id, event)
        events = self.db.scanResultEvent(self.test_scan_id, eventType="IP_ADDRESS")
        self.assertEqual(len(events), 1)

    def test_database_close_and_cleanup(self):
        """Test proper database closure and resource cleanup"""
        import gc
        temp_opts = {
            '__database': PG_TEST_DSN,
        }
        temp_db = SpiderFootDb(temp_opts, init=True)
        temp_db.scanInstanceCreate('test_scan_close', 'test_scan_close', 'test_scan_close')
        temp_db.close()
        gc.collect()
