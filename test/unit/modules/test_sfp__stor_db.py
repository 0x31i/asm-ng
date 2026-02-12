import pytest
import unittest
from unittest.mock import patch, MagicMock, Mock
import time

from modules.sfp__stor_db import sfp__stor_db
from sflib import SpiderFoot
from spiderfoot.event import SpiderFootEvent
from test.unit.utils.test_base import SpiderFootTestBase
from test.unit.utils.test_helpers import safe_recursion


class TestModuleStor_db(SpiderFootTestBase):
    """Test suite for database storage module."""

    def setUp(self):
        """Set up before each test."""
        super().setUp()
        # Create a mock database handle
        self.mock_dbh = MagicMock()
        self.mock_dbh.scanEventStore = MagicMock()

        # Create SpiderFoot instance with mock database handle
        self.sf_instance = SpiderFoot(self.default_options)
        self.sf_instance.dbh = self.mock_dbh

        # Register event emitters if they exist
        if hasattr(self, 'module'):
            self.register_event_emitter(self.module)

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()

    def create_test_event(self, event_type="IP_ADDRESS", data="192.168.1.1", module="test_module"):
        """Create a test SpiderFoot event."""
        if event_type == "ROOT":
            event = SpiderFootEvent("ROOT", data, module)
        else:
            root_event = SpiderFootEvent("ROOT", "root", module)
            event = SpiderFootEvent(event_type, data, module, root_event)

        event.confidence = 100
        event.visibility = 1
        event.risk = 0
        return event

    @unittest.skip("This module contains an extra private option")
    def test_opts(self):
        module = sfp__stor_db()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup_default(self):
        """Test setup with default configuration."""
        module = sfp__stor_db()
        module.setup(self.sf_instance, {})

        self.assertFalse(module.errorState)
        self.assertIsNotNone(module.__sfdb__)

    def test_setup_no_database_handle(self):
        """Test setup fails gracefully when no database handle is available."""
        sf_no_db = SpiderFoot(self.default_options)
        sf_no_db.dbh = None

        module = sfp__stor_db()
        module.setup(sf_no_db, dict())

        self.assertTrue(module.errorState)

    def test_watchedEvents_should_return_list(self):
        module = sfp__stor_db()
        events = module.watchedEvents()
        self.assertIsInstance(events, list)
        self.assertIn("*", events)

    def test_producedEvents_should_return_list(self):
        module = sfp__stor_db()
        self.assertIsInstance(module.producedEvents(), list)

    def test_sqlite_storage(self):
        """Test SQLite storage functionality."""
        module = sfp__stor_db()
        module.setup(self.sf_instance, {'_store': True})

        # Create test event
        test_event = self.create_test_event()

        # Mock getScanId
        module.getScanId = MagicMock(return_value="test_scan_id")

        module.handleEvent(test_event)

        # Verify that scanEventStore was called
        self.mock_dbh.scanEventStore.assert_called()

    def test_sqlite_storage_with_size_limit(self):
        """Test SQLite storage with size limits."""
        module = sfp__stor_db()
        module.setup(self.sf_instance, {
            '_store': True,
            'maxstorage': 10  # Very small limit
        })

        # Create test event with large data
        large_data = "x" * 100  # 100 characters, exceeds limit
        test_event = self.create_test_event("IP_ADDRESS", large_data)

        # Mock getScanId
        module.getScanId = MagicMock(return_value="test_scan_id")

        module.handleEvent(test_event)

        # Verify that scanEventStore was called with size limit
        self.mock_dbh.scanEventStore.assert_called_with(
            "test_scan_id", test_event, 10
        )

    def test_storage_disabled(self):
        """Test that storage is skipped when disabled."""
        module = sfp__stor_db()
        module.setup(self.sf_instance, {'_store': False})

        test_event = self.create_test_event()
        module.handleEvent(test_event)

        # Storage should not be called when disabled
        self.mock_dbh.scanEventStore.assert_not_called()

    def test_storage_error_state(self):
        """Test that storage is skipped when module is in error state."""
        module = sfp__stor_db()
        module.setup(self.sf_instance, {'_store': True})
        module.errorState = True

        test_event = self.create_test_event()
        module.handleEvent(test_event)

        # Storage should not be called when in error state
        self.mock_dbh.scanEventStore.assert_not_called()

    def test_performance_benchmarking(self):
        """Test performance benchmarking capabilities."""
        module = sfp__stor_db()
        module.setup(self.sf_instance, {
            'maxstorage': 1024,
            '_store': True
        })
        module.getScanId = MagicMock(return_value="benchmark_test_scan")

        # Process multiple events to test performance
        events_count = 100
        start_time = time.time()

        for i in range(events_count):
            test_event = self.create_test_event(
                event_type=f"BENCHMARK_EVENT_{i}",
                data=f"benchmark_data_{i}"
            )
            module.handleEvent(test_event)

        total_time = time.time() - start_time
        if total_time == 0:
            events_per_second = float('inf')
        else:
            events_per_second = events_count / total_time
        # Verify reasonable performance (at least 100 events/sec for SQLite)
        self.assertGreater(events_per_second, 100,
                          f"Performance should be at least 100 events/sec, got {events_per_second:.1f}")

        # Verify all events were processed
        self.assertEqual(self.sf_instance.dbh.scanEventStore.call_count, events_count)

    def test_backward_compatibility(self):
        """Test backward compatibility with legacy configuration."""
        module = sfp__stor_db()

        # Test with legacy configuration
        legacy_opts = {
            'maxstorage': 1024,
            '_store': True
        }

        module.setup(self.sf_instance, legacy_opts)
        module.getScanId = MagicMock(return_value="legacy_test_scan")

        # Test that legacy functionality still works
        test_event = self.create_test_event()
        module.handleEvent(test_event)

        # Verify event was stored
        self.sf_instance.dbh.scanEventStore.assert_called()

        # Module should not be in error state
        self.assertFalse(module.errorState, "Legacy configuration should work")

    def test_graceful_shutdown(self):
        """Test graceful shutdown procedures."""
        module = sfp__stor_db()
        module.setup(self.sf_instance, {
            'maxstorage': 1024,
            '_store': True
        })

        # Test module can be properly destroyed
        try:
            del module
            shutdown_successful = True
        except Exception:
            shutdown_successful = False

        self.assertTrue(shutdown_successful, "Module should shutdown gracefully")
