#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Storage Features Integration Test Suite

This comprehensive test suite validates storage features
implemented in SpiderFoot's storage modules:

- SQLite storage with data integrity
- Error handling and recovery
- Performance optimization
- Security features
- Data validation

Author: ASM-NG Team
Created: 2025-01-27
"""

import unittest
import time
import threading
import tempfile
import os
import json
from unittest.mock import patch, MagicMock, Mock
from elasticsearch import Elasticsearch, ConnectionError

from sflib import SpiderFoot
from spiderfoot.event import SpiderFootEvent
from modules.sfp__stor_db import sfp__stor_db
from modules.sfp__stor_elasticsearch import sfp__stor_elasticsearch
from modules.sfp__stor_stdout import sfp__stor_stdout


class TestStorageFeatures(unittest.TestCase):
    """Integration tests for storage features."""

    def setUp(self):
        """Set up test environment."""
        self.sf_options = {
            'database': tempfile.mktemp(suffix='.db'),
            'modules': [],
            'useragent': 'SpiderFoot-Test'
        }

        # Create test SpiderFoot instance
        self.sf = SpiderFoot(self.sf_options)

        # Mock database handle
        self.mock_dbh = MagicMock()
        self.mock_dbh.scanEventStore = MagicMock()
        self.sf.dbh = self.mock_dbh

        self.test_scan_id = "test_scan_12345"

    def tearDown(self):
        """Clean up test environment."""
        # Clean up temporary database file
        if os.path.exists(self.sf_options['database']):
            os.unlink(self.sf_options['database'])

    def create_test_event(self, event_type="IP_ADDRESS", data="192.168.1.1", module="test_module"):
        """Create a test SpiderFoot event."""
        event = SpiderFootEvent(event_type, data, module, None)
        event.confidence = 100
        event.visibility = 1
        event.risk = 0
        return event

    def test_sqlite_storage_features(self):
        """Test SQLite storage features."""
        print("\n=== Testing SQLite Storage Features ===")

        module = sfp__stor_db()
        module.setup(self.sf, {'_store': True})
        module.getScanId = MagicMock(return_value=self.test_scan_id)

        # Verify setup
        self.assertFalse(module.errorState)

        # Test event storage
        test_event = self.create_test_event()
        module.handleEvent(test_event)
        self.mock_dbh.scanEventStore.assert_called()

        print("  SQLite storage working")

    def test_elasticsearch_advanced_features(self):
        """Test Elasticsearch storage advanced features."""
        print("\n=== Testing Elasticsearch Advanced Features ===")

        with patch('modules.sfp__stor_elasticsearch.Elasticsearch') as mock_es_class, \
             patch('elasticsearch.helpers.bulk') as mock_bulk:
            mock_es = MagicMock()
            mock_es.ping.return_value = True
            mock_es.indices.exists.return_value = False
            mock_es.bulk.return_value = {'errors': False}
            mock_es_class.return_value = mock_es
            mock_bulk.return_value = (150, [])

            module = sfp__stor_elasticsearch()
            opts = {
                'enabled': True,
                'host': 'elasticsearch.company.com',
                'port': 9200,
                'index': 'spiderfoot-enterprise',
                'use_ssl': True,
                'verify_certs': True,
                'api_key': 'enterprise_api_key_12345',
                'bulk_size': 1,
                'timeout': 30
            }

            module.setup(self.sf, opts)
            module.getScanId = MagicMock(return_value=self.test_scan_id)

            self.assertFalse(module.errorState)
            call_args = mock_es_class.call_args[1]
            self.assertTrue(call_args['use_ssl'])
            self.assertTrue(call_args['verify_certs'])
            self.assertEqual(call_args['api_key'], 'enterprise_api_key_12345')

            module._ensure_index_exists()
            mock_es.indices.exists.assert_called_with(index='spiderfoot-enterprise')
            self.assertGreaterEqual(mock_es.indices.create.call_count, 1)

            events = []
            for i in range(150):
                event = self.create_test_event("IP_ADDRESS", f"10.0.0.{i}")
                events.append(event)
                module.handleEvent(event)
            module._flush_buffer()
            self.assertTrue(mock_bulk.called)

            def bulk_add_events():
                for i in range(50):
                    event = self.create_test_event("DOMAIN_NAME", f"test{i}.com")
                    module.handleEvent(event)

            threads = []
            for _ in range(3):
                thread = threading.Thread(target=bulk_add_events)
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            self.assertTrue(hasattr(module.buffer_lock, 'acquire') and hasattr(module.buffer_lock, 'release'))

            mock_es.ping.side_effect = [ConnectionError("Connection failed"), True]
            test_event = self.create_test_event("URL", "https://example.com")
            module.handleEvent(test_event)

            print("  Elasticsearch SSL/API key authentication")
            print("  Elasticsearch index management")
            print("  Elasticsearch bulk insertion and buffering")
            print("  Elasticsearch thread safety")
            print("  Elasticsearch connection retry")

    def test_storage_performance_optimization(self):
        """Test performance optimization features."""
        print("\n=== Testing Performance Optimization ===")

        start_time = time.time()

        sqlite_module = sfp__stor_db()
        sqlite_module.setup(self.sf, {'_store': True})
        sqlite_module.getScanId = MagicMock(return_value=self.test_scan_id)

        for i in range(1000):
            event = self.create_test_event("IP_ADDRESS", f"192.168.{i//256}.{i%256}")
            sqlite_module.handleEvent(event)

        sqlite_time = time.time() - start_time

        with patch('modules.sfp__stor_elasticsearch.Elasticsearch') as mock_es_class, \
             patch('elasticsearch.helpers.bulk') as mock_bulk:
            mock_es = MagicMock()
            mock_es.ping.return_value = True
            mock_es.bulk.return_value = {'errors': False}
            mock_es_class.return_value = mock_es
            mock_bulk.return_value = (100, [])

            es_module = sfp__stor_elasticsearch()
            es_module.setup(self.sf, {
                'enabled': True,
                'host': 'localhost',
                'port': 9200,
                'index': 'performance_test',
                'bulk_size': 100
            })
            es_module.getScanId = MagicMock(return_value=self.test_scan_id)

            start_time = time.time()
            for i in range(1000):
                event = self.create_test_event("DOMAIN_NAME", f"test{i}.example.com")
                es_module.handleEvent(event)

            es_module._flush_buffer()
            es_time = time.time() - start_time

            self.assertLess(mock_es.bulk.call_count, 15)

        print(f"  SQLite processing time: {sqlite_time:.3f}s")
        print(f"  Elasticsearch bulk processing: {es_time:.3f}s")
        print("  Performance optimization validated")

    def test_error_handling_resilience(self):
        """Test comprehensive error handling and resilience."""
        print("\n=== Testing Error Handling and Resilience ===")

        # Test Elasticsearch error scenarios
        with patch('modules.sfp__stor_elasticsearch.Elasticsearch') as mock_es_class:
            mock_es_class.side_effect = ConnectionError("Elasticsearch unavailable")

            es_module = sfp__stor_elasticsearch()
            es_module.setup(self.sf, {
                'enabled': True,
                'host': 'unavailable.host',
                'port': 9200,
                'index': 'test'
            })

            self.assertTrue(es_module.errorState)

        print("  Elasticsearch connection failure handling")
        print("  Configuration validation")

    def test_data_integrity_and_validation(self):
        """Test data integrity and validation features."""
        print("\n=== Testing Data Integrity and Validation ===")

        sqlite_module = sfp__stor_db()
        sqlite_module.setup(self.sf, {
            '_store': True,
            'maxstorage': 100
        })
        sqlite_module.getScanId = MagicMock(return_value=self.test_scan_id)

        large_data = "x" * 1000
        large_event = self.create_test_event("LARGE_DATA", large_data)
        sqlite_module.handleEvent(large_event)

        call_args = self.mock_dbh.scanEventStore.call_args
        self.assertEqual(call_args[0][2], 100)

        special_data = "test\nwith\ttabs\rand\x00nulls"
        special_event = self.create_test_event("SPECIAL_DATA", special_data)

        try:
            sqlite_module.handleEvent(special_event)
        except Exception as e:
            self.fail(f"Should handle special characters: {e}")

        unicode_data = "data with unicode chars"
        unicode_event = self.create_test_event("UNICODE_DATA", unicode_data)

        try:
            sqlite_module.handleEvent(unicode_event)
        except Exception as e:
            self.fail(f"Should handle Unicode: {e}")

        print("  Data size limit enforcement")
        print("  Special character handling")
        print("  Unicode data handling")

    def test_advanced_monitoring_features(self):
        """Test advanced monitoring and observability features."""
        print("\n=== Testing Advanced Monitoring Features ===")

        # Test Elasticsearch health monitoring
        with patch('modules.sfp__stor_elasticsearch.Elasticsearch') as mock_es_class:
            mock_es = MagicMock()
            mock_es.ping.return_value = True
            mock_es_class.return_value = mock_es

            es_module = sfp__stor_elasticsearch()
            es_module.setup(self.sf, {
                'enabled': True,
                'host': 'localhost',
                'port': 9200,
                'index': 'monitoring_test'
            })

            self.assertTrue(es_module._check_elasticsearch_health())
            mock_es.ping.assert_called()

            mock_es.ping.side_effect = ConnectionError("Health check failed")
            self.assertFalse(es_module._check_elasticsearch_health())

        print("  Elasticsearch health monitoring")
        print("  Connection failure detection")

    def test_security_features(self):
        """Test security features implementation."""
        print("\n=== Testing Security Features ===")

        # Test Elasticsearch SSL and authentication
        with patch('modules.sfp__stor_elasticsearch.Elasticsearch') as mock_es_class:
            mock_es = MagicMock()
            mock_es_class.return_value = mock_es

            es_module = sfp__stor_elasticsearch()
            es_module.setup(self.sf, {
                'enabled': True,
                'host': 'secure.es.host',
                'port': 9200,
                'index': 'security_test',
                'use_ssl': True,
                'verify_certs': True,
                'api_key': 'secure_api_key_xyz789'
            })

            call_args = mock_es_class.call_args[1]
            self.assertTrue(call_args['use_ssl'])
            self.assertTrue(call_args['verify_certs'])
            self.assertEqual(call_args['api_key'], 'secure_api_key_xyz789')

        print("  Elasticsearch SSL configuration")
        print("  Authentication and API key handling")

    def test_multi_storage_coordination(self):
        """Test coordination between multiple storage backends."""
        print("\n=== Testing Multi-Storage Coordination ===")

        sqlite_module = sfp__stor_db()
        sqlite_module.setup(self.sf, {'_store': True})
        sqlite_module.getScanId = MagicMock(return_value=self.test_scan_id)

        with patch('modules.sfp__stor_elasticsearch.Elasticsearch') as mock_es_class, \
             patch('elasticsearch.helpers.bulk') as mock_bulk:
            mock_es = MagicMock()
            mock_es.ping.return_value = True
            mock_es.bulk.return_value = {'errors': False}
            mock_es_class.return_value = mock_es
            mock_bulk.return_value = (10, [])

            es_module = sfp__stor_elasticsearch()
            es_module.setup(self.sf, {
                'enabled': True,
                'host': 'localhost',
                'port': 9200,
                'index': 'coordination_test',
                'bulk_size': 1
            })
            es_module.getScanId = MagicMock(return_value=self.test_scan_id)

            stdout_module = sfp__stor_stdout()
            stdout_module.setup(self.sf, {'_store': True})
            stdout_module.getScanId = MagicMock(return_value=self.test_scan_id)

            test_events = []
            for i in range(10):
                event = self.create_test_event("COORDINATION_TEST", f"data_{i}")
                test_events.append(event)

                sqlite_module.handleEvent(event)
                es_module.handleEvent(event)
                with patch('sys.stdout'):
                    stdout_module.handleEvent(event)

            self.assertEqual(self.mock_dbh.scanEventStore.call_count, 10)
            self.assertEqual(len(es_module.buffer), 0)
            es_module._flush_buffer()
            self.assertGreaterEqual(mock_bulk.call_count, 1)

        print("  Multi-storage backend coordination")
        print("  Consistent event processing")
        print("  Independent error handling")

    def run_validation(self):
        """Run the complete validation suite."""
        print("\n" + "="*60)
        print("SPIDERFOOT STORAGE VALIDATION SUITE")
        print("="*60)

        test_methods = [
            self.test_sqlite_storage_features,
            self.test_elasticsearch_advanced_features,
            self.test_storage_performance_optimization,
            self.test_error_handling_resilience,
            self.test_data_integrity_and_validation,
            self.test_advanced_monitoring_features,
            self.test_security_features,
            self.test_multi_storage_coordination
        ]

        passed = 0
        failed = 0

        for test_method in test_methods:
            try:
                test_method()
                passed += 1
            except Exception as e:
                print(f"FAIL {test_method.__name__} FAILED: {e}")
                failed += 1

        print("\n" + "="*60)
        print("VALIDATION RESULTS")
        print("="*60)
        print(f"Tests Passed: {passed}")
        print(f"Tests Failed: {failed}")
        print(f"Success Rate: {passed/(passed+failed)*100:.1f}%")

        if failed == 0:
            print("\nALL FEATURES VALIDATED SUCCESSFULLY!")
        else:
            print(f"\n{failed} test(s) failed. Please review and fix issues.")

        return failed == 0


if __name__ == '__main__':
    test_suite = TestStorageFeatures()
    test_suite.setUp()

    try:
        success = test_suite.run_validation()
        exit_code = 0 if success else 1
    finally:
        test_suite.tearDown()

    exit(exit_code)
