# -*- coding: utf-8 -*-
"""Database fixtures for testing SpiderFoot database operations."""

import pytest
import tempfile
import os
import psycopg2
from unittest.mock import Mock, MagicMock, patch
from spiderfoot import SpiderFootDb
from spiderfoot.event import SpiderFootEvent
from spiderfoot.db_backend import DatabaseError, OperationalError


# PostgreSQL test database DSN — set this env var to enable DB tests.
PG_TEST_DSN = os.environ.get('ASMNG_TEST_DATABASE_URL', '')

requires_pg = pytest.mark.skipif(
    not PG_TEST_DSN,
    reason="ASMNG_TEST_DATABASE_URL not set — PostgreSQL not available for testing"
)


@pytest.fixture
def pg_test_dsn():
    """Return the PostgreSQL test database DSN, or skip if not available."""
    if not PG_TEST_DSN:
        pytest.skip("ASMNG_TEST_DATABASE_URL not set")
    return PG_TEST_DSN


@pytest.fixture
def temp_db_path(pg_test_dsn):
    """Provide PostgreSQL test database DSN.

    This fixture replaces the old SQLite temp file approach.
    Tests that used to pass a file path as ``__database`` now
    receive the PostgreSQL DSN string instead.
    """
    return pg_test_dsn


@pytest.fixture
def mock_db_config():
    """Mock database configuration."""
    return {
        '__database': PG_TEST_DSN or 'postgresql://localhost:5432/asmng_test',
    }


@pytest.fixture
def sample_scan_data():
    """Sample scan data for testing."""
    return {
        'scan_id': 'test-scan-123',
        'name': 'Test Scan',
        'seed_target': 'example.com',
        'created': 1640995200,  # 2022-01-01 00:00:00
        'started': 1640995260,  # 2022-01-01 00:01:00
        'ended': 1640995560,    # 2022-01-01 00:06:00
        'status': 'FINISHED'
    }


@pytest.fixture
def sample_target_data():
    """Sample target data for testing."""
    return {
        'target_value': 'example.com',
        'target_type': 'INTERNET_NAME',
        'matches': '.*'
    }


@pytest.fixture
def sample_event_data():
    """Sample event data for testing."""
    return {
        'event_type': 'INTERNET_NAME',
        'event_data': 'example.com',
        'module': 'sfp_dnsresolve',
        'confidence': 100,
        'visibility': 100,
        'risk': 0,
        'source_event_hash': 'ROOT'
    }


@pytest.fixture
def sample_spiderfoot_event():
    """Create a sample SpiderFootEvent for testing."""
    return SpiderFootEvent(
        eventType='INTERNET_NAME',
        data='example.com',
        module='sfp_dnsresolve'
    )


@pytest.fixture
def multiple_events():
    """Create multiple test events."""
    events = []
    event_types = ['INTERNET_NAME', 'IP_ADDRESS', 'DOMAIN_NAME', 'URL_FORM']
    for i, event_type in enumerate(event_types):
        event = SpiderFootEvent(
            eventType=event_type,
            data=f'test-data-{i}',
            module=f'test-module-{i}'
        )
        events.append(event)
    return events


@pytest.fixture
def mock_db_connection():
    """Mock database connection with common methods."""
    mock_conn = Mock()
    mock_cursor = Mock()

    # Mock cursor methods
    mock_cursor.execute = Mock()
    mock_cursor.fetchone = Mock()
    mock_cursor.fetchall = Mock()
    mock_cursor.fetchmany = Mock()
    mock_cursor.rowcount = 0

    # Mock connection methods
    mock_conn.cursor = Mock(return_value=mock_cursor)
    mock_conn.commit = Mock()
    mock_conn.rollback = Mock()
    mock_conn.close = Mock()

    return mock_conn, mock_cursor


@pytest.fixture
def db_schema_tables():
    """Database schema table definitions for testing."""
    return [
        'tbl_scan_config',
        'tbl_scan_instance',
        'tbl_scan_log',
        'tbl_scan_results',
        'tbl_event_types',
        'tbl_config'
    ]


@pytest.fixture
def sample_scan_config():
    """Sample scan configuration data."""
    return {
        'scan_id': 'test-scan-123',
        'config': '{"modules": ["sfp_dnsresolve", "sfp_whois"], "settings": {}}',
        'created_tm': 1640995200
    }


@pytest.fixture
def sample_scan_log():
    """Sample scan log entries."""
    return [
        {
            'scan_instance_id': 'test-scan-123',
            'generated': 1640995200,
            'component': 'sfp_dnsresolve',
            'type': 'INFO',
            'message': 'Starting DNS resolution'
        },
        {
            'scan_instance_id': 'test-scan-123',
            'generated': 1640995260,
            'component': 'sfp_dnsresolve',
            'type': 'ERROR',
            'message': 'DNS resolution failed'
        }
    ]


@pytest.fixture
def database_error_scenarios():
    """Common database error scenarios for testing."""
    return {
        'connection_error': psycopg2.OperationalError("connection refused"),
        'syntax_error': psycopg2.errors.SyntaxError("syntax error at or near \"FROM\""),
        'integrity_error': psycopg2.IntegrityError("duplicate key value violates unique constraint"),
        'data_error': psycopg2.DataError("invalid input syntax"),
        'database_error': psycopg2.DatabaseError("database error")
    }


class MockSpiderFootDb:
    """Mock SpiderFootDb class for testing."""

    def __init__(self, config=None):
        self.config = config or {}
        self.dbh = Mock()
        self.db_type = 'postgresql'
        self.connection_error = False

    def configGet(self, opt, default=None):
        return self.config.get(opt, default)

    def scanInstanceCreate(self, scanId, scanName, scanTarget):
        if self.connection_error:
            raise psycopg2.OperationalError("Connection failed")
        return True

    def scanEventStore(self, scanId, sfEvent):
        if self.connection_error:
            raise psycopg2.OperationalError("Connection failed")
        return True

    def scanResultEvent(self, instanceId, eventType=None, filterFp=None):
        if self.connection_error:
            raise psycopg2.OperationalError("Connection failed")
        return []

    def scanInstanceGet(self, instanceId):
        if self.connection_error:
            raise psycopg2.OperationalError("Connection failed")
        return None


@pytest.fixture
def mock_spiderfoot_db():
    """Create a mock SpiderFootDb instance."""
    return MockSpiderFootDb()


@pytest.fixture
def mock_db_cursor():
    cursor = MagicMock()
    yield cursor
