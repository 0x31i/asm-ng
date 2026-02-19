# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         db_backend
# Purpose:      Database backend abstraction for SQLite and PostgreSQL.
#
# Created:      2026-02-19
# Licence:      MIT
# -------------------------------------------------------------------------------

"""Thin database backend abstraction layer.

Provides a unified interface for SQLite and PostgreSQL so that
``SpiderFootDb`` can work with either backend transparently.
The key trick: ``PgCursorWrapper`` converts SQLite-style ``?``
parameter markers to PostgreSQL-style ``%s`` automatically,
meaning the 200+ SQL queries in db.py don't need individual edits.
"""

import logging
import os
import sqlite3

log = logging.getLogger(f"spiderfoot.{__name__}")

# ---------------------------------------------------------------------------
# Conditional psycopg2 import
# ---------------------------------------------------------------------------
try:
    import psycopg2
    import psycopg2.extras
    import psycopg2.pool
    HAS_PSYCOPG2 = True
except ImportError:
    psycopg2 = None  # type: ignore[assignment]
    HAS_PSYCOPG2 = False

# ---------------------------------------------------------------------------
# Unified exception types that catch errors from *either* backend.
# Use these in ``except`` clauses instead of ``sqlite3.Error``.
# ---------------------------------------------------------------------------
if HAS_PSYCOPG2:
    DatabaseError = (sqlite3.Error, psycopg2.Error)
    OperationalError = (sqlite3.OperationalError, psycopg2.OperationalError)
else:
    DatabaseError = sqlite3.Error
    OperationalError = sqlite3.OperationalError


# ---------------------------------------------------------------------------
# PostgreSQL cursor wrapper
# ---------------------------------------------------------------------------
class PgCursorWrapper:
    """Thin wrapper around a psycopg2 cursor that converts ``?`` parameter
    markers to ``%s`` so existing SQLite-style queries work unchanged.

    Also wraps ``executemany`` for batch inserts.
    """

    def __init__(self, cursor):
        self._cursor = cursor

    # --- query helpers --------------------------------------------------------

    @staticmethod
    def _convert_params(query: str) -> str:
        """Replace SQLite ``?`` placeholders with PostgreSQL ``%s``.

        This is safe because:
        - ``?`` only appears as parameter markers in our SQL
        - String literals are passed as bound parameters, never interpolated
        """
        return query.replace('?', '%s')

    # --- cursor interface -----------------------------------------------------

    def execute(self, query, params=None):
        pg_query = self._convert_params(query)
        if params:
            return self._cursor.execute(pg_query, params)
        return self._cursor.execute(pg_query)

    def executemany(self, query, params_list):
        pg_query = self._convert_params(query)
        return self._cursor.executemany(pg_query, params_list)

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    def fetchmany(self, size=None):
        if size is not None:
            return self._cursor.fetchmany(size)
        return self._cursor.fetchmany()

    def close(self):
        return self._cursor.close()

    @property
    def description(self):
        return self._cursor.description

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        """psycopg2 doesn't support ``lastrowid`` the same way sqlite3 does.
        Return None; callers that need the inserted ID should use
        ``RETURNING id`` in their INSERT statement instead.
        """
        return getattr(self._cursor, 'lastrowid', None)


# ---------------------------------------------------------------------------
# Connection factory
# ---------------------------------------------------------------------------

def detect_db_type(opts: dict) -> str:
    """Determine which database backend to use.

    Priority:
    1. ``ASMNG_DATABASE_URL`` env var → postgresql
    2. ``ASMNG_DB_TYPE`` env var → explicit choice
    3. ``opts['__dbtype']`` config key → explicit choice
    4. Probe localhost:5432 with default creds → postgresql
    5. Fallback → sqlite

    Returns:
        str: ``'postgresql'`` or ``'sqlite'``
    """
    # 1. Explicit DSN env var
    if os.environ.get('ASMNG_DATABASE_URL'):
        return 'postgresql'

    # 2. Explicit type env var
    env_type = os.environ.get('ASMNG_DB_TYPE', '').lower()
    if env_type in ('postgresql', 'postgres', 'pg'):
        return 'postgresql'
    if env_type == 'sqlite':
        return 'sqlite'

    # 3. Config key
    cfg_type = opts.get('__dbtype', '').lower()
    if cfg_type in ('postgresql', 'postgres', 'pg'):
        return 'postgresql'
    if cfg_type == 'sqlite':
        return 'sqlite'

    # 4. Probe PostgreSQL on localhost
    if HAS_PSYCOPG2:
        dsn = _build_pg_dsn(opts)
        try:
            test_conn = psycopg2.connect(dsn, connect_timeout=3)
            test_conn.close()
            log.info("Auto-detected PostgreSQL on localhost. Using PostgreSQL backend.")
            return 'postgresql'
        except Exception:
            pass

    # 5. Fallback
    log.info("PostgreSQL not available. Using SQLite backend.")
    return 'sqlite'


def _build_pg_dsn(opts: dict) -> str:
    """Build a PostgreSQL DSN from environment variables or config defaults.

    Priority: ASMNG_DATABASE_URL > individual PG_* env vars > opts > hardcoded defaults.
    """
    dsn = os.environ.get('ASMNG_DATABASE_URL')
    if dsn:
        return dsn

    host = os.environ.get('PG_HOST', opts.get('__pg_host', 'localhost'))
    port = os.environ.get('PG_PORT', opts.get('__pg_port', '5432'))
    dbname = os.environ.get('PG_DATABASE', opts.get('__pg_database', 'asmng'))
    user = os.environ.get('PG_USER', opts.get('__pg_user', 'admin'))
    password = os.environ.get('PG_PASSWORD', opts.get('__pg_password', 'admin'))

    return f"postgresql://{user}:{password}@{host}:{port}/{dbname}"


def create_sqlite_connection(opts: dict):
    """Create a SQLite connection and cursor with hardening PRAGMAs.

    Args:
        opts: config dict; must contain ``'__database'`` key.

    Returns:
        tuple: ``(connection, cursor, 'sqlite')``
    """
    from pathlib import Path

    database_path = opts['__database']
    Path(database_path).parent.mkdir(exist_ok=True, parents=True)

    conn = sqlite3.connect(database_path, timeout=30)
    conn.text_factory = str
    cursor = conn.cursor()

    # SQLite hardening PRAGMAs
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=30000")

    # Resource-tier-based cache/mmap tuning
    try:
        from spiderfoot.resource_tiers import get_tier_config
        _tier = get_tier_config(opts.get('_resource_tier', 'medium'))
    except Exception:
        _tier = {'sqlite_cache_size': -128000, 'sqlite_mmap_size': 536870912}

    cache_size = os.environ.get('ASMNG_SQLITE_CACHE_SIZE', _tier['sqlite_cache_size'])
    try:
        int(cache_size)
    except ValueError:
        cache_size = _tier['sqlite_cache_size']
    cursor.execute(f"PRAGMA cache_size={cache_size}")

    cursor.execute("PRAGMA temp_store=MEMORY")

    mmap_size = os.environ.get('ASMNG_SQLITE_MMAP_SIZE', _tier['sqlite_mmap_size'])
    try:
        int(mmap_size)
    except ValueError:
        mmap_size = _tier['sqlite_mmap_size']
    cursor.execute(f"PRAGMA mmap_size={mmap_size}")

    cursor.execute("PRAGMA foreign_keys=ON")

    # Register custom REGEXP function
    import re

    def _dbregex(qry: str, data: str) -> bool:
        try:
            rx = re.compile(qry, re.IGNORECASE | re.DOTALL)
            return rx.match(data) is not None
        except Exception:
            return False

    conn.create_function("REGEXP", 2, _dbregex)

    # Startup integrity check
    if opts.get('__db_init'):
        try:
            cursor.execute("PRAGMA quick_check")
            result = cursor.fetchone()
            if result and result[0] != 'ok':
                log.warning(f"SQLite integrity check warning: {result[0]}")
        except sqlite3.Error as e:
            log.warning(f"SQLite integrity check failed: {e}")

    return conn, cursor, 'sqlite'


def create_pg_connection(opts: dict):
    """Create a PostgreSQL connection and wrapped cursor.

    Args:
        opts: config dict.

    Returns:
        tuple: ``(connection, PgCursorWrapper, 'postgresql')``
    """
    if not HAS_PSYCOPG2:
        raise ImportError(
            "psycopg2 is required for PostgreSQL support. "
            "Install it with: pip install psycopg2-binary"
        )

    dsn = _build_pg_dsn(opts)
    conn = psycopg2.connect(dsn)
    conn.autocommit = False
    cursor = PgCursorWrapper(conn.cursor())

    return conn, cursor, 'postgresql'


def create_connection(opts: dict):
    """Create a database connection using the detected or configured backend.

    Args:
        opts: config dict.

    Returns:
        tuple: ``(connection, cursor_or_wrapper, db_type_str)``
    """
    db_type = detect_db_type(opts)

    if db_type == 'postgresql':
        try:
            return create_pg_connection(opts)
        except Exception as e:
            log.warning(
                f"Failed to connect to PostgreSQL: {e}. "
                "Falling back to SQLite."
            )
            if not opts.get('__database'):
                raise
            return create_sqlite_connection(opts)

    return create_sqlite_connection(opts)


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

# PostgreSQL schema variant: replaces AUTOINCREMENT with SERIAL,
# drops the PRAGMA, and uses standard SQL throughout.
def get_pg_schema_queries(sqlite_queries: list) -> list:
    """Convert SQLite schema DDL to PostgreSQL-compatible DDL.

    Args:
        sqlite_queries: the ``createSchemaQueries`` list from SpiderFootDb.

    Returns:
        list: PostgreSQL-compatible DDL statements.
    """
    pg_queries = []
    for qry in sqlite_queries:
        # Skip SQLite PRAGMAs
        if qry.strip().upper().startswith('PRAGMA'):
            continue

        # Convert AUTOINCREMENT to SERIAL
        converted = qry.replace(
            'INTEGER PRIMARY KEY AUTOINCREMENT',
            'SERIAL PRIMARY KEY'
        )

        pg_queries.append(converted)

    return pg_queries


def get_raw_connection(opts: dict):
    """Create a minimal raw database connection for emergency/bypass use.

    Used by sfscan.py ``__forceTerminalStatus()``, sfwebui.py orphan cleanup,
    and other places that bypass SpiderFootDb.

    Args:
        opts: config dict.

    Returns:
        A raw database connection (sqlite3.Connection or psycopg2 connection).
    """
    db_type = detect_db_type(opts)

    if db_type == 'postgresql':
        if not HAS_PSYCOPG2:
            # Fall back to sqlite
            return sqlite3.connect(opts['__database'], timeout=30)
        dsn = _build_pg_dsn(opts)
        conn = psycopg2.connect(dsn)
        return conn

    return sqlite3.connect(opts['__database'], timeout=30)


def raw_execute(conn, query, params=None):
    """Execute a query on a raw connection, handling parameter style conversion.

    For psycopg2 connections, converts ``?`` to ``%s``.

    Args:
        conn: raw database connection.
        query: SQL query string.
        params: query parameters.

    Returns:
        cursor from the execution.
    """
    if HAS_PSYCOPG2 and isinstance(conn, psycopg2.extensions.connection):
        pg_query = query.replace('?', '%s')
        cursor = conn.cursor()
        if params:
            cursor.execute(pg_query, params)
        else:
            cursor.execute(pg_query)
        return cursor

    if params:
        return conn.execute(query, params)
    return conn.execute(query)
