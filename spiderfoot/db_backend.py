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
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time as _time

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
# PostgreSQL connection pool (singleton)
# ---------------------------------------------------------------------------
_pg_pool = None
_pg_pool_lock = threading.Lock()

# Cache the detected database type so we don't re-probe on every instantiation.
_cached_db_type = None


def _get_pg_pool(dsn: str):
    """Get or create the PostgreSQL connection pool (thread-safe singleton).

    Pool size is configurable via ASMNG_PG_POOL_MAX env var (default 20).
    """
    global _pg_pool
    if _pg_pool is not None:
        return _pg_pool
    with _pg_pool_lock:
        if _pg_pool is None:
            max_conn = int(os.environ.get('ASMNG_PG_POOL_MAX', '20'))
            _pg_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=2, maxconn=max_conn, dsn=dsn
            )
            log.info(f"PostgreSQL connection pool created (max={max_conn})")
    return _pg_pool


def return_pg_connection(conn) -> None:
    """Return a PostgreSQL connection to the pool instead of closing it.

    Resets connection state (rolls back any pending transaction) before
    returning.  If the connection is broken, it is discarded from the pool.
    """
    global _pg_pool
    if _pg_pool is None:
        try:
            conn.close()
        except Exception:
            pass
        return
    try:
        if conn.closed:
            _pg_pool.putconn(conn, close=True)
        else:
            conn.rollback()
            conn.autocommit = False
            _pg_pool.putconn(conn)
    except Exception:
        try:
            _pg_pool.putconn(conn, close=True)
        except Exception:
            pass


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
# PostgreSQL auto-setup helpers
# ---------------------------------------------------------------------------

def _get_sentinel_path() -> str:
    """Return the path to the PostgreSQL auto-setup sentinel file.

    Stored in the ``data/`` directory (git-ignored) so it persists across
    restarts but is never committed.
    """
    try:
        from spiderfoot.helpers import SpiderFootHelpers
        return os.path.join(SpiderFootHelpers.dataPath(), '.pg_setup_attempted')
    except Exception:
        base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, '.pg_setup_attempted')


def _read_sentinel() -> dict:
    """Read the sentinel file. Returns dict with 'status' key, or empty dict if not found."""
    path = _get_sentinel_path()
    if not os.path.exists(path):
        return {}
    try:
        result = {}
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    result[k.strip()] = v.strip()
        return result
    except Exception:
        return {}


def _write_sentinel(status: str, reason: str) -> None:
    """Write the sentinel file recording auto-setup outcome."""
    path = _get_sentinel_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(f"status={status}\n")
            f.write(f"timestamp={int(_time.time())}\n")
            f.write(f"reason={reason}\n")
    except Exception as e:
        log.warning(f"Could not write PG setup sentinel file: {e}")


def _detect_pkg_manager() -> str:
    """Detect the available package manager.

    Returns:
        str: ``'apt'``, ``'brew'``, ``'dnf'``, ``'yum'``, or ``''`` if none found.
    """
    if shutil.which('apt-get'):
        return 'apt'
    if shutil.which('brew'):
        return 'brew'
    if shutil.which('dnf'):
        return 'dnf'
    if shutil.which('yum'):
        return 'yum'
    return ''


def _can_run_auto_setup() -> tuple:
    """Check whether auto-setup can be attempted.

    Supports Linux (apt-get, dnf, yum) and macOS (Homebrew).

    Returns:
        tuple: (can_run: bool, reason: str)
    """
    # Check opt-out env var
    opt_out = os.environ.get('ASMNG_PG_AUTO_SETUP', '').lower()
    if opt_out in ('0', 'false', 'no', 'off'):
        return False, "Auto-setup disabled via ASMNG_PG_AUTO_SETUP=0"

    # Check platform — support Linux and macOS
    if sys.platform not in ('linux', 'darwin'):
        return False, (
            f"Auto-setup not supported on {sys.platform}. "
            "Install PostgreSQL manually and set ASMNG_DATABASE_URL."
        )

    # Check for a supported package manager
    pkg_mgr = _detect_pkg_manager()
    if not pkg_mgr:
        return False, (
            "No supported package manager found (apt-get, brew, dnf, yum). "
            "Install PostgreSQL manually."
        )

    # macOS + Homebrew: no root needed (brew runs as user)
    if sys.platform == 'darwin' and pkg_mgr == 'brew':
        return True, "macOS with Homebrew"

    # Linux: need root or sudo
    if os.geteuid() == 0:
        return True, f"Running as root ({pkg_mgr})"

    # Test non-interactive sudo
    try:
        result = subprocess.run(
            ['sudo', '-n', 'true'],
            capture_output=True, timeout=5
        )
        if result.returncode == 0:
            return True, f"Passwordless sudo available ({pkg_mgr})"
    except Exception:
        pass

    return False, "No root/sudo access available"


def _attempt_pg_auto_setup(opts: dict) -> bool:
    """Attempt to automatically install and configure PostgreSQL.

    Runs ``setup-postgresql.sh`` via subprocess. Only executes on first startup
    (no sentinel file) and only on supported systems with the right privileges.
    Supports Linux (apt, dnf, yum + root/sudo) and macOS (Homebrew, no root).

    Returns:
        bool: True if PostgreSQL was successfully set up.
    """
    # Check sentinel (idempotency guard)
    sentinel = _read_sentinel()
    if sentinel:
        status = sentinel.get('status', '')
        reason = sentinel.get('reason', '')
        if status == 'success':
            log.debug("PG auto-setup previously succeeded; skipping re-run.")
            return False
        elif status == 'failed':
            # Check if setup script has been updated since the failure
            script_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), '..', 'setup-postgresql.sh')
            )
            sentinel_ts = int(sentinel.get('timestamp', '0'))
            try:
                script_mtime = int(os.path.getmtime(script_path))
            except OSError:
                script_mtime = 0

            if script_mtime > sentinel_ts:
                log.info(
                    f"PG auto-setup previously failed ({reason}) but setup "
                    "script has been updated. Retrying..."
                )
                try:
                    os.remove(_get_sentinel_path())
                except OSError:
                    pass
                # Fall through to re-run setup
            else:
                log.info(
                    f"PG auto-setup previously failed ({reason}). "
                    f"To retry, delete: {_get_sentinel_path()}"
                )
                return False
        elif status == 'skipped':
            # Re-evaluate: conditions may have changed (e.g., code update
            # added macOS support, user installed brew, gained sudo, etc.)
            can_run_now, _ = _can_run_auto_setup()
            if not can_run_now:
                log.debug(f"PG auto-setup was previously skipped: {reason}")
                return False
            # Conditions changed — clear stale sentinel and retry
            log.info(
                f"PG auto-setup was previously skipped ({reason}) "
                "but conditions have changed. Retrying..."
            )
            try:
                os.remove(_get_sentinel_path())
            except OSError:
                pass

    # Check preconditions
    can_run, reason = _can_run_auto_setup()
    if not can_run:
        log.warning(
            f"Cannot auto-setup PostgreSQL: {reason}. "
            "Falling back to SQLite. "
            "To set up PostgreSQL manually, run: ./setup-postgresql.sh"
        )
        _write_sentinel('skipped', reason)
        return False

    # Locate the setup script
    script_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', 'setup-postgresql.sh')
    )
    if not os.path.isfile(script_path):
        log.warning(
            f"PostgreSQL setup script not found at {script_path}. "
            "Falling back to SQLite."
        )
        _write_sentinel('failed', 'setup-postgresql.sh not found')
        return False

    # Run the setup script
    log.info(
        "PostgreSQL is not running. Attempting automatic setup... "
        "(this may take a minute on first run)"
    )

    try:
        cmd = ['bash', script_path]
        # On Linux, use sudo if not already root.
        # On macOS, run without sudo (brew must NOT run as root).
        if sys.platform != 'darwin' and os.geteuid() != 0:
            cmd = ['sudo'] + cmd

        env = os.environ.copy()
        env['PG_USER'] = opts.get('__pg_user', 'admin')
        env['PG_PASSWORD'] = opts.get('__pg_password', 'admin')
        env['PG_DATABASE'] = opts.get('__pg_database', 'asmng')

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )

        if result.returncode == 0:
            log.info("PostgreSQL auto-setup completed successfully.")
            _write_sentinel('success', 'PostgreSQL installed and configured')
            return True
        else:
            # Script writes info/error messages to stdout; capture both
            output = (result.stdout or '') + (result.stderr or '')
            output_snippet = output.strip()[-500:]
            log.warning(
                f"PostgreSQL auto-setup failed (exit code {result.returncode}). "
                f"Output:\n{output_snippet}"
            )
            _write_sentinel('failed', f'Exit code {result.returncode}: {output.strip()[-200:]}')
            return False

    except subprocess.TimeoutExpired:
        log.warning("PostgreSQL auto-setup timed out after 120 seconds.")
        _write_sentinel('failed', 'Timed out after 120s')
        return False
    except Exception as e:
        log.warning(f"PostgreSQL auto-setup error: {e}")
        _write_sentinel('failed', str(e)[:200])
        return False


# ---------------------------------------------------------------------------
# Connection factory
# ---------------------------------------------------------------------------

def detect_db_type(opts: dict) -> str:
    """Determine which database backend to use.

    The result is cached after the first call so that subsequent
    ``SpiderFootDb()`` instantiations don't re-probe PostgreSQL
    (which would leak a file descriptor per probe).

    Priority:
    1. ``ASMNG_DATABASE_URL`` env var → postgresql
    2. ``ASMNG_DB_TYPE`` env var → explicit choice
    3. ``opts['__dbtype']`` config key → explicit choice
    4. Probe localhost:5432 with default creds → postgresql
    5. Fallback → sqlite

    Returns:
        str: ``'postgresql'`` or ``'sqlite'``
    """
    global _cached_db_type
    if _cached_db_type is not None:
        return _cached_db_type

    result = _detect_db_type_uncached(opts)
    _cached_db_type = result
    return result


def _detect_db_type_uncached(opts: dict) -> str:
    """Internal: perform the actual database type detection (called once)."""

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
            # PostgreSQL not reachable -- attempt auto-setup if first run
            setup_ok = _attempt_pg_auto_setup(opts)
            if setup_ok:
                # Re-probe after setup
                try:
                    test_conn = psycopg2.connect(dsn, connect_timeout=5)
                    test_conn.close()
                    log.info("PostgreSQL is now available after auto-setup. Using PostgreSQL backend.")
                    return 'postgresql'
                except Exception as e:
                    log.warning(
                        f"PostgreSQL auto-setup completed but connection still failed: {e}. "
                        "Falling back to SQLite."
                    )

    # 5. Fallback
    if not HAS_PSYCOPG2:
        log.info(
            "psycopg2 not installed. Using SQLite backend. "
            "Install psycopg2-binary for PostgreSQL support: pip install psycopg2-binary"
        )
    else:
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

    Connections are drawn from a shared ``ThreadedConnectionPool`` so that
    the total number of open PostgreSQL connections stays bounded.

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
    pool = _get_pg_pool(dsn)

    # Retry with backoff if the pool is temporarily exhausted
    conn = None
    for attempt in range(5):
        try:
            conn = pool.getconn()
            break
        except psycopg2.pool.PoolError:
            if attempt < 4:
                log.debug(f"Connection pool exhausted, retrying ({attempt + 1}/5)...")
                _time.sleep(0.2 * (attempt + 1))
            else:
                raise

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
        # Don't silently fall back to SQLite — that splits data across two
        # databases and causes the exact errors the user sees.  Let
        # connection errors propagate so they are visible.
        return create_pg_connection(opts)

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

        # SQLite INT is variable-length (up to 8 bytes), but PostgreSQL INT
        # is strictly 32-bit (max ~2.1 billion).  Millisecond timestamps
        # (e.g. int(time.time() * 1000) ≈ 1.77 trillion) overflow INT.
        # Convert all remaining INT columns to BIGINT (8-byte).
        converted = re.sub(r'\bINT\b', 'BIGINT', converted)

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
