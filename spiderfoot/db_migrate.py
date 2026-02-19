# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         db_migrate
# Purpose:      Bidirectional data migration between SQLite and PostgreSQL.
#
# Created:      2026-02-19
# Licence:      MIT
# -------------------------------------------------------------------------------

"""Bidirectional data migration tool for ASM-NG.

Supports:
- SQLite → PostgreSQL (forward migration)
- PostgreSQL → SQLite (reverse migration)

Usage (CLI):
    python -m spiderfoot.db_migrate --direction sqlite-to-pg \\
        --sqlite ~/.spiderfoot/spiderfoot.db \\
        --pg-dsn postgresql://admin:admin@localhost:5432/asmng

    python -m spiderfoot.db_migrate --direction pg-to-sqlite \\
        --sqlite ~/.spiderfoot/spiderfoot.db \\
        --pg-dsn postgresql://admin:admin@localhost:5432/asmng
"""

import argparse
import logging
import sqlite3
import sys
import time

log = logging.getLogger(f"spiderfoot.{__name__}")

# Table migration order: parent tables first, then children (FK dependencies).
MIGRATION_TABLE_ORDER = [
    'tbl_event_types',
    'tbl_config',
    'tbl_users',
    'tbl_scan_instance',
    'tbl_scan_log',
    'tbl_scan_config',
    'tbl_scan_results',
    'tbl_scan_correlation_results',
    'tbl_scan_correlation_results_events',
    'tbl_scan_findings',
    'tbl_scan_nessus_results',
    'tbl_scan_burp_results',
    'tbl_target_false_positives',
    'tbl_target_validated',
    'tbl_audit_log',
    'tbl_known_assets',
    'tbl_asset_import_history',
]

BATCH_SIZE = 1000


def _get_table_columns(cursor, table_name, db_type):
    """Get column names for a table."""
    if db_type == 'postgresql':
        cursor.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = %s ORDER BY ordinal_position",
            (table_name,))
        return [row[0] for row in cursor.fetchall()]
    else:
        cursor.execute(f"PRAGMA table_info({table_name})")
        return [row[1] for row in cursor.fetchall()]


def _table_exists(cursor, table_name, db_type):
    """Check if a table exists."""
    if db_type == 'postgresql':
        cursor.execute(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_name = %s)",
            (table_name,))
        return cursor.fetchone()[0]
    else:
        cursor.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type='table' AND name=?",
            (table_name,))
        return cursor.fetchone()[0] > 0


def _count_rows(cursor, table_name, db_type):
    """Count rows in a table."""
    if db_type == 'postgresql':
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
    else:
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
    return cursor.fetchone()[0]


def _reset_pg_sequences(pg_cursor, table_name, columns):
    """Reset PostgreSQL SERIAL sequences after data load."""
    # Only tables with 'id' as SERIAL need sequence reset
    if 'id' not in columns:
        return
    seq_name = f"{table_name}_id_seq"
    try:
        pg_cursor.execute(
            f"SELECT setval('{seq_name}', COALESCE((SELECT MAX(id) FROM {table_name}), 0) + 1, false)")
    except Exception:
        pass  # Sequence may not exist for non-SERIAL id columns


def migrate_sqlite_to_pg(sqlite_path, pg_dsn, progress_callback=None):
    """Migrate all data from SQLite to PostgreSQL.

    Args:
        sqlite_path: path to SQLite database file.
        pg_dsn: PostgreSQL DSN string.
        progress_callback: optional callable(table_name, rows_done, total_rows).

    Returns:
        dict: migration results with row counts per table.
    """
    try:
        import psycopg2
    except ImportError:
        raise ImportError("psycopg2 is required for PostgreSQL migration. "
                          "Install it with: pip install psycopg2-binary")

    results = {}
    start_time = time.time()

    # Connect to both databases
    sqlite_conn = sqlite3.connect(sqlite_path, timeout=30)
    sqlite_cursor = sqlite_conn.cursor()

    pg_conn = psycopg2.connect(pg_dsn)
    pg_conn.autocommit = False
    pg_cursor = pg_conn.cursor()

    try:
        for table in MIGRATION_TABLE_ORDER:
            # Check if source table exists
            if not _table_exists(sqlite_cursor, table, 'sqlite'):
                log.info(f"Skipping {table}: does not exist in SQLite")
                results[table] = {'status': 'skipped', 'reason': 'not in source'}
                continue

            # Check if target table exists
            if not _table_exists(pg_cursor, table, 'postgresql'):
                log.warning(f"Skipping {table}: does not exist in PostgreSQL "
                            "(run schema creation first)")
                results[table] = {'status': 'skipped', 'reason': 'not in target'}
                continue

            # Get column info from both sides
            sqlite_cols = _get_table_columns(sqlite_cursor, table, 'sqlite')
            pg_cols = _get_table_columns(pg_cursor, table, 'postgresql')

            # Use intersection of columns (handles schema differences gracefully)
            common_cols = [c for c in sqlite_cols if c in pg_cols]
            if not common_cols:
                log.warning(f"Skipping {table}: no common columns")
                results[table] = {'status': 'skipped', 'reason': 'no common columns'}
                continue

            col_list = ', '.join(common_cols)
            placeholders = ', '.join(['%s'] * len(common_cols))
            col_indices = [sqlite_cols.index(c) for c in common_cols]

            # Count source rows
            total_rows = _count_rows(sqlite_cursor, table, 'sqlite')
            log.info(f"Migrating {table}: {total_rows} rows")

            if progress_callback:
                progress_callback(table, 0, total_rows)

            # Clear target table
            pg_cursor.execute(f"DELETE FROM {table}")

            # Batch-read from SQLite and insert into PostgreSQL
            sqlite_cursor.execute(f"SELECT {col_list} FROM {table}")
            rows_done = 0

            while True:
                batch = sqlite_cursor.fetchmany(BATCH_SIZE)
                if not batch:
                    break

                # Extract only common columns
                values = [tuple(row[i] for i in range(len(common_cols))) for row in batch]

                # Use executemany for batch insert
                insert_qry = f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})"
                try:
                    pg_cursor.executemany(insert_qry, values)
                except Exception as e:
                    # Try one-by-one for better error isolation
                    for val in values:
                        try:
                            pg_cursor.execute(insert_qry, val)
                        except Exception as row_err:
                            log.warning(f"Skipped row in {table}: {row_err}")

                rows_done += len(batch)
                if progress_callback:
                    progress_callback(table, rows_done, total_rows)

            # Reset sequences for SERIAL columns
            _reset_pg_sequences(pg_cursor, table, pg_cols)

            pg_conn.commit()

            # Verify row counts
            pg_count = _count_rows(pg_cursor, table, 'postgresql')
            results[table] = {
                'status': 'ok' if pg_count == total_rows else 'mismatch',
                'source_rows': total_rows,
                'target_rows': pg_count,
            }

            if pg_count != total_rows:
                log.warning(f"{table}: row count mismatch "
                            f"(source={total_rows}, target={pg_count})")
            else:
                log.info(f"{table}: {pg_count} rows migrated successfully")

    except Exception as e:
        pg_conn.rollback()
        raise RuntimeError(f"Migration failed: {e}") from e
    finally:
        sqlite_cursor.close()
        sqlite_conn.close()
        pg_cursor.close()
        pg_conn.close()

    elapsed = time.time() - start_time
    results['_elapsed_seconds'] = round(elapsed, 2)
    log.info(f"Migration completed in {elapsed:.1f}s")
    return results


def migrate_pg_to_sqlite(pg_dsn, sqlite_path, progress_callback=None):
    """Migrate all data from PostgreSQL to SQLite.

    Args:
        pg_dsn: PostgreSQL DSN string.
        sqlite_path: path to SQLite database file (will be created/overwritten).
        progress_callback: optional callable(table_name, rows_done, total_rows).

    Returns:
        dict: migration results with row counts per table.
    """
    try:
        import psycopg2
    except ImportError:
        raise ImportError("psycopg2 is required for PostgreSQL migration. "
                          "Install it with: pip install psycopg2-binary")

    results = {}
    start_time = time.time()

    pg_conn = psycopg2.connect(pg_dsn)
    pg_conn.autocommit = True
    pg_cursor = pg_conn.cursor()

    sqlite_conn = sqlite3.connect(sqlite_path, timeout=30)
    sqlite_cursor = sqlite_conn.cursor()

    try:
        for table in MIGRATION_TABLE_ORDER:
            if not _table_exists(pg_cursor, table, 'postgresql'):
                log.info(f"Skipping {table}: does not exist in PostgreSQL")
                results[table] = {'status': 'skipped', 'reason': 'not in source'}
                continue

            if not _table_exists(sqlite_cursor, table, 'sqlite'):
                log.warning(f"Skipping {table}: does not exist in SQLite "
                            "(run schema creation first)")
                results[table] = {'status': 'skipped', 'reason': 'not in target'}
                continue

            pg_cols = _get_table_columns(pg_cursor, table, 'postgresql')
            sqlite_cols = _get_table_columns(sqlite_cursor, table, 'sqlite')

            common_cols = [c for c in pg_cols if c in sqlite_cols]
            if not common_cols:
                log.warning(f"Skipping {table}: no common columns")
                results[table] = {'status': 'skipped', 'reason': 'no common columns'}
                continue

            col_list = ', '.join(common_cols)
            placeholders = ', '.join(['?'] * len(common_cols))

            total_rows = _count_rows(pg_cursor, table, 'postgresql')
            log.info(f"Migrating {table}: {total_rows} rows")

            if progress_callback:
                progress_callback(table, 0, total_rows)

            # Clear target table
            sqlite_cursor.execute(f"DELETE FROM {table}")

            # Batch-read from PostgreSQL and insert into SQLite
            pg_cursor.execute(f"SELECT {col_list} FROM {table}")
            rows_done = 0

            while True:
                batch = pg_cursor.fetchmany(BATCH_SIZE)
                if not batch:
                    break

                insert_qry = f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})"
                try:
                    sqlite_cursor.executemany(insert_qry, batch)
                except Exception as e:
                    for val in batch:
                        try:
                            sqlite_cursor.execute(insert_qry, val)
                        except Exception as row_err:
                            log.warning(f"Skipped row in {table}: {row_err}")

                rows_done += len(batch)
                if progress_callback:
                    progress_callback(table, rows_done, total_rows)

            sqlite_conn.commit()

            sqlite_count = _count_rows(sqlite_cursor, table, 'sqlite')
            results[table] = {
                'status': 'ok' if sqlite_count == total_rows else 'mismatch',
                'source_rows': total_rows,
                'target_rows': sqlite_count,
            }

            if sqlite_count != total_rows:
                log.warning(f"{table}: row count mismatch "
                            f"(source={total_rows}, target={sqlite_count})")
            else:
                log.info(f"{table}: {sqlite_count} rows migrated successfully")

    except Exception as e:
        sqlite_conn.rollback()
        raise RuntimeError(f"Migration failed: {e}") from e
    finally:
        pg_cursor.close()
        pg_conn.close()
        sqlite_cursor.close()
        sqlite_conn.close()

    elapsed = time.time() - start_time
    results['_elapsed_seconds'] = round(elapsed, 2)
    log.info(f"Migration completed in {elapsed:.1f}s")
    return results


def main():
    """CLI entry point for database migration."""
    parser = argparse.ArgumentParser(
        description='ASM-NG Database Migration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Migrate SQLite to PostgreSQL
  python -m spiderfoot.db_migrate --direction sqlite-to-pg \\
      --sqlite ~/.spiderfoot/spiderfoot.db \\
      --pg-dsn postgresql://admin:admin@localhost:5432/asmng

  # Migrate PostgreSQL to SQLite
  python -m spiderfoot.db_migrate --direction pg-to-sqlite \\
      --sqlite ~/.spiderfoot/spiderfoot.db \\
      --pg-dsn postgresql://admin:admin@localhost:5432/asmng
        """)

    parser.add_argument('--direction', required=True,
                        choices=['sqlite-to-pg', 'pg-to-sqlite'],
                        help='Migration direction')
    parser.add_argument('--sqlite', required=True,
                        help='Path to SQLite database file')
    parser.add_argument('--pg-dsn', required=True,
                        help='PostgreSQL DSN (e.g. postgresql://user:pass@host:5432/db)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )

    def _progress(table, done, total):
        pct = (done / total * 100) if total > 0 else 100
        print(f"\r  {table}: {done}/{total} ({pct:.0f}%)", end='', flush=True)
        if done >= total:
            print()  # newline after completion

    print(f"ASM-NG Database Migration: {args.direction}")
    print(f"  SQLite: {args.sqlite}")
    print(f"  PostgreSQL: {args.pg_dsn.split('@')[1] if '@' in args.pg_dsn else args.pg_dsn}")
    print()

    try:
        if args.direction == 'sqlite-to-pg':
            results = migrate_sqlite_to_pg(args.sqlite, args.pg_dsn, _progress)
        else:
            results = migrate_pg_to_sqlite(args.pg_dsn, args.sqlite, _progress)

        # Print summary
        print()
        print("Migration Summary:")
        print("-" * 50)
        ok = 0
        skipped = 0
        mismatch = 0
        for table in MIGRATION_TABLE_ORDER:
            if table not in results:
                continue
            info = results[table]
            status = info.get('status', 'unknown')
            if status == 'ok':
                ok += 1
                print(f"  {table}: {info['target_rows']} rows OK")
            elif status == 'skipped':
                skipped += 1
                print(f"  {table}: SKIPPED ({info.get('reason', '')})")
            elif status == 'mismatch':
                mismatch += 1
                print(f"  {table}: MISMATCH "
                      f"(source={info['source_rows']}, target={info['target_rows']})")

        elapsed = results.get('_elapsed_seconds', 0)
        print("-" * 50)
        print(f"  OK: {ok}  |  Skipped: {skipped}  |  Mismatch: {mismatch}")
        print(f"  Time: {elapsed:.1f}s")

        if mismatch > 0:
            sys.exit(1)

    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
