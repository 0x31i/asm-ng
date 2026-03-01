#!/bin/bash

# ASM-NG PostgreSQL Database Restore Script
# Usage: ./restore.sh <backup_file>

set -e

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <backup_file>"
    echo "Available backups:"
    ls -la /backups/asmng_backup_*.sql.gz 2>/dev/null || echo "No backups found"
    exit 1
fi

BACKUP_FILE="$1"
PG_DSN="${ASMNG_DATABASE_URL:-postgresql://admin:admin@localhost:5432/asmng}"

# Check if backup file exists
if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "ERROR: Backup file '$BACKUP_FILE' not found!"
    exit 1
fi

echo "Starting database restore from: $BACKUP_FILE"
echo "Target database: $PG_DSN"
echo "WARNING: This will replace the current database contents"
read -p "Are you sure you want to continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Restore cancelled."
    exit 0
fi

# Stop the application if running (best effort)
echo "Note: Stop ASM-NG before restoring for best results."

# Create backup of current database before overwriting
echo "Creating pre-restore backup..."
PRE_RESTORE_BACKUP="/backups/asmng_pre_restore_$(date +%Y%m%d_%H%M%S).sql.gz"
pg_dump "$PG_DSN" | gzip > "$PRE_RESTORE_BACKUP"
echo "Current database backed up to: $PRE_RESTORE_BACKUP"

# Restore from backup
if [[ "$BACKUP_FILE" == *.gz ]]; then
    echo "Decompressing and restoring backup..."
    gunzip -c "$BACKUP_FILE" | psql "$PG_DSN"
else
    echo "Restoring backup..."
    psql "$PG_DSN" < "$BACKUP_FILE"
fi

# Verify the restored database
if psql "$PG_DSN" -c "SELECT 1;" &>/dev/null; then
    echo "Database restore completed successfully!"
    echo "Database connectivity check: PASSED"
else
    echo "WARNING: Database connectivity check failed after restore."
    echo "Consider restoring from a different backup."
fi

echo "You may want to restart the ASM-NG application to ensure proper operation."
