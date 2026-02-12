#!/bin/bash

# ASM-NG SQLite Database Restore Script
# Usage: ./restore.sh <backup_file>

set -e

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <backup_file>"
    echo "Available backups:"
    ls -la /backups/spiderfoot_backup_*.db.gz 2>/dev/null || echo "No backups found"
    exit 1
fi

BACKUP_FILE="$1"
DB_PATH="${SF_DB_PATH:-/home/spiderfoot/.spiderfoot/spiderfoot.db}"

# Check if backup file exists
if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "ERROR: Backup file '$BACKUP_FILE' not found!"
    exit 1
fi

echo "Starting database restore from: $BACKUP_FILE"
echo "Target database: $DB_PATH"
echo "WARNING: This will replace the current database"
read -p "Are you sure you want to continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Restore cancelled."
    exit 0
fi

# Stop the application if running (best effort)
echo "Note: Stop ASM-NG before restoring for best results."

# Create backup of current database before overwriting
if [[ -f "$DB_PATH" ]]; then
    CURRENT_BACKUP="${DB_PATH}.pre-restore.$(date +%Y%m%d_%H%M%S)"
    cp "$DB_PATH" "$CURRENT_BACKUP"
    echo "Current database backed up to: $CURRENT_BACKUP"
fi

# Restore from backup
if [[ "$BACKUP_FILE" == *.gz ]]; then
    echo "Decompressing and restoring backup..."
    gunzip -c "$BACKUP_FILE" > "$DB_PATH"
else
    echo "Restoring backup..."
    cp "$BACKUP_FILE" "$DB_PATH"
fi

# Verify the restored database
if sqlite3 "$DB_PATH" "PRAGMA quick_check;" | grep -q "ok"; then
    echo "Database restore completed successfully!"
    echo "Database integrity check: PASSED"
else
    echo "WARNING: Database integrity check failed after restore."
    echo "Consider restoring from a different backup."
fi

echo "You may want to restart the ASM-NG application to ensure proper operation."
