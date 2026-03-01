#!/bin/bash

# ASM-NG PostgreSQL Database Backup Script
# This script creates compressed backups of the PostgreSQL database

set -e

# Configuration
BACKUP_DIR="/backups"
PG_DSN="${ASMNG_DATABASE_URL:-postgresql://admin:admin@localhost:5432/asmng}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Generate timestamp for backup file
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="asmng_backup_${TIMESTAMP}.sql"
BACKUP_PATH="$BACKUP_DIR/$BACKUP_FILE"

echo "Starting database backup at $(date)"
echo "Backup file: $BACKUP_PATH"

# Create the backup using pg_dump
pg_dump "$PG_DSN" > "$BACKUP_PATH"

# Compress the backup
gzip "$BACKUP_PATH"
BACKUP_PATH="${BACKUP_PATH}.gz"

# Verify backup was created
if [[ -f "$BACKUP_PATH" ]]; then
    BACKUP_SIZE=$(du -h "$BACKUP_PATH" | cut -f1)
    echo "Backup completed successfully!"
    echo "Backup size: $BACKUP_SIZE"
else
    echo "ERROR: Backup failed!"
    exit 1
fi

# Clean up old backups (keep only last N days)
echo "Cleaning up backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -name "asmng_backup_*.sql.gz" -type f -mtime +$RETENTION_DAYS -delete

# List current backups
echo "Current backups:"
ls -lh "$BACKUP_DIR"/asmng_backup_*.sql.gz 2>/dev/null | tail -10

# Optional: Upload to S3 if configured
if [[ "${S3_BACKUP_ENABLED}" == "true" ]]; then
    echo "Uploading backup to S3..."
    if command -v aws >/dev/null 2>&1; then
        aws s3 cp "$BACKUP_PATH" "s3://${S3_BUCKET}/database/" --region="${S3_REGION}"
        echo "Backup uploaded to S3 successfully"
    else
        echo "WARNING: AWS CLI not found, skipping S3 upload"
    fi
fi

echo "Backup process completed at $(date)"
