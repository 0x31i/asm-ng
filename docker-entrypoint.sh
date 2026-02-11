#!/bin/bash
# ASM-NG Docker startup script

# Ensure the correct database and logs directory structure
mkdir -p /home/spiderfoot/.spiderfoot/logs 2>/dev/null || true
mkdir -p /home/spiderfoot/logs 2>/dev/null || true
mkdir -p /home/spiderfoot/cache 2>/dev/null || true
mkdir -p /home/spiderfoot/data 2>/dev/null || true

# Set permissions only if running as root (e.g. when container is started as root)
if [ "$(id -u)" = "0" ]; then
    chown -R spiderfoot:spiderfoot /home/spiderfoot/.spiderfoot
    chown -R spiderfoot:spiderfoot /home/spiderfoot/logs
    chown -R spiderfoot:spiderfoot /home/spiderfoot/cache
    chown -R spiderfoot:spiderfoot /home/spiderfoot/data
    chmod -R 755 /home/spiderfoot/logs
fi

echo "Database will be created at: /home/spiderfoot/data/spiderfoot.db"
echo "Starting ASM-NG..."

# Execute the original command
exec "$@"
