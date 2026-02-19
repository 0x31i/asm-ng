#!/bin/bash
# ---------------------------------------------------------------------------
# setup-postgresql.sh — Automated PostgreSQL setup for ASM-NG
#
# This script installs and configures PostgreSQL for use as the ASM-NG
# database backend. Designed for Kali Linux / Debian-based systems.
#
# Usage:
#   sudo ./setup-postgresql.sh
#   # or without sudo (will prompt for password):
#   ./setup-postgresql.sh
#
# Default credentials: admin:admin (change after first login!)
# ---------------------------------------------------------------------------

set -euo pipefail

# Configuration (override via environment variables)
PG_USER="${PG_USER:-admin}"
PG_PASSWORD="${PG_PASSWORD:-admin}"
PG_DATABASE="${PG_DATABASE:-asmng}"

# Colors for output (disabled when not running in a terminal, e.g. via subprocess)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; }

# Check for root/sudo
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root or with sudo."
    echo "  sudo $0"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Install PostgreSQL if not present
# ---------------------------------------------------------------------------
if command -v psql &>/dev/null; then
    info "PostgreSQL client already installed: $(psql --version)"
else
    info "Installing PostgreSQL..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq postgresql postgresql-client
    info "PostgreSQL installed successfully."
fi

# ---------------------------------------------------------------------------
# Step 2: Start and enable PostgreSQL service
# ---------------------------------------------------------------------------
info "Enabling and starting PostgreSQL service..."
systemctl enable --now postgresql 2>/dev/null || true

# Wait for PostgreSQL to be ready
for i in $(seq 1 10); do
    if sudo -u postgres pg_isready -q 2>/dev/null; then
        break
    fi
    sleep 1
done

if ! sudo -u postgres pg_isready -q 2>/dev/null; then
    error "PostgreSQL failed to start. Check: systemctl status postgresql"
    exit 1
fi
info "PostgreSQL is running."

# ---------------------------------------------------------------------------
# Step 3: Create database user and database
# ---------------------------------------------------------------------------
info "Creating database user '${PG_USER}'..."
sudo -u postgres psql -c "CREATE USER ${PG_USER} WITH PASSWORD '${PG_PASSWORD}';" 2>/dev/null || \
    warn "User '${PG_USER}' may already exist (this is OK)."

info "Creating database '${PG_DATABASE}'..."
sudo -u postgres psql -c "CREATE DATABASE ${PG_DATABASE} OWNER ${PG_USER};" 2>/dev/null || \
    warn "Database '${PG_DATABASE}' may already exist (this is OK)."

# Grant privileges
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${PG_DATABASE} TO ${PG_USER};" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 4: Configure local password authentication
# ---------------------------------------------------------------------------
PG_HBA=$(sudo -u postgres psql -t -c "SHOW hba_file;" 2>/dev/null | xargs)

if [ -n "$PG_HBA" ] && [ -f "$PG_HBA" ]; then
    if ! grep -q "${PG_DATABASE}" "$PG_HBA" 2>/dev/null; then
        info "Configuring pg_hba.conf for local password authentication..."
        # Add entry before the first 'local' line for our database
        sed -i "/^local.*all.*all/i local   ${PG_DATABASE}   ${PG_USER}                           scram-sha-256" "$PG_HBA"
        # Also allow TCP/IP connections from localhost
        sed -i "/^host.*all.*all.*127/i host    ${PG_DATABASE}   ${PG_USER}   127.0.0.1/32          scram-sha-256" "$PG_HBA"
        systemctl reload postgresql
        info "pg_hba.conf updated and PostgreSQL reloaded."
    else
        info "pg_hba.conf already configured for ${PG_DATABASE}."
    fi
else
    warn "Could not locate pg_hba.conf. You may need to configure authentication manually."
fi

# ---------------------------------------------------------------------------
# Step 5: Test connection
# ---------------------------------------------------------------------------
info "Testing connection..."
if PGPASSWORD="${PG_PASSWORD}" psql -U "${PG_USER}" -d "${PG_DATABASE}" -h localhost -c "SELECT 1;" &>/dev/null; then
    echo ""
    info "PostgreSQL is ready!"
    echo "  Connection: postgresql://${PG_USER}:${PG_PASSWORD}@localhost:5432/${PG_DATABASE}"
    echo ""
    warn "IMPORTANT: Change the default password after first login:"
    echo "  sudo -u postgres psql -c \"ALTER USER ${PG_USER} PASSWORD 'new_password';\""
    echo ""
else
    # Try without -h localhost (use Unix socket)
    if PGPASSWORD="${PG_PASSWORD}" psql -U "${PG_USER}" -d "${PG_DATABASE}" -c "SELECT 1;" &>/dev/null; then
        echo ""
        info "PostgreSQL is ready (via Unix socket)!"
        echo "  Connection: postgresql://${PG_USER}:${PG_PASSWORD}@localhost:5432/${PG_DATABASE}"
        echo ""
    else
        warn "PostgreSQL setup completed but connection test failed."
        warn "ASM-NG will fall back to SQLite until the connection is fixed."
        echo "  Debug: PGPASSWORD=${PG_PASSWORD} psql -U ${PG_USER} -d ${PG_DATABASE} -h localhost"
    fi
fi

exit 0
