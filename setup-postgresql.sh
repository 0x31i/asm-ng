#!/bin/bash
# ---------------------------------------------------------------------------
# setup-postgresql.sh — Automated PostgreSQL setup for ASM-NG
#
# Multi-platform support:
#   - Debian/Kali/Ubuntu: apt-get
#   - macOS: Homebrew (brew)
#   - RHEL/Fedora/CentOS: dnf / yum
#
# Usage:
#   sudo ./setup-postgresql.sh          # Linux (requires root)
#   ./setup-postgresql.sh               # macOS (Homebrew, no root needed)
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
error() { echo -e "${RED}[-]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Detect platform and package manager
# ---------------------------------------------------------------------------
OS="$(uname -s)"
PKG_MGR=""

if [ "$OS" = "Darwin" ]; then
    # macOS
    if command -v brew &>/dev/null; then
        PKG_MGR="brew"
    else
        error "Homebrew is required on macOS. Install it from https://brew.sh"
        exit 1
    fi
elif [ "$OS" = "Linux" ]; then
    # Check for root on Linux
    if [ "$EUID" -ne 0 ]; then
        error "This script must be run as root or with sudo on Linux."
        echo "  sudo $0"
        exit 1
    fi
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
    else
        error "No supported package manager found (apt-get, dnf, yum)."
        error "Install PostgreSQL manually and set ASMNG_DATABASE_URL."
        exit 1
    fi
else
    error "Unsupported operating system: $OS"
    exit 1
fi

info "Detected: $OS with $PKG_MGR"

# ---------------------------------------------------------------------------
# Step 1: Install PostgreSQL if not present
# ---------------------------------------------------------------------------
if command -v psql &>/dev/null; then
    info "PostgreSQL client already installed: $(psql --version)"
else
    info "Installing PostgreSQL..."
    case "$PKG_MGR" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq postgresql postgresql-client
            ;;
        brew)
            brew install postgresql@16 || brew install postgresql || {
                error "Failed to install PostgreSQL via Homebrew."
                exit 1
            }
            ;;
        dnf)
            dnf install -y -q postgresql-server postgresql
            ;;
        yum)
            yum install -y -q postgresql-server postgresql
            ;;
    esac
    info "PostgreSQL installed successfully."
fi

# ---------------------------------------------------------------------------
# Homebrew keg-only PATH fix
# ---------------------------------------------------------------------------
# postgresql@16 is keg-only: its binaries are NOT symlinked into the default
# PATH.  Detect the keg prefix and prepend its bin/ so that pg_isready, psql,
# etc. are available for the rest of the script.
if [ "$PKG_MGR" = "brew" ]; then
    PG_KEG_BIN="$(brew --prefix postgresql@16 2>/dev/null)/bin"
    if [ ! -d "$PG_KEG_BIN" ]; then
        PG_KEG_BIN="$(brew --prefix postgresql 2>/dev/null)/bin"
    fi
    if [ -d "$PG_KEG_BIN" ]; then
        export PATH="$PG_KEG_BIN:$PATH"
        info "Added $PG_KEG_BIN to PATH (keg-only formula)"
    fi
fi

# ---------------------------------------------------------------------------
# Step 2: Start PostgreSQL service
# ---------------------------------------------------------------------------
info "Starting PostgreSQL service..."

case "$PKG_MGR" in
    brew)
        # macOS: 'brew services start' returns non-zero if already running,
        # which is not an error. The pg_isready loop below is the real check.
        brew services start postgresql@16 2>/dev/null || \
            brew services start postgresql 2>/dev/null || true
        ;;
    apt)
        systemctl enable --now postgresql 2>/dev/null || true
        ;;
    dnf|yum)
        # RHEL/Fedora may need initdb first
        if [ ! -f /var/lib/pgsql/data/PG_VERSION ]; then
            postgresql-setup --initdb 2>/dev/null || \
                su - postgres -c "initdb -D /var/lib/pgsql/data" 2>/dev/null || true
        fi
        systemctl enable --now postgresql 2>/dev/null || true
        ;;
esac

# Wait for PostgreSQL to be ready
PG_READY=false
for i in $(seq 1 15); do
    if pg_isready -q 2>/dev/null; then
        PG_READY=true
        break
    fi
    # Also try as postgres user (Linux)
    if [ "$OS" = "Linux" ] && sudo -u postgres pg_isready -q 2>/dev/null; then
        PG_READY=true
        break
    fi
    sleep 1
done

if [ "$PG_READY" = false ]; then
    error "PostgreSQL failed to start."
    if [ "$OS" = "Linux" ]; then
        echo "  Check: systemctl status postgresql"
    else
        echo "  Check: brew services list"
    fi
    exit 1
fi
info "PostgreSQL is running."

# ---------------------------------------------------------------------------
# Step 3: Create database user and database
# ---------------------------------------------------------------------------
# Determine how to run psql as superuser
if [ "$OS" = "Darwin" ]; then
    # macOS: current user is typically the PG superuser after brew install
    PG_SUDO=""
    PG_SUPERUSER="$(whoami)"
else
    PG_SUDO="sudo -u postgres"
    PG_SUPERUSER="postgres"
fi

info "Creating database user '${PG_USER}'..."
$PG_SUDO psql -d postgres -c "CREATE USER ${PG_USER} WITH PASSWORD '${PG_PASSWORD}';" 2>/dev/null || \
    warn "User '${PG_USER}' may already exist (this is OK)."

info "Creating database '${PG_DATABASE}'..."
$PG_SUDO psql -d postgres -c "CREATE DATABASE ${PG_DATABASE} OWNER ${PG_USER};" 2>/dev/null || \
    warn "Database '${PG_DATABASE}' may already exist (this is OK)."

# Grant privileges
$PG_SUDO psql -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE ${PG_DATABASE} TO ${PG_USER};" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 4: Configure local password authentication
# ---------------------------------------------------------------------------
PG_HBA=$($PG_SUDO psql -d postgres -t -c "SHOW hba_file;" 2>/dev/null | xargs)

if [ -n "$PG_HBA" ] && [ -f "$PG_HBA" ]; then
    if ! grep -q "${PG_DATABASE}" "$PG_HBA" 2>/dev/null; then
        info "Configuring pg_hba.conf for local password authentication..."

        if [ "$OS" = "Darwin" ]; then
            # macOS sed requires different syntax (-i '' instead of -i)
            sed -i '' "/^local.*all.*all/i\\
local   ${PG_DATABASE}   ${PG_USER}                           scram-sha-256
" "$PG_HBA" 2>/dev/null || true
            sed -i '' "/^host.*all.*all.*127/i\\
host    ${PG_DATABASE}   ${PG_USER}   127.0.0.1/32          scram-sha-256
" "$PG_HBA" 2>/dev/null || true
        else
            sed -i "/^local.*all.*all/i local   ${PG_DATABASE}   ${PG_USER}                           scram-sha-256" "$PG_HBA"
            sed -i "/^host.*all.*all.*127/i host    ${PG_DATABASE}   ${PG_USER}   127.0.0.1/32          scram-sha-256" "$PG_HBA"
        fi

        # Reload PostgreSQL to apply pg_hba.conf changes
        if [ "$OS" = "Darwin" ]; then
            brew services restart postgresql@16 2>/dev/null || \
                brew services restart postgresql 2>/dev/null || true
        else
            systemctl reload postgresql 2>/dev/null || true
        fi
        sleep 2  # Give PG a moment to reload
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
    if [ "$OS" = "Darwin" ]; then
        echo "  psql -c \"ALTER USER ${PG_USER} PASSWORD 'new_password';\""
    else
        echo "  sudo -u postgres psql -c \"ALTER USER ${PG_USER} PASSWORD 'new_password';\""
    fi
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
