#!/usr/bin/env bash
# ==============================================================================
# SpiderFoot Enterprise - Dependency Installer
# ==============================================================================
# Installs all Python packages required for enterprise features.
# Run from the SpiderFoot root directory:
#   bash enterprise/install-deps.sh [--full|--ai|--security|--elasticsearch|--postgresql]
#
# Options:
#   --full           Install ALL enterprise dependencies (default)
#   --ai             Install AI Threat Intelligence Engine dependencies only
#   --security       Install Security Hardening Engine dependencies only
#   --elasticsearch  Install ElasticSearch Storage dependencies only
#   --postgresql     Install PostgreSQL backend dependencies only
#
# Automatically detects externally-managed Python environments (Kali, Debian,
# Ubuntu 23.04+) and uses --break-system-packages or a virtual environment.
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}   $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()   { echo -e "${RED}[ERR]${NC}  $1"; }

# Detect externally-managed Python (PEP 668 - Kali, Debian, Ubuntu 23.04+)
PIP_EXTRA_ARGS=""
detect_pip_environment() {
    # Check if we're already in a virtual environment
    if [ -n "$VIRTUAL_ENV" ]; then
        log_info "Virtual environment detected: ${VIRTUAL_ENV}"
        return
    fi

    # Check for PEP 668 externally-managed marker
    local python_path
    python_path=$(python3 -c "import sys; print(sys.prefix)" 2>/dev/null)
    if [ -f "${python_path}/lib/python3"*/EXTERNALLY-MANAGED ] 2>/dev/null || \
       python3 -c "import sys; sys.exit(0 if any('EXTERNALLY-MANAGED' in str(p) for p in __import__('pathlib').Path(sys.prefix).rglob('EXTERNALLY-MANAGED')) else 1)" 2>/dev/null; then
        log_warn "Externally-managed Python environment detected (Kali/Debian/Ubuntu)"
        log_info "Using --break-system-packages flag for pip"
        PIP_EXTRA_ARGS="--break-system-packages"
    fi
}

install_package() {
    local pkg="$1"
    local desc="$2"
    log_info "Installing ${desc} (${pkg})..."
    if pip install $PIP_EXTRA_ARGS "$pkg" 2>/dev/null; then
        log_ok "${desc} installed successfully"
    elif pip3 install $PIP_EXTRA_ARGS "$pkg" 2>/dev/null; then
        log_ok "${desc} installed successfully (via pip3)"
    else
        log_err "Failed to install ${desc} (${pkg})"
        return 1
    fi
}

install_ai() {
    echo ""
    echo "============================================"
    echo " AI Threat Intelligence Engine Dependencies"
    echo "============================================"
    install_package "numpy"         "NumPy (numerical computing)"
    install_package "scikit-learn"  "scikit-learn (machine learning)"
    install_package "pandas"        "pandas (data analysis)"
    install_package "nltk"          "NLTK (natural language processing)"

    # Download NLTK data for sentiment analysis and tokenization
    log_info "Downloading NLTK data (vader_lexicon, punkt, stopwords)..."
    python3 -c "
import nltk
nltk.download('vader_lexicon', quiet=True)
nltk.download('punkt', quiet=True)
nltk.download('punkt_tab', quiet=True)
nltk.download('stopwords', quiet=True)
print('NLTK data downloaded successfully')
" 2>/dev/null && log_ok "NLTK data ready" || log_warn "NLTK data download had issues (non-critical)"
}

install_security() {
    echo ""
    echo "============================================"
    echo " Security Hardening Engine Dependencies"
    echo "============================================"
    install_package "cffi"          "cffi (C FFI for cryptography)"
    install_package "cryptography"  "cryptography (encryption)"
    install_package "PyJWT"         "PyJWT (JSON Web Tokens)"
    install_package "pyotp"         "pyotp (one-time passwords / MFA)"
}

install_elasticsearch() {
    echo ""
    echo "============================================"
    echo " ElasticSearch Storage Dependencies"
    echo "============================================"
    install_package "elasticsearch" "elasticsearch (ES client library)"
}

install_postgresql() {
    echo ""
    echo "============================================"
    echo " PostgreSQL Backend Dependencies"
    echo "============================================"
    install_package "psycopg2-binary" "psycopg2 (PostgreSQL adapter)"
}

verify_installation() {
    echo ""
    echo "============================================"
    echo " Verifying Installation"
    echo "============================================"

    python3 -c "
results = []

# AI dependencies
try:
    import numpy; results.append(('numpy', True))
except: results.append(('numpy', False))

try:
    import sklearn; results.append(('scikit-learn', True))
except: results.append(('scikit-learn', False))

try:
    import pandas; results.append(('pandas', True))
except: results.append(('pandas', False))

try:
    import nltk; results.append(('nltk', True))
except: results.append(('nltk', False))

# Security dependencies
try:
    import cryptography; results.append(('cryptography', True))
except: results.append(('cryptography', False))

try:
    import jwt; results.append(('PyJWT', True))
except: results.append(('PyJWT', False))

try:
    import pyotp; results.append(('pyotp', True))
except: results.append(('pyotp', False))

# Storage dependencies
try:
    import elasticsearch; results.append(('elasticsearch', True))
except: results.append(('elasticsearch', False))

try:
    import psycopg2; results.append(('psycopg2', True))
except: results.append(('psycopg2', False))

for name, ok in results:
    status = '\033[0;32mOK\033[0m' if ok else '\033[0;31mMISSING\033[0m'
    print(f'  {name:20s} [{status}]')
"
    echo ""
}

# ---- Main ----

MODE="${1:---full}"

echo "============================================"
echo " SpiderFoot Enterprise Dependency Installer"
echo "============================================"
log_info "Mode: ${MODE}"

detect_pip_environment

case "$MODE" in
    --full)
        install_ai
        install_security
        install_elasticsearch
        install_postgresql
        ;;
    --ai)
        install_ai
        ;;
    --security)
        install_security
        ;;
    --elasticsearch)
        install_elasticsearch
        ;;
    --postgresql)
        install_postgresql
        ;;
    *)
        log_err "Unknown option: ${MODE}"
        echo "Usage: $0 [--full|--ai|--security|--elasticsearch|--postgresql]"
        exit 1
        ;;
esac

verify_installation

echo "============================================"
echo " Done!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Start SpiderFoot:  python3 sf.py -l 0.0.0.0:5001"
echo "  2. Go to Settings > IMPORT API KEYS"
echo "  3. Import enterprise/enterprise-full.cfg"
echo ""
