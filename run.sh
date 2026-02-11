#!/usr/bin/env bash
# ASM-NG launcher script
# Usage: ./run.sh [sf.py arguments]
# Example: ./run.sh -l 127.0.0.1:5001

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Validate we're in the correct project directory
if [ ! -f "sf.py" ]; then
    echo "ERROR: sf.py not found in $SCRIPT_DIR"
    echo ""
    echo "You are not in the ASM-NG project directory."
    echo "To install ASM-NG, run:"
    echo ""
    echo "  git clone https://github.com/0x31i/asm-ng.git"
    echo "  cd asm-ng"
    echo "  ./run.sh -l 127.0.0.1:5001"
    echo ""
    exit 1
fi

if [ ! -f "requirements.txt" ]; then
    echo "ERROR: requirements.txt not found in $SCRIPT_DIR"
    echo "Your installation may be incomplete. Try re-cloning the repository."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip to handle modern packages
pip3 install -q --upgrade pip

# Install/update dependencies
echo "Installing dependencies..."
pip3 install -q -r requirements.txt

# Default to web UI on localhost:5001 if no arguments given
if [ $# -eq 0 ]; then
    echo "Starting ASM-NG web UI on http://127.0.0.1:5001 ..."
    exec python3 sf.py -l 127.0.0.1:5001
else
    exec python3 sf.py "$@"
fi
