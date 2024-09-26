#!/bin/bash

# Get the directory of the script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Get root directory
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Set the directory of Python virtual environment
VENV_DIR="$(dirname "$SCRIPT_DIR")/.venv"

# Check if .venv exists
if [ -d "$VENV_DIR" ]; then
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
else
    # Create virtual environment
    python3 -m venv "$VENV_DIR"

    # Activate environment
    source "$VENV_DIR/bin/activate"

    # Installation dependencies from requirements.txt
    pip install -r "$ROOT_DIR/requirements.txt"
fi

# Execute nmap2mysql
python3 "$ROOT_DIR/nmap2mysql.py"