#!/bin/bash

# Get the directory of the current script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Path to the virtual environment
VENV_DIR="$SCRIPT_DIR/../../.venv"

# Check if .venv exists
if [ -d "$VENV_DIR" ]; then
    # Activate the existing virtual environment
    source "$VENV_DIR/bin/activate"
else
    # Create a new virtual environment
    python3 -m venv "$VENV_DIR"

    # Activate the newly created virtual environment
    source "$VENV_DIR/bin/activate"

    # Install dependencies from requirements.txt
    pip install -r "$SCRIPT_DIR/../../requirements.txt"
fi

# Execute nmap2mysql.py
python3 "$SCRIPT_DIR/../../nmap2mysql.py"