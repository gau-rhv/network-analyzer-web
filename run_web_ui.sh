#!/bin/bash

# Network Analyzer - Web UI Launcher
# Simple one-command launcher for the dashboard

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Activate virtual environment
if [ -f ".venv/bin/activate" ]; then
    source ".venv/bin/activate"
fi

# Get Python path
PYTHON_PATH=".venv/bin/python"
if [ ! -f "$PYTHON_PATH" ]; then
    PYTHON_PATH="python3"
fi

# Start CLI Manager
# The CLI manager handles searching for python, setting up the environment,
# and running the server in the background while showing a menu.

$PYTHON_PATH network_analyzer/cli_manager.py
