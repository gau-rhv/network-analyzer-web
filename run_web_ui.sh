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

HOST="127.0.0.1"
PORT="5000"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --host) HOST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        *) shift ;;
    esac
done

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         Network Analyzer - Dashboard                           ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "🌐 Open your browser:"
echo "   http://$HOST:$PORT"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Start server
$PYTHON_PATH -m network_analyzer --web --host "$HOST" --port "$PORT"
