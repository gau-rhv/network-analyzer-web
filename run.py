#!/usr/bin/env python3
"""
Network Analyzer - Cross-platform launcher
Run this script with: python run.py (requires admin/sudo for packet capture)
"""

import sys
import os

# Add project root to path
project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)
os.chdir(project_dir)

from network_analyzer.cli_manager import main

if __name__ == "__main__":
    main()
