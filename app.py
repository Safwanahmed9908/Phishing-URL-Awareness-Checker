#!/usr/bin/env python3
"""
Application Launcher for Phishing URL Awareness Checker UI
----------------------------------------------------------
Run this file from the project root to start the clean, interactive UI:
    python3 app.py
"""

import sys
import os

# Ensure the phishing-url-awareness package is in sys.path
package_dir = os.path.join(os.path.dirname(__file__), "phishing-url-awareness")
if package_dir not in sys.path:
    sys.path.insert(0, package_dir)

from web_ui import start_server

if __name__ == "__main__":
    start_server()
