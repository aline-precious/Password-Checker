#!/bin/bash
# CIPHER — Start Backend Server
# Requires: Python 3.8+

cd "$(dirname "$0")/backend"

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   CIPHER Backend — Starting...          ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

python3 server.py
