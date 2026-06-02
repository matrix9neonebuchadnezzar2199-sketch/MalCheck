#!/usr/bin/env bash
set -euo
set -o pipefail

# make_usb.sh — development machine (network available)
# Build Docker images and pack them into ./images/*.tar.gz for USB.

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "======================================================"
echo "  Malware Unified Analyzer — make_usb.sh"
echo "======================================================"
echo ""

bash "${ROOT}/build/build_and_pack.sh"

