#!/bin/bash
set -euo
set -o pipefail

# Run from repo root (or set MAU_ROOT). Builds images and saves to ./images

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGES_DIR="${ROOT_DIR}/images"
mkdir -p "${IMAGES_DIR}"

echo "======================================================"
echo "  Malware Unified Analyzer - Build & Pack"
echo "======================================================"

echo ""
echo "[1/5] REMnux (optional)"
SKIP_REMNUX_PULL="${SKIP_REMNUX_PULL:-1}"
if [ "${SKIP_REMNUX_PULL}" = "1" ]; then
  echo "[!] Skip REMnux pull (set SKIP_REMNUX_PULL=0 to enable)"
else
  echo "[*] Pulling REMnux image: remnux/remnux-distro:focal"
  if docker pull remnux/remnux-distro:focal; then
    docker save remnux/remnux-distro:focal | gzip > "${IMAGES_DIR}/remnux-distro.tar.gz"
    echo "[+] Saved remnux-distro.tar.gz"
  else
    echo "[!] Skip REMnux pull (offline or error)"
  fi
fi

echo ""
echo "[2/5] Building Ghidra Headless..."
GHIDRA_DIR="${SCRIPT_DIR}/ghidra-headless"
GHIDRA_ZIP="${GHIDRA_DIR}/ghidra_11.4.3_PUBLIC_20251203.zip"
if [ ! -f "${GHIDRA_ZIP}" ]; then
  echo "[!] ERROR: Place Ghidra zip at: ${GHIDRA_ZIP}"
  exit 1
fi
docker build -t ghidra-headless:latest -f "${GHIDRA_DIR}/Dockerfile" "${GHIDRA_DIR}"
docker save ghidra-headless:latest | gzip > "${IMAGES_DIR}/ghidra-headless.tar.gz"
echo "[+] Saved ghidra-headless.tar.gz"

echo ""
echo "[3/5] Building Orchestrator..."
docker build -t mal-orchestrator:latest -f "${ROOT_DIR}/build/orchestrator/Dockerfile" "${ROOT_DIR}"
docker save mal-orchestrator:latest | gzip > "${IMAGES_DIR}/mal-orchestrator.tar.gz"
echo "[+] Saved mal-orchestrator.tar.gz"

echo ""
echo "[4/5] Building slim surface (optional)..."
docker build -t mal-surface:latest -f "${ROOT_DIR}/containers/surface/Dockerfile" "${ROOT_DIR}"
docker save mal-surface:latest | gzip > "${IMAGES_DIR}/mal-surface.tar.gz"
echo "[+] Saved mal-surface.tar.gz"

echo ""
echo "[5/5] Building Web UI..."
if [ -f "${ROOT_DIR}/web_ui/Dockerfile" ]; then
  docker build -t mal-web:latest -f "${ROOT_DIR}/web_ui/Dockerfile" "${ROOT_DIR}"
  docker save mal-web:latest | gzip > "${IMAGES_DIR}/mal-web.tar.gz"
  echo "[+] Saved mal-web.tar.gz"
else
  echo "[!] web_ui/Dockerfile not found — skip web image"
fi

echo ""
echo "------------------------------------------------------"
du -h "${IMAGES_DIR}"/*.tar.gz 2>/dev/null || true
echo "======================================================"
echo "[+] Done. Copy repo + images/ to USB."
echo "======================================================"
