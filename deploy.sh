#!/bin/bash
set -euo
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGES_DIR="${SCRIPT_DIR}/images"
COMPOSE_DIR="${SCRIPT_DIR}/compose"

echo "======================================================"
echo "  Malware Unified Analyzer - Deploy"
echo "======================================================"

if ! command -v docker &> /dev/null; then
  echo "[!] ERROR: docker not installed."
  exit 1
fi

if ! docker info &> /dev/null; then
  echo "[!] ERROR: Docker daemon not running."
  exit 1
fi

echo "[Step 1/3] Loading images from ${IMAGES_DIR}..."
shopt -s nullglob
for tar_file in "${IMAGES_DIR}"/*.tar.gz "${IMAGES_DIR}"/*.tar; do
  [ -f "$tar_file" ] || continue
  echo "  Loading: $(basename "$tar_file")..."
  if [[ "$tar_file" == *.gz ]]; then
    gunzip -c "$tar_file" | docker load
  else
    docker load -i "$tar_file"
  fi
done
shopt -u nullglob

echo "[Step 2/3] Creating directories..."
mkdir -p "${SCRIPT_DIR}/samples" "${SCRIPT_DIR}/results/surface" "${SCRIPT_DIR}/results/network" \
  "${SCRIPT_DIR}/results/static" "${SCRIPT_DIR}/results/reports"

echo "[Step 3/3] Writing compose/.env.runtime..."
cat > "${COMPOSE_DIR}/.env.runtime" <<EOF
PROJECT_ROOT=${SCRIPT_DIR}
SAMPLES_DIR=${SCRIPT_DIR}/samples
RESULTS_DIR=${SCRIPT_DIR}/results
SCRIPTS_DIR=${SCRIPT_DIR}/scripts
RULES_DIR=${SCRIPT_DIR}/rules
CONFIG_DIR=${COMPOSE_DIR}/config
EOF

echo "[Step 4/4] Starting containers with docker-compose.usb.yml..."
cd "${SCRIPT_DIR}"
docker compose -f docker-compose.usb.yml --env-file "${COMPOSE_DIR}/.env.runtime" up -d

echo ""
echo "[+] Deploy complete."
echo "  Web UI: http://127.0.0.1:8080"
echo "  Run analysis: docker exec orchestrator python -m mau.main YOUR_SAMPLE.exe"
echo "  Results: ${SCRIPT_DIR}/results/reports/"
echo ""
