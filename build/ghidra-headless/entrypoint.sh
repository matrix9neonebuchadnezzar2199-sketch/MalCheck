#!/bin/bash
set -euo
set -o pipefail

SAMPLE_NAME="${1:-target.bin}"
TIMEOUT="${2:-600}"
SAMPLE_PATH="/samples/${SAMPLE_NAME}"
PROJECT_DIR="/tmp/ghidra-project"
PROJECT_NAME="AutoAnalysis"
OUTPUT_DIR="/output"

echo "===================================================="
echo "  Ghidra Headless Analyzer"
echo "===================================================="
echo "[*] Sample     : ${SAMPLE_PATH}"
echo "[*] Timeout    : ${TIMEOUT}s"
echo "[*] Output Dir : ${OUTPUT_DIR}"
echo ""

if [ ! -f "${SAMPLE_PATH}" ]; then
    echo "[!] ERROR: Sample not found at ${SAMPLE_PATH}" >&2
    exit 1
fi

echo "[*] File type: $(file -b "${SAMPLE_PATH}")"
echo ""

run_phase() {
    local logfile="$1"
    local script="$2"
    local out_arg="$3"
    local title="$4"
    echo "[*] ${title}"
    set +e
    timeout "${TIMEOUT}" analyzeHeadless \
        "${PROJECT_DIR}" "${PROJECT_NAME}" \
        -import "${SAMPLE_PATH}" \
        -scriptPath /ghidra-scripts \
        -postScript "${script}" "${out_arg}" \
        -deleteProject \
        2>&1 | tee "${OUTPUT_DIR}/${logfile}"
    local rc=$?
    set -e
    if [ "${rc}" -ne 0 ] && [ "${rc}" -ne 124 ]; then
        echo "[!] Warning: phase exit ${rc}" >&2
    fi
}

run_phase "ghidra_decompile.log" "decompile_simple.py" "${OUTPUT_DIR}/decompiled.c" "Phase 1/3: Decompiling..."
echo ""
run_phase "ghidra_functions.log" "export_functions.py" "${OUTPUT_DIR}/functions.json" "Phase 2/3: Functions..."
echo ""
run_phase "ghidra_metadata.log" "extract_metadata.py" "${OUTPUT_DIR}/metadata.json" "Phase 3/3: Metadata..."
echo ""
echo "===================================================="
echo "[*] Output files:"
ls -la "${OUTPUT_DIR}/" || true
echo "===================================================="
