#!/bin/bash
set -euo
set -o pipefail

SAMPLE_NAME="${1:-target.bin}"
TIMEOUT="${2:-600}"
SAMPLE_PATH="/samples/${SAMPLE_NAME}"
PROJECT_DIR="/tmp/ghidra-project"
PROJECT_NAME="AutoAnalysis"
OUTPUT_DIR="/output"
MAU_GHIDRA_LEGACY="${MAU_GHIDRA_LEGACY:-0}"

echo "===================================================="
echo "  Ghidra Headless Analyzer (MalCheck)"
echo "===================================================="
echo "[*] Sample     : ${SAMPLE_PATH}"
echo "[*] Timeout    : ${TIMEOUT}s"
echo "[*] Output Dir : ${OUTPUT_DIR}"
echo "[*] Legacy mode: ${MAU_GHIDRA_LEGACY}"
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
    local title="$3"
    shift 3
    local -a script_args=("$@")
    echo "[*] ${title}"
    set +e
    timeout "${TIMEOUT}" analyzeHeadless \
        "${PROJECT_DIR}" "${PROJECT_NAME}" \
        -import "${SAMPLE_PATH}" \
        -scriptPath /ghidra-scripts \
        -postScript "${script}" "${script_args[@]}" \
        -deleteProject \
        2>&1 | tee "${OUTPUT_DIR}/${logfile}"
    local rc=$?
    set -e
    if [ "${rc}" -ne 0 ] && [ "${rc}" -ne 124 ]; then
        echo "[!] Warning: phase exit ${rc}" >&2
    fi
}

if [ "${MAU_GHIDRA_LEGACY}" = "1" ]; then
    run_phase "ghidra_decompile.log" "decompile_simple.py" "Phase 1/3: Decompiling..." "${OUTPUT_DIR}/decompiled.c"
    echo ""
    run_phase "ghidra_functions.log" "export_functions.py" "Phase 2/3: Functions..." "${OUTPUT_DIR}/functions.json"
    echo ""
    run_phase "ghidra_metadata.log" "extract_metadata.py" "Phase 3/3: Metadata..." "${OUTPUT_DIR}/metadata.json"
else
    run_phase "ghidra_analysis.log" "auto_analyze.py" "Unified analysis (auto_analyze)..." \
        "target" "${OUTPUT_DIR}/analysis.json"
fi

echo ""
echo "===================================================="
echo "[*] Output files:"
ls -la "${OUTPUT_DIR}/" || true
echo "===================================================="
