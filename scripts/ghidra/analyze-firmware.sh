#!/usr/bin/env bash
# Linux/macOS version of analyze-firmware.ps1: unpack the AD1204 0073 image,
# import it into a new Ghidra project at base 0x00403000, reconstruct startup
# memory, repair dispatch tables, export pseudocode and verify the decompressor.
# Static analysis only. OUTPUT_DIR must be new.
#
# Usage: scripts/ghidra/analyze-firmware.sh IMAGE OUTPUT_DIR GHIDRA_HOME [--assets] [--split-unclassified] [--verify]
# Set JAVA_HOME to a JDK 21+ if Ghidra does not find one by itself.
# Tested on Linux with Ghidra 12.2. The script avoids GNU-only tools for macOS.
set -euo pipefail

if [ $# -lt 3 ]; then
    echo "usage: $0 IMAGE OUTPUT_DIR GHIDRA_HOME [--assets] [--split-unclassified] [--verify]" >&2
    exit 2
fi
# Portable absolute paths (macOS realpath has no -m).
abspath() { python3 -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "$1"; }
[ -f "$1" ] || { echo "IMAGE not found: $1" >&2; exit 1; }
[ -d "$3" ] || { echo "GHIDRA_HOME not found: $3" >&2; exit 1; }
image=$(abspath "$1")
output=$(abspath "$2")
ghidra=$(abspath "$3")
shift 3
script_dir=$(cd "$(dirname "$0")" && pwd)
python_root=$(dirname "$script_dir")
headless="$ghidra/support/analyzeHeadless"

[ -x "$headless" ] || { echo "Ghidra analyzeHeadless was not found in $ghidra/support" >&2; exit 1; }
[ ! -e "$output" ] || { echo "OUTPUT_DIR must be new; existing research is preserved." >&2; exit 1; }

unpacked="$output/unpacked"
(cd "$python_root" && uv run -m cuktech_pc.firmware_unpack "$image" --output "$unpacked" "$@")

manifest="$unpacked/manifest.json"
regions=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["startup_regions"]))' "$manifest")
[ "$regions" = 5 ] || { echo "This Ghidra workflow requires the measured AD1204 0073 startup profile." >&2; exit 1; }

project="$output/project"
analysis="$output/analysis"
mkdir -p "$project" "$analysis"

"$headless" "$project" AD1204_0073 \
    -import "$unpacked/firmware.bin" \
    -loader BinaryLoader -loader-baseAddr 0x00403000 -processor ARM:LE:32:Cortex \
    -scriptPath "$script_dir" -preScript PrepareChargerFirmware.java \
    -postScript ReconstructChargerMemory.java "$manifest" \
    -postScript RepairChargerDispatch.java \
    -postScript ExportChargerFirmware.java "$analysis" \
    -postScript VerifyStartupDecoder.java "$unpacked/load-3-20001730-expanded.bin" "$analysis/decoder-verification.json" \
    -analysisTimeoutPerFile 300 -max-cpu 4 -log "$analysis/headless.log"

# Ghidra can exit 0 after a script exception; require the result files too.
python3 - "$analysis" "$manifest" <<'EOF'
import json, sys
analysis, manifest = sys.argv[1], sys.argv[2]
results = json.load(open(f"{analysis}/analysis.json"))
check = json.load(open(f"{analysis}/decoder-verification.json"))
outputs = json.load(open(manifest))["outputs"]
if not check.get("python_matches_original_thumb") or not check.get("output_guards_intact"):
    sys.exit("Independent decoder verification failed.")
if results["sha256"] != outputs[0]["sha256"]:
    sys.exit("Ghidra input hash differs from extracted firmware.")
print(f"Completed: {results['function_count']} function records; decoder matches original instructions. Results: {analysis}")
EOF
