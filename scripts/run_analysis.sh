#!/usr/bin/env bash
# Run a full SIFT-HUNTER analysis pipeline
# Usage: run_analysis.sh <evidence_dir_or_file> [output_path]
#
# Examples:
#   run_analysis.sh /cases/incident-001/
#   run_analysis.sh /cases/disk.dd /cases/report.md
#   run_analysis.sh /cases/disk.dd /cases/memory.dmp --output /cases/report.md

set -euo pipefail

CYAN="\033[36m"
RED="\033[31m"
RESET="\033[0m"

die() { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
info() { echo -e "${CYAN}[INFO]${RESET} $*"; }

# Default output path
OUTPUT="/tmp/sift-output/report-$(date +%Y%m%d-%H%M%S).md"

# Parse arguments
EVIDENCE_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output|-o)
            OUTPUT="$2"
            shift 2
            ;;
        --model)
            export SIFT_MODEL="$2"
            shift 2
            ;;
        --max-iterations)
            export SIFT_MAX_ITERATIONS="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: run_analysis.sh [OPTIONS] <evidence1> [evidence2] ..."
            echo ""
            echo "Options:"
            echo "  --output, -o PATH       Output report path (default: /tmp/sift-output/report-TIMESTAMP.md)"
            echo "  --model MODEL_ID        Claude model ID (default: claude-opus-4-7-20250514)"
            echo "  --max-iterations N      Max agent iterations (default: 50)"
            echo "  --help                  Show this help"
            echo ""
            echo "Examples:"
            echo "  run_analysis.sh /cases/disk.dd"
            echo "  run_analysis.sh /cases/disk.dd /cases/memory.dmp --output /cases/report.md"
            echo "  run_analysis.sh /mnt/evidence/ -o /tmp/report.md"
            exit 0
            ;;
        *)
            EVIDENCE_ARGS+=("$1")
            shift
            ;;
    esac
done

# Validate inputs
if [[ "${#EVIDENCE_ARGS[@]}" -eq 0 ]]; then
    die "No evidence paths provided. Usage: run_analysis.sh <evidence1> [evidence2] ..."
fi

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    die "ANTHROPIC_API_KEY not set. Export it before running: export ANTHROPIC_API_KEY='sk-ant-...'"
fi

# Validate all evidence paths exist
for path in "${EVIDENCE_ARGS[@]}"; do
    if [[ ! -e "$path" ]]; then
        die "Evidence path does not exist: $path"
    fi
done

# Create output directory
OUTPUT_DIR=$(dirname "$OUTPUT")
mkdir -p "$OUTPUT_DIR"

# Find python in venv or system
PYTHON=""
VENV_PYTHON="$HOME/.local/share/sift-hunter/venv/bin/python"
if [[ -f "$VENV_PYTHON" ]]; then
    PYTHON="$VENV_PYTHON"
elif command -v python3.11 &>/dev/null; then
    PYTHON="python3.11"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
else
    die "Python 3 not found"
fi

# Build evidence paths argument
EVIDENCE_JOINED=$(IFS=' '; echo "${EVIDENCE_ARGS[*]}")

info "Starting SIFT-HUNTER analysis"
info "Evidence: $EVIDENCE_JOINED"
info "Output: $OUTPUT"
info "Model: ${SIFT_MODEL:-claude-opus-4-7-20250514}"
echo ""

# Run analysis
exec "$PYTHON" -m agents.orchestrator \
    --evidence "${EVIDENCE_ARGS[@]}" \
    --output "$OUTPUT"
