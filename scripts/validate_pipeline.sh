#!/bin/bash
# Convenience wrapper for K8s scan pipeline validation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=========================================="
echo "K8s Scan Pipeline Validation"
echo "=========================================="
echo ""

# Check if we're in the project root
if [ ! -f "${PROJECT_ROOT}/requirements.txt" ]; then
    echo "Error: Must run from project root"
    exit 1
fi

# Check for optional arguments
SKIP_E2E=""
if [ "$1" == "--skip-e2e" ]; then
    SKIP_E2E="--skip-e2e"
    echo "Skipping end-to-end test"
fi

echo "Running validation script..."
echo ""

# Run the validation script
cd "${PROJECT_ROOT}"
python3 tests/validate_k8s_scan_pipeline.py ${SKIP_E2E}

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "=========================================="
    echo "✅ Validation passed!"
    echo "=========================================="
else
    echo "=========================================="
    echo "❌ Validation failed!"
    echo "=========================================="
    echo ""
    echo "Check validation_report.json for details:"
    echo "  cat output_zap/validation_report.json | jq ."
fi

exit $EXIT_CODE

