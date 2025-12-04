#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RESULTS_PATH="${RESULTS_PATH:-/tmp/agentic-bugbounty-results}"

echo "=========================================="
echo "Checking results in PVC"
echo "=========================================="

if [ ! -d "${RESULTS_PATH}" ]; then
    echo "Error: Results path does not exist: ${RESULTS_PATH}"
    echo ""
    echo "Note: For kind cluster, results are stored in the cluster's hostPath."
    echo "To access results from a pod, use:"
    echo "  kubectl run -it --rm debug --image=busybox --restart=Never -n scan-workers -- sh"
    echo "  # Then inside the pod:"
    echo "  ls -la /mnt/scan-results/"
    exit 1
fi

echo ""
echo "Results path: ${RESULTS_PATH}"
echo ""

# Count results by tool
for tool_dir in "${RESULTS_PATH}"/*/; do
    if [ -d "${tool_dir}" ]; then
        tool=$(basename "${tool_dir}")
        count=$(find "${tool_dir}" -name "*.json" 2>/dev/null | wc -l)
        echo "  ${tool}: ${count} results"
        
        # Show latest 5 results
        if [ "${count}" -gt 0 ]; then
            echo "    Latest results:"
            find "${tool_dir}" -name "*.json" -type f -printf "%T@ %p\n" 2>/dev/null | \
                sort -rn | head -5 | while read timestamp filepath; do
                filename=$(basename "${filepath}")
                echo "      - ${filename}"
            done
        fi
    fi
done

echo ""
echo "To view a specific result file:"
echo "  cat ${RESULTS_PATH}/whatweb/YYYY/MM/DD/job-id.json"
echo ""

