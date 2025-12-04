#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

echo "=========================================="
echo "Testing job submission to local K8s"
echo "=========================================="

# Check if LOCAL_K8S_MODE is set
if [ "${LOCAL_K8S_MODE}" != "true" ]; then
    echo "Setting LOCAL_K8S_MODE=true for this test..."
    export LOCAL_K8S_MODE=true
fi

# Default values
TOOL="${1:-whatweb}"
TARGET="${2:-http://example.com}"

echo ""
echo "Submitting job:"
echo "  Tool: ${TOOL}"
echo "  Target: ${TARGET}"
echo ""

# Use Python to submit job via LocalExecutor
python3 <<EOF
import sys
import os
sys.path.insert(0, "${PROJECT_ROOT}")

from tools.local_executor import LocalExecutor, is_local_k8s_mode

if not is_local_k8s_mode():
    print("Error: LOCAL_K8S_MODE is not enabled")
    sys.exit(1)

try:
    executor = LocalExecutor()
    print(f"Submitting {TOOL} job for {TARGET}...")
    job_id = executor.submit("${TOOL}", "${TARGET}")
    print(f"✓ Job submitted: {job_id}")
    print("")
    print("Check job status:")
    print(f"  kubectl get jobs -n scan-workers")
    print(f"  kubectl get pods -n scan-workers")
    print("")
    print("View results:")
    print(f"  python3 ${PROJECT_ROOT}/tools/local_executor.py --tool ${TOOL} --target ${TARGET} --wait")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
EOF

echo ""
echo "=========================================="
echo "Job submission test complete!"
echo "=========================================="

