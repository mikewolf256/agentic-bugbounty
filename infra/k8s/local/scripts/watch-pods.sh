#!/bin/bash
set -e

CLUSTER_NAME="agentic-bugbounty-local"
NAMESPACE="scan-workers"

echo "=========================================="
echo "Watching pods in local K8s cluster"
echo "=========================================="

# Check if cluster exists
if ! kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Error: Cluster ${CLUSTER_NAME} does not exist."
    exit 1
fi

echo ""
echo "Watching pods in namespace: ${NAMESPACE}"
echo "Press Ctrl+C to stop"
echo ""

# Watch pods
kubectl get pods -n "${NAMESPACE}" -w

