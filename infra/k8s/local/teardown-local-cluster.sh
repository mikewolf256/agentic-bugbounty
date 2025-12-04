#!/bin/bash
set -e

CLUSTER_NAME="agentic-bugbounty-local"

echo "=========================================="
echo "Tearing down local Kubernetes cluster"
echo "=========================================="

# Check if cluster exists
if ! kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Cluster ${CLUSTER_NAME} does not exist."
    exit 0
fi

# Delete cluster
echo "Deleting kind cluster: ${CLUSTER_NAME}"
kind delete cluster --name "${CLUSTER_NAME}"

echo ""
echo "=========================================="
echo "Cluster teardown complete!"
echo "=========================================="

