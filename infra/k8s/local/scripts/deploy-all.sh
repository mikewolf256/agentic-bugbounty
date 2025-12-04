#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CLUSTER_NAME="agentic-bugbounty-local"

echo "=========================================="
echo "Deploying all components to local K8s"
echo "=========================================="

# Check if cluster exists
if ! kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Error: Cluster ${CLUSTER_NAME} does not exist. Run setup-local-cluster.sh first."
    exit 1
fi

# Check if kubectl is configured
if ! kubectl cluster-info --context "kind-${CLUSTER_NAME}" >/dev/null 2>&1; then
    echo "Error: kubectl is not configured for cluster ${CLUSTER_NAME}"
    exit 1
fi

echo ""
echo "Step 1: Deploying Redis..."
kubectl apply -f "${LOCAL_DIR}/redis/"
kubectl wait --for=condition=available --timeout=120s deployment/redis -n scan-workers
echo "✓ Redis deployed"

echo ""
echo "Step 2: Deploying storage..."
# Create PV first (for kind)
kubectl apply -f "${LOCAL_DIR}/storage/storage-pv.yaml" || true
kubectl apply -f "${LOCAL_DIR}/storage/storage-pvc.yaml"
kubectl wait --for=condition=bound --timeout=60s pvc/scan-results -n scan-workers
echo "✓ Storage deployed"

echo ""
echo "Step 3: Installing KEDA..."
# Check if KEDA is already installed
if ! helm list -n keda | grep -q "^keda "; then
    # Add KEDA Helm repo if not already added
    if ! helm repo list | grep -q "^kedacore "; then
        helm repo add kedacore https://kedacore.github.io/charts
        helm repo update
    fi
    
    # Create namespace and service account
    kubectl apply -f "${LOCAL_DIR}/keda/keda-install-local.yaml"
    
    # Install KEDA
    helm install keda kedacore/keda \
        --namespace keda \
        -f "${LOCAL_DIR}/keda/keda-values-local.yaml" \
        --wait
    
    echo "✓ KEDA installed"
else
    echo "✓ KEDA already installed"
fi

echo ""
echo "Step 4: Deploying worker ScaledJobs..."
kubectl apply -f "${LOCAL_DIR}/keda/scaledjob-whatweb-local.yaml"
# Add more as they're implemented:
# kubectl apply -f "${LOCAL_DIR}/keda/scaledjob-nuclei-local.yaml"
# kubectl apply -f "${LOCAL_DIR}/keda/scaledjob-katana-local.yaml"
echo "✓ Worker ScaledJobs deployed"

echo ""
echo "=========================================="
echo "Deployment complete!"
echo "=========================================="
echo ""
echo "Check status:"
echo "  kubectl get pods -n scan-workers"
echo "  kubectl get scaledjobs -n scan-workers"
echo "  kubectl get pvc -n scan-workers"
echo ""
echo "View Redis:"
echo "  kubectl port-forward -n scan-workers svc/redis 6379:6379"
echo ""

