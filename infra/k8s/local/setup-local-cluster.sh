#!/bin/bash
set -e

echo "=========================================="
echo "Setting up local Kubernetes cluster"
echo "=========================================="

# Check prerequisites
command -v kind >/dev/null 2>&1 || { echo "Error: kind is not installed. Install from https://kind.sigs.k8s.io/"; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "Error: kubectl is not installed. Install from https://kubernetes.io/docs/tasks/tools/"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Error: docker is not installed. Install from https://docs.docker.com/get-docker/"; exit 1; }

CLUSTER_NAME="agentic-bugbounty-local"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if cluster already exists
if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Cluster ${CLUSTER_NAME} already exists. Use teardown-local-cluster.sh to remove it first."
    exit 1
fi

# Create kind cluster
echo "Creating kind cluster: ${CLUSTER_NAME}"
kind create cluster --config "${SCRIPT_DIR}/kind-config.yaml" --name "${CLUSTER_NAME}"

# Wait for cluster to be ready
echo "Waiting for cluster to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=300s

# Create namespace
echo "Creating scan-workers namespace..."
kubectl create namespace scan-workers --dry-run=client -o yaml | kubectl apply -f -

# Create ServiceAccount for workers
echo "Creating ServiceAccount and RBAC..."
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: scan-worker
  namespace: scan-workers
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: scan-worker
  namespace: scan-workers
rules:
  - apiGroups: [""]
    resources: ["pods", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: scan-worker
  namespace: scan-workers
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: scan-worker
subjects:
  - kind: ServiceAccount
    name: scan-worker
    namespace: scan-workers
EOF

echo ""
echo "=========================================="
echo "Cluster setup complete!"
echo "=========================================="
echo "Cluster name: ${CLUSTER_NAME}"
echo "Namespace: scan-workers"
echo ""
echo "Next steps:"
echo "  1. Deploy Redis: kubectl apply -f ${SCRIPT_DIR}/redis/"
echo "  2. Deploy storage: kubectl apply -f ${SCRIPT_DIR}/storage/"
echo "  3. Install KEDA: helm install keda kedacore/keda --namespace keda --create-namespace"
echo "  4. Deploy workers: kubectl apply -f ${SCRIPT_DIR}/keda/"
echo ""
echo "To check cluster status:"
echo "  kubectl cluster-info --context kind-${CLUSTER_NAME}"
echo "  kubectl get nodes"
echo ""

