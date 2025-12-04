#!/bin/bash
set -e

CLUSTER_NAME="agentic-bugbounty-local"
LOCAL_REGISTRY="localhost:5001"

echo "=========================================="
echo "Loading images into kind cluster"
echo "=========================================="

# Check if cluster exists
if ! kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Error: Cluster ${CLUSTER_NAME} does not exist. Run setup-local-cluster.sh first."
    exit 1
fi

# Check if images exist locally
IMAGES=(
    "agentic-bugbounty/whatweb-worker:latest"
    # Add more as they're implemented:
    # "agentic-bugbounty/nuclei-worker:latest"
    # "agentic-bugbounty/katana-worker:latest"
)

echo ""
echo "Loading images into kind cluster..."

for image in "${IMAGES[@]}"; do
    local_image="${LOCAL_REGISTRY}/${image}"
    
    # Check if image exists
    if ! docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "^${local_image}$"; then
        echo "Warning: Image ${local_image} not found. Run build-local-images.sh first."
        continue
    fi
    
    echo "Loading ${image}..."
    kind load docker-image "${local_image}" --name "${CLUSTER_NAME}"
    echo "✓ Loaded ${image}"
done

echo ""
echo "=========================================="
echo "Images loaded successfully!"
echo "=========================================="
echo "Images are now available in the cluster as:"
for image in "${IMAGES[@]}"; do
    echo "  - ${LOCAL_REGISTRY}/${image}"
done
echo ""

