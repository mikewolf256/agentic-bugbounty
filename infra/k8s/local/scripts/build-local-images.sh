#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
LOCAL_REGISTRY="localhost:5001"

echo "=========================================="
echo "Building worker images for local K8s"
echo "=========================================="

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker is not running"
    exit 1
fi

# Build WhatWeb worker
echo ""
echo "Building WhatWeb worker..."
cd "${PROJECT_ROOT}/infra/docker/whatweb-worker"
docker build -t agentic-bugbounty/whatweb-worker:latest .
docker tag agentic-bugbounty/whatweb-worker:latest "${LOCAL_REGISTRY}/agentic-bugbounty/whatweb-worker:latest"
echo "✓ WhatWeb worker built"

# Note: For now, we only have WhatWeb worker implemented
# When Nuclei and Katana workers are created, add them here:
#
# echo ""
# echo "Building Nuclei worker..."
# cd "${PROJECT_ROOT}/infra/docker/nuclei-worker"
# docker build -t agentic-bugbounty/nuclei-worker:latest .
# docker tag agentic-bugbounty/nuclei-worker:latest "${LOCAL_REGISTRY}/agentic-bugbounty/nuclei-worker:latest"
# echo "✓ Nuclei worker built"
#
# echo ""
# echo "Building Katana worker..."
# cd "${PROJECT_ROOT}/infra/docker/katana-worker"
# docker build -t agentic-bugbounty/katana-worker:latest .
# docker tag agentic-bugbounty/katana-worker:latest "${LOCAL_REGISTRY}/agentic-bugbounty/katana-worker:latest"
# echo "✓ Katana worker built"

echo ""
echo "=========================================="
echo "Images built successfully!"
echo "=========================================="
echo "Next step: Run load-images.sh to load images into kind cluster"
echo ""

