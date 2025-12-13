# Local Kubernetes Setup Guide

This guide explains how to set up and use a local Kubernetes cluster (using kind) to test the distributed worker infrastructure before deploying to AWS.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Architecture Overview](#architecture-overview)
- [Quick Start](#quick-start)
- [Step-by-Step Setup](#step-by-step-setup)
- [Testing Workflow](#testing-workflow)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before starting, ensure you have the following installed:

- **kind** >= 0.20 - [Installation guide](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
- **kubectl** >= 1.28 - [Installation guide](https://kubernetes.io/docs/tasks/tools/)
- **Docker** - [Installation guide](https://docs.docker.com/get-docker/)
- **Helm** 3.x - [Installation guide](https://helm.sh/docs/intro/install/)
- **Python 3.11+** with `redis` library: `pip install redis`

### Verify Prerequisites

```bash
kind version
kubectl version --client
docker --version
helm version
python3 --version
pip3 show redis
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LOCAL ENVIRONMENT                                   │
│                                                                             │
│  ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐     │
│  │  MCP Server    │────▶│  Redis Queue    │────▶│  kind Cluster   │     │
│  │  (FastAPI)     │     │  (Job Lists)    │     │  (KEDA)         │     │
│  └─────────────────┘     └─────────────────┘     │                 │     │
│         │                    │                     │  ┌──────────┐   │     │
│         │                    │                     │  │ WhatWeb  │   │     │
│         ▼                    │                     │  │   Pod    │   │     │
│  ┌─────────────────┐        │                     │  └────┬─────┘   │     │
│  │  Local PVC      │◀───────┼─────────────────────│──────┘         │     │
│  │  (Results)      │        │                     │                 │     │
│  └─────────────────┘        │                     └─────────────────┘     │
│                              │                                              │
│                    KEDA ScaledJob                                          │
│                    (triggers on Redis list length)                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Differences from AWS Setup

| Component | AWS | Local |
|-----------|-----|-------|
| Queue | SQS | Redis |
| Storage | S3 | PVC (hostPath) |
| Registry | ECR | localhost:5001 |
| Cluster | EKS | kind |

---

## Quick Start

```bash
# 1. Set up cluster
cd infra/k8s/local
./setup-local-cluster.sh

# 2. Build and load images
./scripts/build-local-images.sh
./scripts/load-images.sh

# 3. Deploy everything
./scripts/deploy-all.sh

# 4. Test it
export LOCAL_K8S_MODE=true
./scripts/test-job-submission.sh whatweb http://example.com
```

---

## Step-by-Step Setup

### Step 1: Create kind Cluster

```bash
cd infra/k8s/local
./setup-local-cluster.sh
```

This script:
- Creates a kind cluster named `agentic-bugbounty-local`
- Sets up the `scan-workers` namespace
- Creates ServiceAccount and RBAC for workers

**Verify cluster is running:**
```bash
kubectl cluster-info --context kind-agentic-bugbounty-local
kubectl get nodes
```

### Step 2: Build Worker Images

```bash
./scripts/build-local-images.sh
```

This builds the worker containers and tags them for the local registry (`localhost:5001`).

**Note:** Currently only WhatWeb worker is fully implemented. Nuclei and Katana workers will be added in future updates.

### Step 3: Load Images into Cluster

```bash
./scripts/load-images.sh
```

This loads the built images into the kind cluster so pods can pull them.

### Step 4: Deploy Infrastructure

```bash
./scripts/deploy-all.sh
```

This script deploys:
1. **Redis** - Job queue server
2. **Storage** - PVC for results
3. **KEDA** - Auto-scaling operator
4. **Worker ScaledJobs** - WhatWeb, Nuclei, Katana workers

**Verify deployment:**
```bash
kubectl get pods -n scan-workers
kubectl get scaledjobs -n scan-workers
kubectl get pvc -n scan-workers
```

### Step 5: Configure MCP Server

Set environment variables to enable local K8s mode:

```bash
export LOCAL_K8S_MODE=true
export REDIS_HOST=localhost  # Or use port-forward
export REDIS_PORT=6379
export RESULTS_PATH=/tmp/agentic-bugbounty-results
```

**Port-forward Redis (if needed):**
```bash
kubectl port-forward -n scan-workers svc/redis 6379:6379
```

---

## Testing Workflow

### Submit a Test Job

```bash
export LOCAL_K8S_MODE=true
cd infra/k8s/local/scripts
./test-job-submission.sh whatweb http://example.com
```

### Watch Pods Scale

```bash
# In one terminal
./watch-pods.sh

# In another terminal, submit jobs
./test-job-submission.sh whatweb http://example.com
```

You should see:
1. KEDA detects job in Redis queue
2. Pod is created
3. Job executes
4. Pod terminates
5. Results saved to PVC

### Check Results

```bash
./check-results.sh
```

Or manually:
```bash
# Access results via a debug pod
kubectl run -it --rm debug --image=busybox --restart=Never -n scan-workers -- sh
# Inside pod:
ls -la /mnt/scan-results/whatweb/
cat /mnt/scan-results/whatweb/YYYY/MM/DD/job-id.json
```

### Use LocalExecutor Directly

```python
from tools.local_executor import LocalExecutor, is_local_k8s_mode

if is_local_k8s_mode():
    executor = LocalExecutor()
    
    # Submit and wait
    result = executor.submit_and_wait("whatweb", "http://example.com")
    print(result)
    
    # Or fire-and-forget
    job_id = executor.submit("whatweb", "http://example.com")
    print(f"Job ID: {job_id}")
```

---

## Troubleshooting

### Cluster Not Found

**Error:** `Cluster agentic-bugbounty-local does not exist`

**Solution:**
```bash
cd infra/k8s/local
./setup-local-cluster.sh
```

### Images Not Found

**Error:** `ImagePullBackOff` or `ErrImagePull`

**Solution:**
```bash
# Rebuild and reload images
./scripts/build-local-images.sh
./scripts/load-images.sh

# Verify images are loaded
docker images | grep agentic-bugbounty
kind load docker-image --help  # Verify kind can see images
```

### Redis Connection Failed

**Error:** `Failed to connect to Redis`

**Solution:**
```bash
# Check Redis is running
kubectl get pods -n scan-workers | grep redis

# Port-forward if accessing from outside cluster
kubectl port-forward -n scan-workers svc/redis 6379:6379

# Test connection
redis-cli -h localhost -p 6379 ping
```

### Jobs Not Processing

**Symptoms:** Jobs in queue but no pods created

**Solution:**
```bash
# Check KEDA is running
kubectl get pods -n keda

# Check ScaledJob status
kubectl describe scaledjob whatweb-worker -n scan-workers

# Check Redis queue depth
kubectl run -it --rm redis-cli --image=redis:7-alpine --restart=Never -n scan-workers -- \
  redis-cli -h redis LLEN whatweb-jobs
```

### PVC Not Bound

**Error:** `PersistentVolumeClaim is in Pending state`

**Solution:**
```bash
# Check PV exists
kubectl get pv

# Create PV manually if needed
kubectl apply -f infra/k8s/local/storage/storage-pv.yaml

# Check PVC status
kubectl describe pvc scan-results -n scan-workers
```

### Worker Pod Fails

**Error:** Pod exits with error code

**Solution:**
```bash
# Check pod logs
kubectl logs -n scan-workers job/whatweb-worker-xxxxx

# Check job status
kubectl describe job -n scan-workers

# Check events
kubectl get events -n scan-workers --sort-by='.lastTimestamp'
```

### Clean Up and Start Over

```bash
# Tear down cluster
cd infra/k8s/local
./teardown-local-cluster.sh

# Recreate
./setup-local-cluster.sh
./scripts/deploy-all.sh
```

---

## Next Steps

Once local K8s is working:

1. **Test scaling** - Submit multiple jobs and verify parallel execution
2. **Test different tools** - Try Nuclei and Katana workers (when implemented)
3. **Integrate with MCP** - Update MCP server to use LocalExecutor
4. **Move to AWS** - Deploy to EKS using the AWS setup guide

---

## Additional Resources

- [kind Documentation](https://kind.sigs.k8s.io/)
- [KEDA Documentation](https://keda.sh/docs/)
- [Redis Documentation](https://redis.io/docs/)
- [Distributed Infrastructure Guide (AWS)](DISTRIBUTED_INFRASTRUCTURE.md)

