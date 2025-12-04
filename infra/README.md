# Infrastructure: On-Demand Container Execution

This directory contains infrastructure-as-code for running scan tools (WhatWeb, Katana, Nuclei, etc.) on-demand using Kubernetes with KEDA (scale-to-zero).

**Two deployment modes are supported:**
- **Local K8s** (kind cluster) - For testing and development
- **AWS EKS** - For production workloads

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Agentic Bug Bounty Infra                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────────────────────┐│
│  │  MCP Server  │────▶│  SQS Queue   │────▶│   EKS Cluster (KEDA)         ││
│  │  (FastAPI)   │     │  (Job Queue) │     │                              ││
│  └──────────────┘     └──────────────┘     │  ┌────────┐  ┌────────┐     ││
│         │                    │              │  │WhatWeb │  │ Nuclei │     ││
│         │                    │              │  │  Pod   │  │  Pod   │ ... ││
│         ▼                    │              │  └────────┘  └────────┘     ││
│  ┌──────────────┐           │              │       ▲           ▲          ││
│  │     S3       │◀──────────┼──────────────│───────┴───────────┘          ││
│  │  (Results)   │           │              │   (Scales 0→N based on queue)││
│  └──────────────┘           │              └──────────────────────────────┘│
│                             │                                              │
│                    KEDA ScaledJob                                          │
│                    (triggers on SQS)                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Benefits

- **Cost Efficient**: Pods scale to zero when no jobs - pay only for compute time
- **Auto-Scaling**: KEDA automatically spins up workers when jobs arrive
- **Isolated**: Each scan runs in its own container with no state
- **Parallel**: Multiple scans can run concurrently

## Quick Start

### Local K8s Setup (Recommended for Testing)

```bash
# 1. Set up local kind cluster
cd k8s/local
./setup-local-cluster.sh

# 2. Build and load worker images
./scripts/build-local-images.sh
./scripts/load-images.sh

# 3. Deploy all components (Redis, storage, KEDA, workers)
./scripts/deploy-all.sh

# 4. Test job submission
export LOCAL_K8S_MODE=true
./scripts/test-job-submission.sh whatweb http://example.com
```

📖 **Full guide:** [Local K8s Setup Guide](../docs/LOCAL_K8S_SETUP.md)

### AWS EKS Setup (Production)

```bash
# 1. Set up AWS credentials
export AWS_PROFILE=your-profile

# 2. Deploy infrastructure with Terraform
cd terraform
terraform init
terraform apply

# 3. Deploy KEDA and worker configs
cd ../k8s/keda
kubectl apply -f keda-install.yaml
helm install keda kedacore/keda --namespace keda -f keda-values.yaml
kubectl apply -f scaledjob-*.yaml

# 4. Test job submission
export DISTRIBUTED_MODE=true
python ../tools/job_submitter.py --tool whatweb --target http://example.com
```

📖 **Full guide:** [Distributed Infrastructure Guide](../docs/DISTRIBUTED_INFRASTRUCTURE.md)

## Components

| Component | Description |
|-----------|-------------|
| `terraform/` | AWS infrastructure (EKS, SQS, S3, IAM) |
| `k8s/keda/` | KEDA ScaledJob configurations (AWS) |
| `k8s/local/` | Local K8s setup (kind cluster, Redis, local configs) |
| `docker/` | Dockerfiles for scan tools |

## Supported Tools

| Tool | Container | Max Runtime |
|------|-----------|-------------|
| WhatWeb | `whatweb-worker` | 5 min |
| Nuclei | `nuclei-worker` | 30 min |
| Katana | `katana-worker` | 15 min |
| Dalfox | `dalfox-worker` | 10 min |
| ffuf | `ffuf-worker` | 20 min |

