# Infrastructure: On-Demand Container Execution

This directory contains infrastructure-as-code for running scan tools (WhatWeb, Katana, Nuclei, etc.) on-demand in AWS using Kubernetes with KEDA (scale-to-zero).

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

```bash
# 1. Set up AWS credentials
export AWS_PROFILE=your-profile

# 2. Deploy infrastructure with Terraform
cd terraform
terraform init
terraform apply

# 3. Deploy KEDA and worker configs
cd ../k8s
kubectl apply -f keda/
kubectl apply -f workers/

# 4. Test job submission
python ../tools/job_submitter.py --tool whatweb --target http://example.com
```

## Components

| Component | Description |
|-----------|-------------|
| `terraform/` | AWS infrastructure (EKS, SQS, S3, IAM) |
| `k8s/keda/` | KEDA ScaledJob configurations |
| `k8s/workers/` | Worker container definitions |
| `docker/` | Dockerfiles for scan tools |

## Supported Tools

| Tool | Container | Max Runtime |
|------|-----------|-------------|
| WhatWeb | `whatweb-worker` | 5 min |
| Nuclei | `nuclei-worker` | 30 min |
| Katana | `katana-worker` | 15 min |
| Dalfox | `dalfox-worker` | 10 min |
| ffuf | `ffuf-worker` | 20 min |

