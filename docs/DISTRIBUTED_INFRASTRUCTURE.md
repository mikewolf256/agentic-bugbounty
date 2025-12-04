# Distributed Infrastructure Guide

This guide explains how to run scan tools (WhatWeb, Nuclei, Katana, etc.) on-demand in AWS using Kubernetes with KEDA, enabling scale-to-zero for cost efficiency.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Key Concept: Job/Worker Pattern](#key-concept-jobworker-pattern)
- [How It Integrates with MCP](#how-it-integrates-with-mcp)
- [Scope and Security](#scope-and-security)
- [Setup Guide](#setup-guide)
- [Configuration](#configuration)
- [Cost Optimization](#cost-optimization)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              YOUR LOCAL ENVIRONMENT                                  │
│                                                                                      │
│  ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐             │
│  │  agentic_runner │─────▶│   MCP Server    │─────▶│  Local Docker   │             │
│  │     .py         │      │   (FastAPI)     │      │  (WhatWeb, etc) │             │
│  └─────────────────┘      │   port 8000     │      └─────────────────┘             │
│                           └────────┬────────┘                                       │
│                                    │                                                │
│                    DISTRIBUTED_MODE=true                                            │
│                                    │                                                │
└────────────────────────────────────┼────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                    AWS                                               │
│                                                                                      │
│  ┌─────────────┐    ┌─────────────┐    ┌────────────────────────────────────┐      │
│  │  SQS Queue  │◀───│ Job Message │    │         EKS Cluster (KEDA)         │      │
│  │  (Jobs)     │    │             │    │                                    │      │
│  └──────┬──────┘    └─────────────┘    │  Pods scale 0→N based on queue    │      │
│         │                              │                                    │      │
│         │ KEDA watches queue depth     │  ┌──────────┐  ┌──────────┐       │      │
│         └─────────────────────────────▶│  │ WhatWeb  │  │  Nuclei  │  ...  │      │
│                                        │  │   Pod    │  │   Pod    │       │      │
│                                        │  └────┬─────┘  └────┬─────┘       │      │
│                                        └───────┼─────────────┼─────────────┘      │
│                                                │             │                     │
│                                                ▼             ▼                     │
│                                        ┌─────────────────────────┐                 │
│                                        │      S3 Bucket          │                 │
│                                        │   (Results JSON)        │                 │
│                                        └───────────┬─────────────┘                 │
│                                                    │                               │
│  ┌─────────────┐                                   │                               │
│  │ SQS Results │◀──────────────────────────────────┘                               │
│  │   Queue     │    (completion notification)                                      │
│  └──────┬──────┘                                                                   │
│         │                                                                          │
└─────────┼──────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│  ┌─────────────────┐      ┌─────────────────┐                                       │
│  │ Results Poller  │─────▶│   MCP Server    │─────▶ Triage, Reports, etc.          │
│  │                 │      │                 │                                       │
│  └─────────────────┘      └─────────────────┘                                       │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Concept: Job/Worker Pattern

**Important: The containers do NOT run an API server.** They work like batch jobs:

1. **Container starts** → Reads ONE job from SQS queue
2. **Runs the tool** (whatweb, nuclei, etc.) against the target
3. **Uploads results** to S3 as JSON
4. **Sends notification** to results queue
5. **Container exits** (terminates)

This is different from a traditional API where a container stays running and waits for requests. Benefits:

| Aspect | Traditional API | Job/Worker Pattern |
|--------|-----------------|-------------------|
| Idle Cost | Pays for idle time | $0 when no jobs |
| Scaling | Manual or time-based | Automatic based on queue |
| Isolation | Shared container state | Fresh container per job |
| Failure | Affects other requests | Only affects one job |

### Job Message Format

When MCP dispatches a job to SQS:

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "tool": "whatweb",
  "target": "https://app.example.com",
  "options": {
    "aggression": 3,
    "timeout": 120
  },
  "metadata": {
    "program": "example-bbp",
    "submitted_by": "mcp-server"
  },
  "submitted_at": "2024-12-04T10:30:00Z"
}
```

---

## How It Integrates with MCP

The MCP server can operate in two modes with the **same API**:

### Mode 1: Local Execution (Default)

```bash
# No AWS config needed - uses local Docker
python mcp_zap_server.py

# Scans run in local Docker containers
curl -X POST http://localhost:8000/mcp/run_whatweb \
  -d '{"target": "http://example.com"}'
```

### Mode 2: Distributed Execution (AWS)

```bash
# Enable distributed mode
export DISTRIBUTED_MODE=true
export AWS_REGION=us-east-1
export SQS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789/scan-jobs
export S3_BUCKET=my-scan-results

python mcp_zap_server.py

# Same API - but jobs go to AWS workers
curl -X POST http://localhost:8000/mcp/run_whatweb \
  -d '{"target": "http://example.com"}'
```

### Code Flow

```python
@app.post("/mcp/run_whatweb")
def run_whatweb(req: WhatWebRequest):
    # 1. Scope check happens LOCALLY first
    validated_host = _enforce_scope(req.target)
    
    # 2. Check execution mode
    if is_distributed_mode():
        # Submit to AWS workers
        executor = DistributedExecutor()
        
        if req.async_mode:
            # Fire and forget - return job ID immediately
            job_id = executor.submit("whatweb", req.target)
            return {"job_id": job_id, "status": "queued"}
        else:
            # Wait for results (blocking)
            result = executor.submit_and_wait("whatweb", req.target)
            return WhatWebResult(**result)
    else:
        # Run locally via Docker (existing behavior)
        return run_whatweb_local(req.target)
```

---

## Scope and Security

### Scope Enforcement Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SCOPE FLOW                                          │
│                                                                             │
│  1. User calls: POST /mcp/set_scope                                        │
│     {                                                                       │
│       "program_name": "example-bbp",                                        │
│       "primary_targets": ["app.example.com", "api.example.com"],           │
│       "secondary_targets": []                                               │
│     }                                                                       │
│                                                                             │
│  2. MCP Server stores scope in memory (SCOPE global variable)              │
│                                                                             │
│  3. User calls: POST /mcp/run_whatweb {"target": "http://app.example.com"} │
│                                                                             │
│  4. MCP Server:                                                             │
│     a) Validates target is in scope (_enforce_scope)  ◀── SECURITY CHECK   │
│     b) If DISTRIBUTED_MODE=false: runs Docker locally                      │
│     c) If DISTRIBUTED_MODE=true: submits job to SQS                        │
│                                                                             │
│  5. Scope is enforced LOCALLY before any job is dispatched                 │
│     Workers trust that jobs in the queue are pre-validated                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Security Point:** Scope validation happens on the MCP server BEFORE any job is sent to AWS. The workers trust that jobs in the queue have already been validated.

---

## Setup Guide

### Prerequisites

- AWS account with appropriate permissions
- Terraform >= 1.0
- kubectl configured
- Helm 3.x

### Step 1: Deploy AWS Infrastructure

```bash
cd infra/terraform

# Initialize Terraform
terraform init

# Review the plan
terraform plan

# Deploy (creates EKS, SQS, S3, IAM)
terraform apply
```

### Step 2: Configure kubectl

```bash
# Get the command from Terraform output
aws eks update-kubeconfig --region us-east-1 --name agentic-bugbounty
```

### Step 3: Install KEDA

```bash
# Add KEDA Helm repo
helm repo add kedacore https://kedacore.github.io/charts
helm repo update

# Create namespaces
kubectl apply -f infra/k8s/keda/keda-install.yaml

# Install KEDA with custom values
helm install keda kedacore/keda \
  --namespace keda \
  -f infra/k8s/keda/keda-values.yaml
```

### Step 4: Deploy Worker Configurations

```bash
# Update the YAML files with your AWS account details
# (Replace ${AWS_ACCOUNT_ID}, ${AWS_REGION}, ${SQS_QUEUE_URL}, etc.)

kubectl apply -f infra/k8s/keda/scaledjob-whatweb.yaml
kubectl apply -f infra/k8s/keda/scaledjob-nuclei.yaml
kubectl apply -f infra/k8s/keda/scaledjob-katana.yaml
```

### Step 5: Build and Push Worker Images

```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com

# Build and push WhatWeb worker
cd infra/docker/whatweb-worker
docker build -t agentic-bugbounty/whatweb-worker .
docker tag agentic-bugbounty/whatweb-worker:latest \
  ${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com/agentic-bugbounty/whatweb-worker:latest
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com/agentic-bugbounty/whatweb-worker:latest
```

### Step 6: Configure MCP Server

```bash
# Set environment variables
export DISTRIBUTED_MODE=true
export AWS_REGION=us-east-1
export SQS_QUEUE_URL=$(terraform output -raw sqs_queue_url)
export SQS_PRIORITY_QUEUE_URL=$(terraform output -raw sqs_priority_queue_url)
export RESULTS_QUEUE_URL=$(terraform output -raw sqs_results_queue_url)
export S3_BUCKET=$(terraform output -raw s3_bucket)

# Start MCP server
python mcp_zap_server.py
```

### Step 7: Start Results Poller (Optional)

```bash
# In a separate terminal
python tools/job_results_poller.py
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DISTRIBUTED_MODE` | `false` | Enable distributed execution |
| `AWS_REGION` | `us-east-1` | AWS region for resources |
| `SQS_QUEUE_URL` | - | Main job queue URL |
| `SQS_PRIORITY_QUEUE_URL` | - | Priority queue for fast jobs |
| `RESULTS_QUEUE_URL` | - | Queue for completion notifications |
| `S3_BUCKET` | - | Bucket for storing results |

### Tool Timeouts

Default timeouts per tool (configurable in `job_submitter.py`):

| Tool | Timeout | Description |
|------|---------|-------------|
| WhatWeb | 5 min | Technology fingerprinting |
| Nuclei | 30 min | Vulnerability scanning |
| Katana | 15 min | Web crawling |
| Dalfox | 10 min | XSS validation |
| ffuf | 20 min | Directory fuzzing |

---

## Cost Optimization

### Scale-to-Zero

The key benefit is that pods scale to zero when idle:

```
Queue empty     → 0 pods running → $0/hour compute
1 job arrives   → KEDA spins up 1 pod → runs scan → pod terminates
10 jobs arrive  → KEDA spins up 10 pods → parallel scans → all terminate
Queue empty     → back to 0 pods → $0/hour compute
```

### Estimated Costs

For occasional scanning (e.g., 100 scans/month):

| Resource | Cost |
|----------|------|
| EKS Control Plane | ~$73/month (fixed) |
| EC2 (Spot instances) | ~$5-20/month (only when scanning) |
| SQS | ~$0.01/month (negligible) |
| S3 | ~$0.50/month (results storage) |
| **Total** | **~$80-95/month** |

For comparison, keeping 2 `t3.medium` instances running 24/7 would cost ~$60/month PLUS the EKS control plane.

### Cost-Saving Tips

1. **Use Spot Instances**: The Terraform config uses Spot by default (up to 90% cheaper)
2. **Use Fargate for Infrequent Scans**: No EC2 management, pay per-second
3. **Set Aggressive TTLs**: Jobs auto-clean up after completion
4. **Use S3 Lifecycle Rules**: Auto-archive old results to Glacier

---

## Component Reference

| Component | Purpose | Location |
|-----------|---------|----------|
| Terraform | Creates AWS infrastructure | `infra/terraform/` |
| KEDA Configs | Defines auto-scaling rules | `infra/k8s/keda/` |
| Worker Dockerfiles | Container images for tools | `infra/docker/` |
| Job Submitter | Submit jobs to queue | `tools/job_submitter.py` |
| Results Poller | Pull results from AWS | `tools/job_results_poller.py` |
| Distributed Executor | MCP integration helper | `tools/distributed_executor.py` |

---

## Troubleshooting

### Jobs Not Processing

```bash
# Check queue depth
aws sqs get-queue-attributes \
  --queue-url $SQS_QUEUE_URL \
  --attribute-names ApproximateNumberOfMessages

# Check KEDA is running
kubectl get pods -n keda

# Check ScaledJob status
kubectl get scaledjobs -n scan-workers
kubectl describe scaledjob whatweb-worker -n scan-workers
```

### Worker Pod Failures

```bash
# List completed/failed jobs
kubectl get jobs -n scan-workers

# Check pod logs
kubectl logs -n scan-workers job/whatweb-worker-xxxxx
```

### Results Not Appearing

```bash
# Check S3 bucket
aws s3 ls s3://$S3_BUCKET/whatweb/ --recursive

# Check results queue
aws sqs get-queue-attributes \
  --queue-url $RESULTS_QUEUE_URL \
  --attribute-names ApproximateNumberOfMessages
```

