# Multi-Scope Kubernetes Scanning Guide

This guide explains how to use the Kubernetes infrastructure to scan multiple bug bounty scopes in parallel.

## Overview

The multi-scope scanning system leverages local Kubernetes (kind) cluster with KEDA for automatic scaling of scan workers. This enables:

- **Parallel execution**: Scan multiple scopes simultaneously
- **Auto-scaling**: Workers scale from 0 to N based on job queue depth
- **Cost efficient**: Only pay for compute when jobs are running
- **Isolated execution**: Each scan runs in its own container

## Prerequisites

1. **Kubernetes cluster set up**:
   ```bash
   cd infra/k8s/local
   ./setup-local-cluster.sh
   ./scripts/deploy-all.sh
   ```

2. **Environment variables**:
   ```bash
   export LOCAL_K8S_MODE=true
   export REDIS_HOST=localhost
   export REDIS_PORT=6379
   export OPENAI_API_KEY=your-key-here  # For triage
   ```

3. **MCP server running** (for ZAP scans):
   ```bash
   python mcp_zap_server.py
   ```

## Quick Start

### Scan Multiple Scopes

```bash
# Scan specific scope files
python tools/multi_scope_runner.py \
  --scopes scopes/23andme_bbp.json scopes/hackerone.json

# Scan all scopes in a directory
python tools/multi_scope_runner.py \
  --scopes-dir scopes/ \
  --max-concurrent 3

# Disable K8s mode (use local execution)
python tools/multi_scope_runner.py \
  --scopes scope.json \
  --no-k8s
```

### Single Scope with K8s

```bash
# Enable K8s mode for single scope
python scope_runner.py --scope scope.json --k8s-mode
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Multi-Scope Runner                       │
│  (tools/multi_scope_runner.py)                              │
└──────────────┬──────────────────────────────────────────────┘
               │
               ├─── Submit jobs to Redis queues
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│                    Redis Queues                             │
│  - whatweb-jobs                                             │
│  - nuclei-jobs                                               │
│  - katana-jobs                                               │
└──────────────┬──────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│              KEDA ScaledJobs (Kubernetes)                    │
│  - Monitors Redis queue depth                                │
│  - Scales 0→N pods automatically                             │
└──────────────┬──────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│              Worker Pods (Containers)                       │
│  - whatweb-worker                                            │
│  - nuclei-worker                                             │
│  - katana-worker                                             │
└──────────────┬──────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│              Results Storage (PVC)                           │
│  - /mnt/scan-results/{tool}/{job_id}.json                   │
└──────────────┬──────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│              Results Queue (Redis)                          │
│  - scan-results                                              │
└──────────────┬──────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│              Multi-Scope Runner                             │
│  - Polls results queue                                       │
│  - Runs triage per scope                                     │
│  - Generates aggregated reports                             │
└─────────────────────────────────────────────────────────────┘
```

## Workflow

1. **Job Submission**: Multi-scope runner submits scan jobs to Redis queues
2. **Auto-Scaling**: KEDA detects jobs in queue and scales up worker pods
3. **Execution**: Worker pods process jobs and write results to PVC
4. **Results Notification**: Workers push completion notifications to Redis results queue
5. **Result Retrieval**: Multi-scope runner polls results queue and reads result files
6. **Triage**: AI triage runs on findings from each scope
7. **Report Generation**: Reports are generated per scope and aggregated

## Output Structure

```
output_zap/
├── scope_23andme_bbp/
│   ├── scope_results.json          # Scope-specific results
│   ├── recon_*.json                # Recon results per host
│   └── ...
├── scope_hackerone/
│   └── ...
├── triage_*.json                   # Triage results
├── *_reports_index.json            # Report indexes
├── *__*.md                         # Markdown reports
└── multi_scope_summary.json       # Aggregated summary
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOCAL_K8S_MODE` | `false` | Enable K8s execution mode |
| `REDIS_HOST` | `localhost` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `RESULTS_PATH` | `/tmp/agentic-bugbounty-results` | Results storage path |
| `MCP_BASE` | `http://localhost:8000` | MCP server URL |
| `OPENAI_API_KEY` | - | Required for AI triage |

### Command-Line Options

**multi_scope_runner.py**:
- `--scopes`: List of scope JSON files
- `--scopes-dir`: Directory containing scope files
- `--max-concurrent`: Maximum concurrent scopes (default: 3)
- `--no-k8s`: Disable K8s mode
- `--output-dir`: Output directory (default: output_zap)

**scope_runner.py**:
- `--scope`: Scope JSON file
- `--k8s-mode`: Enable K8s mode
- `--no-secondary`: Scan only primary targets
- `--ffuf-wordlist`: Optional wordlist for ffuf

## Supported Tools

| Tool | K8s Worker | Status |
|------|------------|--------|
| WhatWeb | ✅ | Available |
| Nuclei | ✅ | Available |
| Katana | ✅ | Available |
| Dalfox | ⚠️ | Partial |
| ffuf | ⚠️ | Partial |
| ZAP | ❌ | Via MCP server |

## Validation

Run the validation script to verify the pipeline:

```bash
# Full validation
python tests/validate_k8s_scan_pipeline.py

# Skip end-to-end test
python tests/validate_k8s_scan_pipeline.py --skip-e2e
```

The validation script checks:
1. Prerequisites (k8s cluster, Redis, KEDA)
2. Job submission
3. Results retrieval
4. Triage functionality
5. Report generation
6. End-to-end multi-scope test

## Troubleshooting

### Jobs Not Processing

1. Check Redis connectivity:
   ```bash
   kubectl port-forward -n scan-workers svc/redis 6379:6379
   redis-cli ping
   ```

2. Check KEDA ScaledJobs:
   ```bash
   kubectl get scaledjobs -n scan-workers
   kubectl describe scaledjob whatweb-worker -n scan-workers
   ```

3. Check worker pods:
   ```bash
   kubectl get pods -n scan-workers
   kubectl logs -n scan-workers <pod-name>
   ```

### Results Not Appearing

1. Check results queue:
   ```bash
   redis-cli LLEN scan-results
   ```

2. Check PVC:
   ```bash
   kubectl get pvc -n scan-workers
   ```

3. Check results path:
   ```bash
   # If using local mode, check local path
   ls -la /tmp/agentic-bugbounty-results/
   ```

### Triage Failures

1. Verify OPENAI_API_KEY is set
2. Check triage logs in output_zap/
3. Verify findings files exist and are valid JSON

## Best Practices

1. **Start Small**: Test with 1-2 scopes before scaling up
2. **Monitor Resources**: Watch pod resource usage during scans
3. **Rate Limiting**: Respect program rate limits in scope files
4. **Error Handling**: Check multi_scope_summary.json for failed scopes
5. **Cleanup**: Remove old results periodically to save disk space

## Examples

### Example 1: Scan Two Scopes

```bash
export LOCAL_K8S_MODE=true
python tools/multi_scope_runner.py \
  --scopes scopes/23andme_bbp.json scopes/hackerone.json \
  --max-concurrent 2
```

### Example 2: Scan All Scopes in Directory

```bash
export LOCAL_K8S_MODE=true
python tools/multi_scope_runner.py \
  --scopes-dir scopes/ \
  --max-concurrent 3 \
  --output-dir output_zap/multi_scan_$(date +%Y%m%d)
```

### Example 3: Single Scope with K8s

```bash
export LOCAL_K8S_MODE=true
python scope_runner.py \
  --scope scope.lab.json \
  --k8s-mode
```

## Integration with agentic_runner.py

The `agentic_runner.py` script automatically uses K8s workers when `LOCAL_K8S_MODE=true`:

```bash
export LOCAL_K8S_MODE=true
python agentic_runner.py --scope scope.json
```

This enables K8s execution for:
- Nuclei recon
- Katana crawling
- Other supported tools

## Next Steps

- Add more tools to K8s workers (dalfox, sqlmap, etc.)
- Implement distributed mode (AWS EKS)
- Add result aggregation and deduplication across scopes
- Implement real-time progress tracking

