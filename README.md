# 🧠 Agentic Bug Bounty System
### Automated, Intelligent, and Scalable Vulnerability Research Framework

> **Mission:** Build an autonomous bug bounty reconnaissance and triage engine that uses AI, automation, and scalable containers to identify and validate impactful vulnerabilities — without wasting tokens or human time.

---

## 🌐 Overview

**Agentic Bug Bounty** is a modular framework for automated, AI-assisted security testing across public bug bounty programs.  
It combines traditional scanners (ffuf, Dalfox, Nuclei, Katana, etc.) with an LLM-based triage pipeline that filters, analyzes, and summarizes findings into clean, human-ready vulnerability reports.

This project is designed to:
- Run **continuously** against program scopes,
- **Self-filter** noise before LLM inference,
- **Validate** findings with external proof engines (Dalfox, Nuclei, etc.),
- Scale horizontally across containers or Kubernetes jobs,
- Save human triagers **time and money** by auto-prioritizing high-value results.

---

## 🧩 Current Architecture

```
┌───────────────────────────────────────────────────────────┐
│                  Agentic Bug Bounty Stack                 │
├───────────────────────────────────────────────────────────┤
│ Scope Runner (Python)          → Feeds in-scope targets   │
│ MCP (Modular Control Plane)    → Orchestrates recon/scans │
│ Web Recon / Active Scans       → Collect findings         │
│ Dedupe & Noise Filter          → Drops low-value alerts   │
│ AI Triage (OpenAI / GPT-4o)    → Summarizes & scores CVSS │
│ Dalfox / SQLmap / BAC / SSRF  → Validates key bug classes │
│ Markdown Report Generator      → Produces human reports   │
└───────────────────────────────────────────────────────────┘
```

**Data Flow:**
1. **Scope ingestion:** Import from HackerOne directly or define a `scope.json` manually.  
2. **Scanning:** Recon tools crawl each target and export findings.  
3. **Pre-processing:** `mcp_helpers/dedupe.py` removes noise and deduplicates results.  
4. **AI triage:** Only meaningful findings are passed to the LLM for contextual scoring, impact, and bounty estimation.  
5. **Validation:** Tools like **Dalfox** (XSS), **sqlmap** (SQLi), and MCP-powered **BAC/SSRF checks** re-validate high-value findings.  
6. **Recon & Enrichment:** Katana+Nuclei web recon, JS miner, and backup hunter jobs enrich the surface map for each host.  
7. **Reporting:** Results are written as structured JSON + Markdown vulnerability reports.

---

## ⚙️ Key Features

| Feature | Description |
|----------|--------------|
| **Smart Pre-Filter** | Removes redundant and low-value scanner noise before AI triage — saving up to 90% token cost. |
| **CVSS & Focus Filtering** | Keeps only findings with estimated CVSS ≥ 6.0 or high-impact keywords (XSS, SQLi, SSRF, Auth Bypass…). |
| **Dalfox Validation** | Runs automatic confirmation of reflected XSS vectors via the Dalfox engine. |
| **SQLi / BAC / SSRF Validation** | Uses MCP endpoints (`/mcp/run_sqlmap`, `/mcp/run_bac_checks`, `/mcp/run_ssrf_checks`) to validate SQL injection, broken access control, and SSRF candidates, surfacing engine results in Markdown. |
| **JS Miner & Backup Hunter** | Background jobs (via MCP) crawl JavaScript and common backup/config paths; results are wired into host profiles and full-scan summaries. |
| **Evidence Stubbing** | Always writes artifacts, even on “0 issue” scans, for full traceability. |
| **AI-Based Triage** | Summarizes findings, assigns CVSS vectors, and estimates bounty value. |
| **Modular Control Plane (MCP)** | Provides API endpoints to start scans, triage, or check scope compliance. |
| **Token-Efficient Design** | Filters findings *before* LLM inference to cut costs and scale affordably. |
| **RAG Knowledge Base** | Semantic search over 8k+ historical HackerOne reports for context-aware triage. |
| **Distributed Execution** | Scale-to-zero AWS workers via EKS/KEDA — only pay when scanning. |
| **HackerOne Integration** | Auto-import program scopes, bounty ranges, and rules directly from HackerOne. |
| **Human Validation Workflow** | Queue high-value findings for manual review before submission with Discord/Slack alerts. |
| **Browser PoC Validation** | Chrome DevTools integration for visual PoC validation with screenshot capture. |
| **HackerOne Submission** | Automated submission of approved findings to HackerOne via API. |

---

## 🔍 Human Validation Workflow

The system includes a complete human validation workflow that queues high-value findings for manual review before optional submission to HackerOne.

### Features

- **Automatic Queueing**: Findings with CVSS ≥ 7.0 or estimated bounty ≥ $500 are automatically queued
- **Discord/Slack Alerts**: Receive notifications when findings need validation
- **CLI Management**: Easy approve/reject workflow via command-line tools
- **HackerOne Integration**: Submit approved findings directly to HackerOne via API

### Environment Variables

```bash
# Discord webhook for validation alerts
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."

# HackerOne API credentials (optional, for submission)
export H1_API_TOKEN="your_api_token"
export H1_USERNAME="your_h1_username"
```

### CLI Usage

#### Validation Management

```bash
# List pending validations
python tools/validation_cli.py list

# Show details of a specific validation
python tools/validation_cli.py show <validation_id>

# Approve a finding
python tools/validation_cli.py approve <validation_id> --notes "Looks good, confirmed exploit"

# Reject a finding
python tools/validation_cli.py reject <validation_id> --reason "False positive, already patched"

# Show validation statistics
python tools/validation_cli.py stats
```

#### HackerOne Submission

```bash
# List approved findings ready for submission
python tools/submission_cli.py list-approved

# Submit a single approved finding
python tools/submission_cli.py submit <validation_id> --program <handle>

# Submit all approved findings for a program
python tools/submission_cli.py submit-all --program <handle>

# Check submission status
python tools/submission_cli.py status <validation_id>
```

### Configuration

Add to your scan profile (`profiles/full.yaml`):

```yaml
human_validation:
  enabled: true
  auto_queue_cvss_threshold: 7.0
  auto_queue_bounty_threshold: 500
  require_validation: true  # Findings must be approved before submission
```

---

## 🌐 Browser PoC Validation

The system includes headless browser PoC validation using Chrome DevTools Protocol for visual proof-of-concept validation.

### Features

- **Screenshot Capture**: Automatically captures screenshots of exploited vulnerabilities
- **Visual Validation**: Detects visual indicators of exploitation (XSS, UI-based issues)
- **Console Log Capture**: Captures browser console logs for debugging
- **Chrome DevTools Integration**: Uses existing Chrome DevTools infrastructure

### Setup

1. **Start Chrome with remote debugging**:
   ```bash
   chrome --remote-debugging-port=9222
   ```

2. **Configure in profile** (`profiles/full.yaml`):
   ```yaml
   browser_validation:
     enabled: true
     auto_validate_xss: true
     auto_validate_ui: true
     devtools_port: 9222
     screenshot_timeout: 5
     require_devtools: false  # Skip if DevTools unavailable
   ```

### MCP Endpoint

```bash
POST /mcp/validate_poc_with_browser
{
  "finding": {
    "url": "https://example.com/page?param=<script>alert(1)</script>",
    "type": "xss",
    "payload": "<script>alert(1)</script>"
  },
  "devtools_port": 9222,
  "wait_timeout": 5
}
```

### Workflow

1. **Scan** → Findings are discovered
2. **Triage** → AI triage analyzes findings
3. **Browser PoC Validation** → Eligible findings (XSS, UI-based) are validated with browser
4. **Validation Queue** → High-value findings are queued for human review
5. **Approval** → Human reviewer approves/rejects
6. **Submission** → Approved findings are submitted to HackerOne

---

## 🎯 HackerOne Scope Integration

Automatically import bug bounty program scopes from HackerOne to target real programs with proper scope enforcement.

### Quick Start

```bash
# Fetch a program scope by handle
python tools/h1_scope_fetcher.py fetch 23andme_bbp

# Fetch from HackerOne URL
python tools/h1_scope_fetcher.py fetch "https://hackerone.com/security?type=team"

# Fetch and immediately start scanning
python tools/h1_scope_fetcher.py fetch hackerone --run

# Search for programs
python tools/h1_scope_fetcher.py search "fintech"

# List popular bounty programs  
python tools/h1_scope_fetcher.py list --top 20
```

### MCP API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /mcp/import_h1_scope` | Import program scope from HackerOne and optionally set as active |
| `POST /mcp/search_h1_programs` | Search for bug bounty programs |
| `GET /mcp/h1_program/{handle}` | Get full program details including scope and policies |

### Import via API

```bash
# Import and set as active scope
curl -X POST http://localhost:8000/mcp/import_h1_scope \
  -H "Content-Type: application/json" \
  -d '{"handle": "23andme_bbp", "auto_set_scope": true}'
```

Response includes:
- Program name and URL
- In-scope and out-of-scope asset counts
- Primary targets (ready for scanning)
- Bounty ranges by severity
- Path to saved scope file

### What Gets Extracted

| Data | Description |
|------|-------------|
| **In-scope assets** | URLs, APIs, wildcards, CIDRs, mobile apps, source code |
| **Out-of-scope** | Excluded targets with explanations |
| **Bounty ranges** | Min/max payouts per severity level |
| **Program rules** | Rate limits, safe harbor, excluded vuln types |
| **Asset instructions** | Per-target notes from the program |

### Generated Scope Format

```json
{
  "program_name": "23andMe Bug Bounty",
  "program_handle": "23andme_bbp",
  "primary_targets": [
    "https://api.23andme.com",
    "https://www.23andme.com"
  ],
  "rules": {
    "safe_harbor": true,
    "allow_automated": true,
    "excluded_vuln_types": ["dos", "rate limiting"]
  },
  "in_scope": [
    {
      "url": "https://api.23andme.com",
      "type": "URL",
      "bounty_eligible": true,
      "instruction": "Main API endpoint"
    }
  ],
  "bounties": {
    "low": {"min": 150, "max": 300},
    "critical": {"min": 7500, "max": 15000}
  }
}
```

### Container Cluster Workflow

For distributing work across a Kubernetes cluster:

```python
from tools.h1_client import H1Client

# 1. Fetch program scope
client = H1Client()
program = client.fetch_program("target_program")

# 2. Generate per-target job configurations
for asset in program.in_scope_assets:
    if asset.asset_type.value in ("URL", "WILDCARD", "API"):
        job_config = {
            "target": asset.to_target_url(),
            "program": program.name,
            "rules": program.policy.to_dict(),
        }
        # 3. Dispatch to worker container
        dispatch_k8s_job(job_config)
```

See [`docs/hackerone_integration.md`](docs/hackerone_integration.md) for complete documentation.

---

## 🧠 RAG Vulnerability Knowledge Base

The system includes a RAG (Retrieval-Augmented Generation) pipeline that ingests historical HackerOne disclosed reports and uses them to enhance triage quality. During triage, similar historical vulnerabilities are automatically retrieved and injected into the LLM prompt, providing:

- **Historical precedent** for severity and bounty estimation
- **Proven payloads** and attack patterns
- **Impact narratives** from accepted reports

### RAG Architecture

```
GitHub Repo (8k+ reports) → Parser → Normalized Schema → OpenAI Embeddings → Supabase pgvector
                                                                                    ↓
                                              MCP Server ← /mcp/rag_search ← Triage Agent
                                                     ↓
                                          agentic_runner.py (auto-inject context)
```

### RAG Setup

#### 1. Clone the reports repository

```bash
git clone https://github.com/marcotuliocnd/bugbounty-disclosed-reports.git
```

#### 2. Set up Supabase

1. Create a free Supabase project at https://supabase.com
2. Go to the SQL Editor and run the schema from `tools/rag_setup_supabase.sql`
3. This creates the `vuln_reports` table with pgvector extension and HNSW index

#### 3. Configure environment variables

```bash
export SUPABASE_URL="https://your-project.supabase.co"
export SUPABASE_KEY="your-supabase-anon-or-service-key"
export OPENAI_API_KEY="sk-..."  # Already required for triage
```

#### 4. Install RAG dependencies

```bash
pip install supabase tiktoken
```

#### 5. Run the ingestion (one-time, ~8k reports)

```bash
# Dry run to see what will be processed
python tools/rag_ingest.py ingest \
    --reports-dir ./bugbounty-disclosed-reports/reports \
    --dry-run

# Full ingestion (takes ~30-60 minutes)
python tools/rag_ingest.py ingest \
    --reports-dir ./bugbounty-disclosed-reports/reports

# Verify ingestion
python tools/rag_ingest.py verify
```

The ingestion is resumable - progress is saved to `rag_ingest_progress.json`.

#### 6. Test the RAG search

```bash
# Search for similar vulnerabilities
python tools/rag_client.py search "SSRF in image upload endpoint"

# Search by vulnerability type
python tools/rag_client.py by-type xss

# Search by technology
python tools/rag_client.py by-tech graphql nodejs

# View database statistics
python tools/rag_client.py stats
```

### RAG MCP Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /mcp/rag_search` | Semantic search for similar vulnerabilities |
| `POST /mcp/rag_similar_vulns` | Find similar vulns for a scanner finding + get LLM context |
| `GET /mcp/rag_stats` | Get knowledge base statistics |
| `POST /mcp/rag_search_by_type` | Search by vulnerability type (xss, ssrf, etc.) |
| `POST /mcp/rag_search_by_tech` | Search by technology stack |

### RAG Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `RAG_ENABLED` | `true` | Enable/disable RAG context injection |
| `RAG_MAX_EXAMPLES` | `3` | Max historical examples to inject per finding |
| `SUPABASE_URL` | - | Supabase project URL |
| `SUPABASE_KEY` | - | Supabase API key |

### How RAG Improves Triage

When RAG is enabled, the triage flow automatically:

1. Extracts key indicators from each finding (title, CWE, tags)
2. Queries the knowledge base for similar historical reports
3. Injects the top 3 matches into the LLM prompt as context
4. The LLM uses this context to improve:
   - CVSS scoring based on historical precedent
   - Impact descriptions from accepted reports
   - Bounty estimation from similar payouts
   - Payload suggestions that have worked before

---

## ☁️ Distributed Infrastructure (AWS/Kubernetes)

For production workloads, scan tools can run on-demand in AWS using Kubernetes with KEDA (Kubernetes Event-Driven Autoscaling). This enables **scale-to-zero** — you only pay for compute when jobs are running.

```
MCP Server → SQS Queue → EKS/KEDA → Worker Pods (scale 0→N) → S3 Results
```

**Key Benefits:**
- **Cost efficient**: Pods scale to zero when idle ($0/hour when not scanning)
- **Auto-scaling**: KEDA automatically spins up workers based on queue depth
- **Parallel execution**: Run 10+ scans concurrently
- **Isolated**: Each scan runs in a fresh container

**Quick Start:**
```bash
# Enable distributed mode
export DISTRIBUTED_MODE=true
export SQS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/xxx/scan-jobs
export S3_BUCKET=my-scan-results

# Same API - jobs now go to AWS workers
curl -X POST http://localhost:8000/mcp/run_whatweb \
  -d '{"target": "http://example.com"}'
```

📖 **Full setup guide:** [Distributed Infrastructure Guide](docs/DISTRIBUTED_INFRASTRUCTURE.md)

---

## 🚀 Roadmap

### ✅ Phase 1 — Core Automation (In Progress)
- [x] ZAP scanning via MCP endpoints  
- [x] Dedupe + low-value filter  
- [x] Pre-LLM CVSS gating  
- [x] Dalfox validator integration  
- [x] Markdown reporting  

### ⚙️ Phase 2 — Authenticated & Deep Scanning
- [ ] ZAP context-based authenticated scans  
- [ ] Forced user mode & session management  
- [ ] Custom test accounts per program  
- [ ] Cookie/session isolation between jobs  

### ☁️ Phase 3 — Scaling & Agentic Cluster
- [x] Containerized workers per scan (Docker/Kubernetes) — [See Distributed Infrastructure Guide](docs/DISTRIBUTED_INFRASTRUCTURE.md)
- [x] AI agent to fetch live bounty scopes (HackerOne/BBP)  
- [x] Job queue (SQS) dispatch to workers — [See Distributed Infrastructure Guide](docs/DISTRIBUTED_INFRASTRUCTURE.md)
- [x] Centralized results dashboard + S3 artifact storage  

### 🧠 Phase 4 — Autonomous Analyst
- [x] RAG-based training on previous findings for pattern recognition  
- [x] Secondary validation across other tools (Nuclei, sqlmap, etc.)  
- [ ] Self-tuning prompts for improved accuracy per bug class  

---

## 📦 Example Workflow

This section walks through a full run against a single target: from scope setup, through scanning and recon, to LLM triage and final reports.

### 1. Environment setup

```bash
# (Optional) activate virtualenv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

Configure any external tools (ZAP, ffuf, sqlmap, nuclei, interactsh-client) in your `$PATH` or via environment variables such as `ZAP_API_BASE`, `ZAP_API_KEY`, `INTERACTSH_CLIENT`, `OUTPUT_DIR`.

### 2. Define program scope

Create a `scope.json` with your program details:

```bash
cat > scope.json << 'EOF'
{
	"program_name": "demo-program",
	"primary_targets": [
		"https://app.example.com",
		"https://api.example.com"
	],
	"secondary_targets": [],
	"rules": {}
}
EOF
```

### 3. Start the MCP server

Run the FastAPI MCP server that exposes all `/mcp/*` endpoints (ZAP, nuclei, recon, validation, reporting):

```bash
python mcp_zap_server.py
```

By default this listens on `http://127.0.0.1:8000`. You can interact with it via `curl`, `HTTPie`, or an agent.

### 4. Load scope into MCP

Send `scope.json` to the server:

```bash
curl -s \
	-X POST http://127.0.0.1:8000/mcp/set_scope \
	-H 'Content-Type: application/json' \
	--data-binary @scope.json | jq .
```

You should see a response like:

```json
{ "status": "ok", "program": "demo-program" }
```

### 5. Kick off ZAP scanning

Start a ZAP spider + active scan for your in-scope hosts:

```bash
curl -s \
	-X POST http://127.0.0.1:8000/mcp/start_zap_scan \
	-H 'Content-Type: application/json' \
	-d '{"targets": ["https://app.example.com", "https://api.example.com"]}' | jq .
```

This returns an internal `our_scan_id` you can later correlate with alerts and reports.

### 6. Optional: configure auth headers

If you have authenticated areas, configure per-host auth headers so ZAP uses them:

```bash
curl -s \
	-X POST http://127.0.0.1:8000/mcp/set_auth \
	-H 'Content-Type: application/json' \
	-d '{
				"host": "app.example.com",
				"type": "header",
				"headers": {"Authorization": "Bearer YOUR_TOKEN"}
			}' | jq .
```

Then run an authenticated scan:

```bash
curl -s \
	-X POST http://127.0.0.1:8000/mcp/start_auth_scan \
	-H 'Content-Type: application/json' \
	-d '{"targets": ["https://app.example.com"]}' | jq .
```

### 7. Run nuclei recon and store findings

Use the curated recon template pack to collect high-signal fingerprints and exposures.

> Note: This project does **not** ship any nuclei templates. The
> `NUCLEI_RECON_TEMPLATES` list in `mcp_zap_server.py` is built from a
> small set of relative paths and an optional `NUCLEI_TEMPLATES_DIR`
> environment variable. If `NUCLEI_TEMPLATES_DIR` is set (for example to
> `$HOME/nuclei-templates`), each relative entry like `http/exposed-panels/`
> is resolved under that directory. Otherwise the relative paths are
> passed through as-is and nuclei will resolve them according to its own
> search rules.

```bash
curl -s \
	-X POST http://127.0.0.1:8000/mcp/run_nuclei \
	-H 'Content-Type: application/json' \
	-d '{
				"target": "https://api.example.com",
				"mode": "recon"
			}' | jq .
```

This writes nuclei JSONL output into `OUTPUT_DIR` (default `./output_zap`) for later aggregation.

### 8. Build a host profile for LLM planning

Ask the MCP server to aggregate everything it knows about a host (ZAP URLs, nuclei recon, auth surface, parameters):

```bash
curl -s \
	-X POST http://127.0.0.1:8000/mcp/host_profile \
	-H 'Content-Type: application/json' \
	-d '{"host": "https://api.example.com", "llm_view": true}' | jq .
```

The response contains a compact `llm_profile` designed to be cheap to send to the LLM for planning which endpoints and issues to focus on next.

### 9. Validate a specific PoC with nuclei

Once your agent/LLM proposes a PoC using a particular nuclei template, you can validate it:

```bash
curl -s \
	-X POST http://127.0.0.1:8000/mcp/validate_poc_with_nuclei \
	-H 'Content-Type: application/json' \
	-d '{
				"target": "https://api.example.com/api/v1/users?id=123",
				"templates": ["http/pocs/xss.yaml"]
			}' | jq .
```

The response includes:

- `validated`: `true`/`false`
- `match_count`: number of findings
- `findings`: raw nuclei findings
- `summaries`: PoC-oriented summaries the LLM can interpret

### 10. Export final triage reports

After ZAP scanning and any additional tooling, consolidate findings into HackerOne-style Markdown reports. First ensure ZAP findings were exported into `output_zap/zap_findings_<scan_id>.json` (typically done by your poller or pipeline). Then:

```bash
curl -s \
	-X GET http://127.0.0.1:8000/mcp/export_report/<scan_id> | jq .
```

This creates:

- An index file: `output_zap/<scan_id>_reports_index.json`
- One Markdown report per finding: `output_zap/<scan_id>_<finding_id>.md`

Each report is ready to be reviewed by a human triager or attached directly to a bug bounty submission.

---

## 💡 Design Philosophy

> **"Automate first, analyze smart, scale later."**

- Each module can run standalone or in a distributed job system.
- AI is treated as an *augmenter*, not a replacement — it interprets scanner data, not raw scan traffic.
- Costs scale linearly with signal, not noise.
- Designed for **real-world bug bounty programs**, not lab benchmarks.

---

## 🧰 Tech Stack

| Component | Tool |
|------------|------|
| Orchestrator | Python 3.11 |
| Scanners | OWASP ZAP, ffuf, Dalfox, Nuclei, Katana |
| Validator | Dalfox (XSS), sqlmap (SQLi), BAC/SSRF checks |
| AI Engine | OpenAI GPT-4o (triage & summarization) |
| Scope Import | HackerOne GraphQL API + page scraping |
| Knowledge Base | Supabase pgvector (RAG) |
| Message Queue | Planned: Redis/Kafka |
| Cluster Runtime | Planned: Docker / Kubernetes |
| Artifact Storage | Local → S3 (planned) |

---

## 📈 Scaling Vision

Once containerized, each node will:
- Pull new in-scope targets from the queue.
- Run scanning and triage autonomously.
- Push findings to a central data lake.
- Learn from prior results (RAG-style context retrieval) to improve detection over time.

Long-term goal:  
**A self-directed, auto-scaling vulnerability intelligence engine that operates across multiple bug bounty platforms.**

---

## 👷‍♂️ Development Status

**Current phase:** P0 Implementation  
**Focus:** Reliable core, noise reduction, token efficiency, validated results.  
**Next Up:** Authenticated ZAP scanning and distributed job orchestration.

---

## 🐳 Run the stack in Docker (easy path)

The simplest way to run the MCP server + ZAP together is via `docker-compose`. This gives you:

- A ZAP daemon container listening on `8080`.
- An MCP API container (FastAPI) listening on `8000`.
- A shared `./output_zap` volume for findings & triage artifacts.

### 1. Prerequisites

- Docker and docker-compose installed.
- An `OPENAI_API_KEY` in your environment (used by `agentic_runner.py` for triage).

### 2. Build and start the services

From the `agentic-bugbounty` directory:

```bash
docker compose up --build
```

This starts:

- `zap` at `http://localhost:8080` (inside the Docker network as `http://zap:8080`).
- `mcp` at `http://localhost:8000`.

You can verify MCP is up via:

```bash
curl -s http://localhost:8000/docs >/dev/null && echo "MCP is up"
```

### 3. Provide a scope file

Create a `scope.json` in the same directory as `agentic_runner.py` with an explicit `in_scope` list, for example:

```json
{
	"program_name": "demo-program",
	"primary_targets": ["app.example.com"],
	"secondary_targets": [],
	"in_scope": [
		{ "url": "https://app.example.com" }
	],
	"rules": {}
}
```

### 4. Run a full scan + triage from your host

With MCP + ZAP running in Docker, you can orchestrate scans from your host using `agentic_runner.py`:

```bash
cd agentic-bugbounty

export OPENAI_API_KEY="sk-..."          # required for triage
export MCP_SERVER_URL="http://localhost:8000"

python agentic_runner.py --mode full-scan --scope_file scope.json
```

What this does:

- Calls `/mcp/set_scope` with your `scope.json`.
- Starts ZAP scans for each `in_scope` URL.
- (Best-effort) runs nuclei recon and lightweight cloud recon.
- Builds `host_profile`, `prioritize_host`, and `host_delta` per host.
- Writes a run summary to `output_zap/program_run_<ts>.json`.
- Auto-triages any `zap_findings_*.json` and `cloud_findings_*.json` into:
	- `output_zap/triage_*.json` (structured triage)
	- `output_zap/*__<title>.md` (Markdown reports).

### 5. Inspecting results

On your host machine:

```bash
ls -1 output_zap

# Example: inspect triaged findings
jq '.[] | {title, cvss_score, confidence, recommended_bounty_usd}' \
	output_zap/triage_*.json | less
```

You can also open the Markdown reports in your editor or browser; they are designed to be close to ready-to-submit bug bounty writeups.

---

## 🏁 Credits

Built by security engineer **Mike Wolf** — blending automation, applied AI, and offensive security research.

> “Finding bugs is an art; scaling it is engineering.”

---

## 📜 License
MIT License © 2025 Mike Wolf  
See [LICENSE](LICENSE) for details.
