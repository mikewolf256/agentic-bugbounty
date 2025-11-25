# 🧠 Agentic Bug Bounty System
### Automated, Intelligent, and Scalable Vulnerability Research Framework

> **Mission:** Build an autonomous bug bounty reconnaissance and triage engine that uses AI, automation, and scalable containers to identify and validate impactful vulnerabilities — without wasting tokens or human time.

---

## 🌐 Overview

**Agentic Bug Bounty** is a modular framework for automated, AI-assisted security testing across public bug bounty programs.  
It combines traditional scanners (ZAP, ffuf, Dalfox, etc.) with an LLM-based triage pipeline that filters, analyzes, and summarizes findings into clean, human-ready vulnerability reports.

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
│ MCP (Modular Control Plane)    → Orchestrates scans (ZAP) │
│ ZAP Spider / Active Scan       → Collects findings        │
│ Dedupe & Noise Filter          → Drops low-value alerts   │
│ AI Triage (OpenAI / GPT-4o)    → Summarizes & scores CVSS │
│ Dalfox Validator               → Confirms XSS findings    │
│ Markdown Report Generator      → Produces human reports   │
└───────────────────────────────────────────────────────────┘
```

**Data Flow:**
1. **Scope ingestion:** A `scope.json` defines targets & rules.  
2. **Scanning:** ZAP or other tools crawl each target and export findings.  
3. **Pre-processing:** `mcp_helpers/dedupe.py` removes noise and deduplicates results.  
4. **AI triage:** Only meaningful findings are passed to the LLM for contextual scoring, impact, and bounty estimation.  
5. **Validation:** Tools like **Dalfox** re-check XSS findings to confirm proof.  
6. **Reporting:** Results are written as structured JSON + Markdown vulnerability reports.

---

## ⚙️ Key Features

| Feature | Description |
|----------|--------------|
| **Smart Pre-Filter** | Removes redundant and low-value scanner noise before AI triage — saving up to 90% token cost. |
| **CVSS & Focus Filtering** | Keeps only findings with estimated CVSS ≥ 6.0 or high-impact keywords (XSS, SQLi, SSRF, Auth Bypass…). |
| **Dalfox Validation** | Runs automatic confirmation of reflected XSS vectors via the Dalfox engine. |
| **Evidence Stubbing** | Always writes artifacts, even on “0 issue” scans, for full traceability. |
| **AI-Based Triage** | Summarizes findings, assigns CVSS vectors, and estimates bounty value. |
| **Modular Control Plane (MCP)** | Provides API endpoints to start scans, triage, or check scope compliance. |
| **Token-Efficient Design** | Filters findings *before* LLM inference to cut costs and scale affordably. |

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
- [ ] Containerized workers per scan (Docker/Kubernetes)  
- [ ] AI agent to fetch live bounty scopes (HackerOne/BBP)  
- [ ] Job queue (Redis/Kafka) dispatch to workers  
- [ ] Centralized results dashboard + S3 artifact storage  

### 🧠 Phase 4 — Autonomous Analyst
- [ ] RAG-based training on previous findings for pattern recognition  
- [ ] Secondary validation across other tools (Nuclei, sqlmap, etc.)  
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

Use the curated recon template pack to collect high-signal fingerprints and exposures:

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
| Scanners | OWASP ZAP, ffuf, Dalfox |
| Validator | Dalfox (XSS), future: Nuclei, sqlmap |
| AI Engine | OpenAI GPT-4o (triage & summarization) |
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

## 🏁 Credits

Built by security engineer **Mike Wolf** — blending automation, applied AI, and offensive security research.

> “Finding bugs is an art; scaling it is engineering.”

---

## 📜 License
MIT License © 2025 Mike Wolf  
See [LICENSE](LICENSE) for details.
