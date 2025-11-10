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

```bash
# Activate environment
source .venv/bin/activate

# Define scope
cat scope.json
# ["https://you.23andme.com", "https://api.23andme.com", ...]

# Run a scope scan
python scope_runner.py --scope scope.json

# Triaging the results
export OPENAI_API_KEY="sk-..."
export DALFOX_BIN="$(which dalfox)"
export MIN_PRE_CVSS=6.0
export KEEP_NOISE=0
python agentic_from_file.py --findings_file output_zap/test_findings.json --scope_file scope.json
```

Results:
- Filtered triage JSON → `output_zap/triage_<scan_id>.json`
- Markdown reports → `output_zap/<scan_id>__Finding_Title.md`

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
