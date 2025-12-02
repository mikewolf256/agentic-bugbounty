# P0 Bug Bounty & Red-Team Roadmap

This roadmap tracks planned capabilities for the current P0 program across seven core bug bounty focus areas, plus red-team and platform features.

---

## Now / Next / Later (Unified View)

- **Now – P0: Core Findings + Evidence Automation**
  - Core MCP + runner pipeline, host profiling, and host deltas implemented and tested (`P0.0`).
  - ZAP scanning orchestration via MCP, multi-host scan orchestration, and host history.
  - Dedupe + pre-filtering of findings (skip noisy/low-CVSS issues) before LLM triage.
  - XSS + Dalfox behavior tightened to XSS-only, medium+ confidence with clean triage/Markdown (`P0.1`).
  - SQLi validation wired via `/mcp/run_sqlmap` and triage + Markdown integration (`P0.2`).
  - BAC v1 (`/mcp/run_bac_checks` + config + basic vertical/IDOR checks) and SSRF v1 (`/mcp/run_ssrf_checks`) enriched with engine metadata in triage and Markdown (`P0.3`, `P0.4`).
  - Katana + Nuclei web recon wired via MCP `/mcp/run_katana_nuclei` and helper script (`P0.0`, `P0.1`, `P0.2`).
  - JS miner for endpoints/keys (MCP `/mcp/run_js_miner` + background job) and reflection detector for XSS candidates.
  - Backup hunter (HTTP-based, via `/mcp/run_backup_hunt`) for common backup/config file exposures, with hits surfaced in `host_profile.web.backups`.
  - Artifact hygiene + structured outputs (triage JSONs, Markdown reports, `program_run_*.json`).
- **Next – P1: Authenticated Testing + High-ROI Expansions**
  - ZAP Auth Context + API tokens for authenticated spidering and scanning.
  - ffuf/sqlmap authenticated mode (reuse auth contexts, session cookies, or tokens).
  - Deeper business logic checks (IDOR, BOLA, mass assignment) building on BAC v1.
  - Nuclei curated recon/attack template sets for high-signal coverage.
  - Interactsh (or equivalent) for OOB payloads and SSRF/callback correlation.
  - Secrets detection + redaction pipeline (beyond basic regex/entropy checks).
- **Later – P2–P5: Intelligence, Scale, Red-Team, Platform**
  - **P2 – Intelligence + RAG memory:** vector DB of past findings, pattern recognition on repeats, RAG-assisted second-stage scanning, and LLM-assisted payload mutation.
  - **P3 – Distributed worker cluster:** Redis/Kafka work queue, K8s worker pods with autoscaling, job templates for ZAP/ffuf/sqlmap/nuclei, and per-scan isolation.
  - **P4 – Red team / ASM mode:** Wayback machine URI mining, JS/source-map harvesting, technology fingerprinting, attack-path graph building, MITRE ATT&CK JSON export, and red-team report templates.
  - **P5 – Commercial features:** tenant onboarding, one-click scanning portal, automated evidence-to-report pipeline (PDF/MD), billing and usage metering.

---

## P0.0 – Core Pipeline (P0 – Done / Ongoing Polish)

- **MCP + Runner foundation**
  - [x] FastAPI MCP server in `mcp_zap_server.py` with core integration.
  - [x] `agentic_runner.py` with `full-scan` and `triage` modes.
  - [x] Host profiling, prioritization, and `/mcp/host_delta` endpoint with per-host snapshot history under `OUTPUT_DIR/host_history/`.
- **Containerization**
  - [x] `Dockerfile.mcp` for MCP server.
  - [x] `docker-compose.yml` for MCP + supporting services.
- **Cloud recon + basic secrets**
  - [x] `/mcp/run_cloud_recon` endpoint and `cloud_findings_*.json` outputs.
  - [x] LLM triage for cloud findings with simple secret/PII regex checks.
- **Web recon foundation**
  - [x] Introduce Katana + Nuclei helper: `tools/katana_nuclei_recon.py`.
  - [x] Add `/mcp/run_katana_nuclei` endpoint to orchestrate Katana + Nuclei and emit JSON findings.
  - [x] Wire Katana+Nuclei findings into `full-scan` flow and unified triage automatically (basic integration).

---

## P0.1 – XSS (Reflected, Stored, DOM) – P0

- **Discovery**
  - [ ] Extend `host_profile` to track:
    - [ ] Reflected parameters and HTML injection points.
    - [ ] JS/DOM risk indicators (inline event handlers, dangerous sinks).
  - [ ] Tune ZAP policies / scan configs for XSS-heavy coverage.
**Validation (Dalfox)**
  - [x] Tighten Dalfox integration in `agentic_runner.py`:
    - [x] Only run Dalfox when LLM or other modules classify a finding as XSS-like and confidence is medium+.
    - [x] Add `validation_engine` and `validation_confidence` fields to triage.
    - [ ] Cache Dalfox results per URL + param + payload.
  - [x] Skip Dalfox for cloud-only findings and hide Dalfox section in XSS-irrelevant markdown.
**Triage & Reporting**
  - [x] Update triage prompt to classify:
    - [x] XSS type (reflected, stored, DOM).
    - [x] Context (attribute, body, JS).
  - [x] Standard XSS report template (v1):
    - [x] Reproduction steps with payload and automated Dalfox evidence when available.
    - [x] Impact narrative for XSS in the generic template.
    - [x] Remediation guidance (output encoding, CSP, input validation) via existing helper.
- **Profiles / Modes**
  - [ ] Add `--profile xss-heavy` mode in `agentic_runner.py` focusing on:
    - [ ] Heavier XSS checks and Dalfox validation.
    - [ ] UI-heavy hosts or paths from scope.

---

## P0.2 – SQL Injection (SQLi) – P0

- **Discovery**
  - [ ] Enhance recon to flag endpoints with:
    - [ ] DB-like error messages and stack traces.
    - [ ] Numeric or identifier-style parameters (`id`, `user_id`, etc.).
- **Validation (sqlmap)**
  - [x] Implement `/mcp/run_sqlmap` endpoint:
    - [x] Accept URL and optional data/headers.
    - [x] Run `sqlmap` with safe defaults and timeouts.
    - [x] Write `sqlmap_<host>_<ts>` output directory under `OUTPUT_DIR/`.
  - [x] Wire `agentic_runner.py` triage to:
    - [x] Trigger `/mcp/run_sqlmap` for suspected SQLi findings (medium+ confidence, SQLi-like).
    - [x] Parse results into `dbms`, `vulnerable_params`, `dumped_data_summary` and surface them in triage/Markdown (`SQLmap Validation Details`).
- **Triage & Reporting**
  - [x] SQLi-specific reporting improvements (v1):
    - [x] DBMS and vulnerable parameter summary in validation metadata.
    - [x] SQLmap validation section in Markdown showing engine result, DBMS, vulnerable params, and dump summary when present.
    - [ ] Optional future: deeper SQLi triage prompt describing exploitation method and data access impact.
- **Profiles / Modes**
  - [ ] Add `--profile sqli-heavy` focused on identifier parameters and search endpoints.

---

## P0.3 – Broken Access Control (BAC) – P0/P1

- **Discovery**
  - [ ] Extend `host_profile` to capture:
    - [ ] Candidate admin or internal endpoints (`/admin`, `/internal`, etc.).
    - [ ] Object/tenant identifiers (project IDs, org IDs).
  - [ ] Define `access_model.yaml` (or similar) to describe:
    - [ ] Roles (user, admin, support, etc.).
    - [ ] Sample credentials or tokens.
- **Validation**
  - [x] Implement `/mcp/run_bac_checks` endpoint (v1):
    - [x] Enforce scope on host and accept optional URL.
    - [x] Load per-host `bac_config_<host>.json` with roles and checks.
    - [x] Run basic vertical access and IDOR-style checks and write `bac_findings_<host>_<ts>.json`.
  - [ ] Add full BAC logic:
    - [ ] Richer IDOR checks across resources/tenants.
    - [ ] Vertical auth checks: low-priv tokens on admin endpoints with deeper semantics.
    - [ ] Horizontal auth checks across accounts.
    - [ ] Detailed, typed BAC results for reporting.
- **Triage & Reporting**
  - [ ] Triage prompt tuned for:
    - [ ] Expected vs actual access level.
    - [ ] Tenant boundary and privilege escalation.
  - [ ] Markdown template:
    - [ ] Role used and target resource.
    - [ ] Proof of unauthorized access.
    - [ ] Impact narrative (data exposure, takeover).
- **Profiles / Modes**
  - [ ] `--profile bac-heavy` consuming `access_model.yaml` and running dedicated BAC checks.

---

## P0.4 – SSRF – P0/P1

- **Discovery**
  - [ ] Recon enhancements to identify SSRF candidates:
    - [ ] Parameters like `url`, `callback`, `redirect`, `target`.
    - [ ] Import-by-URL features and webhooks.
  - [x] Add config for callback server:
    - [x] `SSRF_CALLBACK_URL` env var.
- **Validation**
  - [x] Implement `/mcp/run_ssrf_checks` endpoint:
    - [x] Send best-effort payloads with callback URLs for a given `target` + `param`.
    - [x] Store `ssrf_findings_<host>_<ts>.json` with `payloads_sent` for later correlation.
  - [ ] Add real callback correlation (logs/DNS/webhook) and `validated: true` semantics.
- **Triage & Reporting**
  - [ ] Triage classification:
    - [ ] SSRF type (blind, direct, semi-blind).
    - [ ] Reachability (internal IPs, metadata endpoints, arbitrary URLs).
  - [ ] Markdown template:
    - [ ] Exact request and evidence of callback.
    - [ ] Potential escalation (cloud metadata, internal panels).
- **Profiles / Modes**
  - [ ] `--profile ssrf-heavy` prioritizing SSRF candidates and callback monitoring.

---

## P0.5 – Secrets, Sensitive Data & Info Disclosure – P0/P1

- **Discovery**
  - [ ] Extend cloud/secret scanners to:
    - [ ] Use richer regex + entropy rules for API keys, tokens, credentials.
    - [ ] Crawl JS and static assets for embedded secrets.
    - [ ] Sample large responses intelligently to avoid over-scan.
- **Validation**
  - [ ] For each potential secret:
    - [ ] Classify type (API key, JWT, DB URI, credential).
    - [ ] Perform non-destructive checks (e.g., JWT decode, format validation).
- **Triage & Reporting**
  - [ ] Enhance triage to:
    - [ ] Assess exploitability and blast radius for each secret.
    - [ ] Group duplicate occurrences of the same secret.
  - [ ] Markdown sections:
    - [ ] Sanitized sample (masked token).
    - [ ] Exact location (endpoint/path/file).
    - [ ] Abuse scenarios and remediation.
- **Profiles / Modes**
  - [ ] `--profile secrets-heavy` favoring asset crawling and secret scans.

---

## P0.6 – Misconfig & Cloud Storage Surface – P1

- **Discovery**
  - [ ] Build out cloud storage recon:
    - [ ] Normalize buckets/containers across AWS/GCP/Azure.
    - [ ] Probe permissions (read/list/write) safely.
  - [ ] Add web misconfig checks:
    - [ ] CSP presence/strength.
    - [ ] Cookie flags (Secure, HttpOnly, SameSite).
    - [ ] CORS configuration (wildcards, overly permissive origins).
- **Validation**
  - [ ] For storage:
    - [ ] Attempt non-destructive read/list operations.
  - [ ] For CSP/CORS/cookies:
    - [ ] Correlate with XSS/CSRF likelihood and other findings.
- **Triage & Reporting**
  - [ ] Cloud storage report template:
    - [ ] Bucket/container name and permissions.
    - [ ] Listing evidence where applicable.
  - [ ] Misconfig report template for CSP/CORS/cookies:
    - [ ] Policy summary.
    - [ ] Risks in context of the application.
- **Profiles / Modes**
  - [ ] `--profile cloud-heavy` focusing on cloud + misconfig modules.

---

## P0.7 – Outdated Components & Dependency Issues – P2/P4

- **Discovery**
  - [ ] Implement `/mcp/run_component_scan` endpoint:
    - [ ] Passive fingerprinting from headers, HTML, and JS (version strings).
    - [ ] Optional integration with `nuclei` templates for version disclosure and known vulns.
  - [ ] Track third-party platforms (WordPress, Jenkins, Jira, etc.) in `host_profile`.
- **Validation**
  - [ ] For each component/version:
    - [ ] Lookup associated CVEs (local DB or API).
    - [ ] Classify severity and exploitability.
- **Triage & Reporting**
  - [ ] Standardize component findings into:
    - [ ] Product, version (confirmed vs guessed).
    - [ ] CVE list with short descriptions.
    - [ ] Recommended upgrade paths.
- **Profiles / Modes**
  - [ ] `--profile component-heavy` emphasizing passive fingerprinting and nuclei templates.

---

## P0.8 – Cross-Cutting: Orchestration, UX, and Testing – P0/P2

- **Orchestration & Telemetry**
  - [ ] Extend `program_run_<ts>.json` to record:
    - [ ] Modules/profiles executed.
    - [ ] Per-step runtime, errors, and status.
  - [ ] Define scan orders per profile (recon → validators → triage).
- **Unified MCP API Surface**
  - [ ] Ensure each module has:
    - [ ] `/mcp/run_<module>` endpoint with clear request/response schema.
    - [ ] Documentation in `README.md` or a dedicated API doc.
- **Triage Schema & Templates**
  - [ ] Standardize triage JSON:
    - [x] Add static MITRE mapping (`mitre` field) for common bug classes (XSS, SQLi, BAC, SSRF, etc.).
    - [x] Normalize `validation.*` blocks for Dalfox (and initial SQLi/SSRF) with consistent keys.
    - [x] Add top-level `validation_status` + `validation_engine` per finding, plus per-engine summaries.
  - [ ] Move Markdown rendering to templates under `templates/` for reuse.
- **Testing & CI**
  - [ ] Add tests per module (unit + small integration tests with mocked targets).
  - [ ] Provide a `make` or `task` target to:
    - [ ] Run a minimal sample scan.
    - [ ] Generate example reports for each major category.

---

### P4.1 – MITRE ATT&CK Mapping Engine

- **MITRE ATT&CK Mapping**
  - [ ] Implement LLM-based MITRE mapping for each triaged finding.
  - [x] Create static mapping rules for common bug classes (XSS, SQLi, BAC, SSRF, etc.).
  - [x] Add `"mitre"` field to the unified triage JSON schema (techniques, tactics, confidence).
  - [ ] Store MITRE tags and artifacts under `artifacts/mitre/` (per program/run).
  - [ ] Integrate MITRE tags with RAG-style memory so past ATT&CK coverage influences future scans.

### P4.2 – ATT&CK Navigator Export

- **Navigator Export & Visualization**
  - [ ] Create `export_mitre_navigator.py` utility.
  - [ ] Generate valid ATT&CK Navigator JSON from `program_run_<ts>.json` + `artifacts/mitre/`.
  - [ ] Color-code techniques by severity and validation status.
  - [ ] Add evidence links (Markdown reports, raw artifacts) in technique comments.
  - [ ] Implement `/mcp/export_mitre` endpoint to trigger Navigator export via MCP.

### P4.3 – Executive Red-Team PDF Report

- **Executive Reporting**
  - [ ] Build HTML → PDF report pipeline (e.g., WeasyPrint or wkhtmltopdf).
  - [ ] Write Jinja2 template for an executive red-team report (exec summary, tech details, mitigation roadmap).
  - [ ] Add MITRE matrix visualization to the PDF (from Navigator JSON or direct mapping).
  - [ ] Add finding impact scoring summary by category and severity.
  - [ ] Implement `/mcp/export_redteam_report` API endpoint.

### P4.5 – Red-Team Simulation Mode

- **Chaining & Simulation**
  - [ ] Add vulnerability chaining logic that combines multiple confirmed/likely findings into multi-step kill chains.
  - [ ] Add role-diff privilege escalation tester (auth required), building on `/mcp/run_bac_checks` and `access_model.yaml`.
  - [ ] Add JWT-scope analyzer to parse tokens, scopes/claims, and detect over-privileged access.
- **Attack Graphs & High-Value Paths**
  - [ ] Add attack graph generator that produces JSON graphs of assets, vulnerabilities, and attack paths.
  - [ ] Add “high-value-path” scoring system (likelihood of kill chain + business impact).
  - [ ] Surface attack graphs and path scores in exec reports and MITRE Navigator exports.

---

## P0.9 – Continuous ASM & Multi-Tenancy – P4/P5

- **Scheduling & Automation**
  - [ ] Add scheduler for recurring scans (daily/weekly) with persisted job configs.
  - [ ] Support profiles per job (e.g., `xss-heavy`, `sqli-heavy`, `cloud-heavy`).
- **Notifications & Alerting**
  - [ ] Add Slack/Email/Teams alerting for new critical findings or host deltas.
  - [ ] Support per-tenant notification channels.
- **Multi-Tenant Support**
  - [ ] Add workspace/program separation (per-client directories and configs).
  - [ ] Enforce isolation in storage (`output_zap`, `artifacts/`, logs).
- **Cost & Token Monitoring**
  - [ ] Add global token-usage monitor with per-tenant budgets.
  - [ ] Configure alerts when thresholds are exceeded.
- **Client Portal (Future UI)**
  - [ ] Prototype a “client portal” UX (even as static-generated HTML) to browse findings, reports, and MITRE coverage.
