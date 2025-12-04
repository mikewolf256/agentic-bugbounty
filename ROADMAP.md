# Agentic Bug Bounty – Updated Roadmap (with Authenticated Katana Session Support)

## P0 – Core Pipeline Foundations
- [x] Project Scaffolding & Repo Structure
- [x] Core MCP endpoints (run_scan, fetch_scope, nuclei_scan, zap_scan)
- [x] Kubernetes Worker Model & Container Templates
- [x] Global Config Management (scopes.json, endpoints.json)
- [x] Local + K8s Execution Modes
- [x] Scan Orchestration Controller
- [x] Artifact Output Folder Standardization
- [x] Local K8s cluster setup (kind + Redis) - [See Local K8s Setup Guide](docs/LOCAL_K8S_SETUP.md)

---

## P1 – High Priority Features (Critical to MVP)

### **P1.1 – Recon & Crawling Layer**
- [x] Katana unauthenticated crawling integration
- [x] Katana + JS Miner for endpoint extraction
- [x] WaybackURL ingestion
- [x] Param mine baseline
- [ ] Basic fingerprinting (technologies, frameworks)
- [ ] Add WhatWeb/Similar tech-fingerprinter fallback

---

### **P1.2 – NEW: Authenticated Recon via Katana Active Browser Session (Added)**
**Purpose:** Unlock full authenticated surface mapping using live Chrome session + DevTools WebSocket.

**Tasks:**
- [ ] MCP Endpoint: `/mcp/run_katana_auth`
- [ ] Output directory: `artifacts/katana_auth/<host>/`
- [ ] Chrome helper script (`--remote-debugging-port=9222`)
- [ ] Auto-extract authenticated session cookies
- [ ] Collect authenticated-only:
  - URLs
  - JS files
  - API endpoints (XHR/fetch)
  - GraphQL schemas
  - POST bodies
- [ ] Normalize results into unified recon DB
- [ ] Feed authenticated URLs → ffuf/sqlmap/dalfox/ZAP
- [ ] Tag resources in RAG knowledge store
- [ ] Integrate into reporting pipeline

---

### **P1.3 – Nuclei Layer**
- [x] Baseline nuclei scan integration
- [ ] Curated template bundle for highest-paying bug classes
- [ ] Add GraphQL templates
- [ ] Add authenticated-template support
- [ ] Severity post-processing

---

### **P1.4 – ZAP Integration**
- [ ] ZAP baseline passive scan
- [ ] Advanced script loader
- [ ] Scripted authenticated scans
- [ ] Normalize ZAP results

---

### **P1.5 – RAG Vulnerability Intelligence Pipeline**
- [x] Embedding model selection
- [ ] Unified schema:
  - vuln_type
  - attack_chain
  - endpoint
  - reproduction_steps
  - payload
  - impact
- [ ] H1 ingestion pipeline
- [ ] Fingerprinting correlations
- [ ] Suggest exploit chains
- [ ] Add SSRF, GraphQL, ReDoS, IDOR embeddings

---

## P2 – Medium Priority Features

### **P2.1 – Worker Clustering**
- [ ] Batch scheduler
- [ ] Priority queue
- [ ] Adaptive parallelism

### **P2.2 – Enhanced Fingerprinting**
- [ ] JS/tech-library detection
- [ ] Backend/framework inference
- [ ] Cloud-provider fingerprinting
- [ ] Favicon hash → tech inference

---

## P3 – Reporting & Export Layer
- [ ] Markdown report generator
- [ ] JSON export
- [ ] MITRE ATT&CK Navigator export
- [ ] Authenticated recon sections

---

## P4 – Long-term/Stretch Features

### **P4.1 – Fully Autonomous Red Team Mode**
- [ ] Search-based exploitation planner
- [ ] Multi-step attack simulations
- [ ] Auto-chain SSRF → metadata → takeover
- [ ] Attack path graph generator

### **P4.2 – Red Team Service Offering Mode**
- [ ] Client-ready deliverables
- [ ] MITRE mapping
- [ ] Executive report generation
- [ ] External API mode

---

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
- **AI-driven Nuclei template selection**
  - [x] Implement `tools/ai_nuclei_triage.py` - AI helper that analyzes host_profile and selects optimal templates.
  - [x] Add `/mcp/triage_nuclei_templates` endpoint for AI-driven template selection based on tech stack.
  - [x] Add `/mcp/run_targeted_nuclei` endpoint for running Nuclei with AI-selected templates.
  - [x] Wire AI triage into `full-scan` orchestration (after Katana+WhatWeb, before final triage).
  - [x] Template category mappings for 50+ technologies (WordPress, GraphQL, Spring, AWS, etc.).
  - [x] Attack surface analysis (API detection, auth endpoints, file upload, admin panels).
  - [x] Static fallback when LLM unavailable.

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

## P2.9 – Training & Lab Harness – P2/P3

- **Bug Taxonomy & RAG Index (P2)**
  - [ ] Collect and normalize a small corpus of public, high-quality bug bounty writeups and lab walkthroughs into a structured schema (bug_type, CWE, attack_surface, pattern, impact).
  - [ ] Build a vector index for these documents (e.g., Chroma/Weaviate) keyed by bug_type/CWE/surface for retrieval-augmented triage and report generation.
  - [ ] Wire triage to optionally pull 3–5 similar historical cases per finding (by CWE/bug_type) to improve payload suggestions, impact narratives, and remediation text.

- **Dockerized Labs as Eval Harness (P2/P3)**
  - [ ] Create a small set of dockerized vulnerable labs with `lab_metadata.json` describing expected bugs:
    - [ ] Reflected XSS (basic patterns: reflected query param, error-page reflection).
    - [ ] IDOR/BOLA-style broken access control on an API.
    - [ ] Backup/config/VCS exposure (e.g., `/.git/`, `/backup.zip`, `.env`).
    - [ ] JS hard-coded secrets/config endpoints.
    - [ ] SSRF endpoint with internal/metadata reachability.
  - [ ] Implement a `tools/lab_runner.py` (or similar) that:
    - [ ] Starts/stops a given lab (docker-compose).
    - [ ] Sets MCP scope to the lab host and runs the standard scan + triage pipeline.
    - [ ] Compares triaged findings to `expected_findings` and writes a compact JSON score (detected, report_quality, cvss_error).
  - [ ] Integrate lab runs into CI as a non-blocking "capability health" check for core bug classes.

- **Future Fine-Tuning (P3+)**
  - [ ] Once enough lab + real-world data exists, evaluate training a small, specialized model for `(scanner_output + traces + RAG snippets) → structured bug report JSON` while respecting platform TOS and data governance.

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
  - [ ] Prototype a "client portal" UX (even as static-generated HTML) to browse findings, reports, and MITRE coverage.

---

---

# NEW FEATURE PROPOSALS (Dec 2024)

## P1.6 – OAuth/OIDC Security Analyzer – P0/P1
**Rationale:** OAuth misconfigurations are consistently high-paying ($5K-$50K). Most automation tools ignore this complex attack surface.

- **Discovery**
  - [ ] Detect OAuth/OIDC endpoints (`/oauth/authorize`, `/token`, `/.well-known/openid-configuration`).
  - [ ] Extract and parse OAuth flows from JS (implicit, authorization code, PKCE).
  - [ ] Identify state parameter handling, redirect_uri validation patterns.
- **Validation**
  - [ ] `/mcp/run_oauth_checks` endpoint:
    - [ ] Open redirect via redirect_uri manipulation.
    - [ ] State parameter fixation/missing checks.
    - [ ] Token leakage via referrer header.
    - [ ] Scope escalation attempts.
    - [ ] PKCE downgrade attacks.
  - [ ] Account takeover chain detection (OAuth → session).
- **Triage & Reporting**
  - [ ] OAuth-specific impact narratives (ATO, data exfil).
  - [ ] Chain visualization (redirect → token steal → ATO).
- **Profiles / Modes**
  - [ ] `--profile oauth-heavy` for auth-focused programs.

---

## P1.7 – Race Condition / TOCTOU Detection – P0/P1
**Rationale:** Race conditions often yield critical bugs ($10K+) and are underexplored due to testing complexity.

- **Discovery**
  - [ ] Identify race-prone endpoints:
    - [ ] Financial transactions, balance updates, coupon redemption.
    - [ ] Account creation, invitation systems.
    - [ ] File operations, resource allocation.
  - [ ] Detect non-idempotent state changes in API responses.
- **Validation**
  - [ ] `/mcp/run_race_checks` endpoint:
    - [ ] Parallel request sender (configurable threads, timing).
    - [ ] Response diffing to detect race success.
    - [ ] Turbo Intruder-style single-packet attack support.
  - [ ] Track balance/count deltas as evidence.
- **Triage & Reporting**
  - [ ] Timing diagrams in reports.
  - [ ] Financial impact estimation.
- **Profiles / Modes**
  - [ ] `--profile race-heavy` for fintech/e-commerce targets.

---

## P1.8 – HTTP Request Smuggling Detection – P1
**Rationale:** Request smuggling = Critical severity, often $10K-$100K bounties. Requires specialized detection.

- **Discovery**
  - [ ] Detect smuggling-prone architectures (CDN + origin, load balancers).
  - [ ] Identify CL.TE, TE.CL, TE.TE variants via timing/response analysis.
- **Validation**
  - [ ] `/mcp/run_smuggling_checks` endpoint:
    - [ ] Safe timing-based detection (no cache poisoning).
    - [ ] Differential response analysis.
    - [ ] Header normalization fingerprinting.
  - [ ] Integration with smuggler.py or similar tools.
- **Triage & Reporting**
  - [ ] Architecture diagram (frontend/backend topology).
  - [ ] Exploitation scenarios (cache poisoning, auth bypass).

---

## P1.9 – WebSocket Security Testing – P1/P2
**Rationale:** WebSockets bypass many traditional security controls. Growing attack surface in modern apps.

- **Discovery**
  - [ ] Detect WebSocket endpoints from JS analysis.
  - [ ] Extract message schemas and event handlers.
  - [ ] Identify auth mechanisms (token in URL, headers, first message).
- **Validation**
  - [ ] `/mcp/run_websocket_checks` endpoint:
    - [ ] CSWSH (Cross-Site WebSocket Hijacking) detection.
    - [ ] Auth bypass via origin manipulation.
    - [ ] Message injection and privilege escalation.
    - [ ] Rate limit bypass via persistent connections.
- **Triage & Reporting**
  - [ ] WebSocket-specific impact (real-time data exfil, impersonation).

---

## P2.3 – Subdomain Takeover Pipeline – P1/P2
**Rationale:** Easy wins, but requires continuous monitoring. Highly automatable.

- **Discovery**
  - [ ] Integrate with subdomain enumeration (subfinder, amass).
  - [ ] CNAME fingerprinting for dangling records.
  - [ ] Cloud service signature detection (S3, Azure, Heroku, GitHub Pages).
- **Validation**
  - [ ] `/mcp/run_takeover_checks` endpoint:
    - [ ] Automated claim verification (safe, non-destructive).
    - [ ] Screenshot + DNS evidence collection.
  - [ ] Integration with `can-i-take-over-xyz` fingerprints.
- **Continuous Monitoring**
  - [ ] Delta alerting when new dangling CNAMEs appear.
  - [ ] Historical tracking of subdomain changes.

---

## P2.4 – Cache Poisoning Detection – P1/P2
**Rationale:** Web cache poisoning can escalate to mass user compromise. High-impact, often overlooked.

- **Discovery**
  - [ ] Detect caching layers (CDN fingerprinting, cache headers).
  - [ ] Identify unkeyed inputs (headers, cookies, query params).
- **Validation**
  - [ ] `/mcp/run_cache_poison_checks` endpoint:
    - [ ] Cache key detection via response analysis.
    - [ ] Unkeyed header injection testing.
    - [ ] XSS/redirect via cached response.
  - [ ] Safe testing mode (unique cache busters per test).
- **Triage & Reporting**
  - [ ] Affected user scope estimation.
  - [ ] Cache TTL and purge documentation.

---

## P2.5 – Business Logic Flaw Detection (AI-Assisted) – P2
**Rationale:** Business logic bugs often pay the most but are hardest to automate. LLM can help identify patterns.

- **Discovery**
  - [ ] LLM analysis of API schemas and workflows.
  - [ ] Detect price manipulation, quantity bypass, coupon abuse vectors.
  - [ ] Identify multi-step processes (checkout, signup, approval flows).
- **Validation**
  - [ ] `/mcp/run_bizlogic_checks` endpoint:
    - [ ] Negative quantity/price injection.
    - [ ] Step-skipping in multi-stage flows.
    - [ ] Coupon/discount stacking.
    - [ ] Free trial abuse patterns.
- **AI Triage**
  - [ ] LLM-generated attack scenarios per discovered flow.
  - [ ] Business impact estimation.

---

## P2.6 – Password Reset Flow Analyzer – P1/P2
**Rationale:** Password reset bugs are common and often lead to ATO. Highly structured, automatable.

- **Discovery**
  - [ ] Detect password reset endpoints and flows.
  - [ ] Extract token formats, expiration, and delivery mechanisms.
- **Validation**
  - [ ] `/mcp/run_reset_flow_checks` endpoint:
    - [ ] Token predictability analysis (entropy, timestamp leakage).
    - [ ] Host header injection for password reset poisoning.
    - [ ] Token reuse after password change.
    - [ ] Rate limiting and lockout bypass.
    - [ ] Email parameter injection.
- **Triage & Reporting**
  - [ ] ATO chain documentation.
  - [ ] Token sample evidence.

---

## P2.7 – GraphQL Deep Security Testing – P1/P2
**Rationale:** GraphQL is increasingly common and has unique attack patterns (batching, introspection, DoS).

- **Discovery**
  - [ ] Full schema extraction via introspection.
  - [ ] Mutation and query analysis for sensitive operations.
  - [ ] Detect disabled introspection (field suggestion bypass).
- **Validation**
  - [ ] `/mcp/run_graphql_security` endpoint:
    - [ ] Query depth/complexity attacks (DoS).
    - [ ] Batching attacks for brute force.
    - [ ] Field-level authorization testing.
    - [ ] Alias-based rate limit bypass.
    - [ ] Introspection data leakage assessment.
- **AI Integration**
  - [ ] LLM-generated attack queries from schema.
  - [ ] IDOR detection via ID field enumeration.

---

## P2.8 – Mass Assignment / Parameter Pollution – P2
**Rationale:** Common in REST APIs, especially with auto-binding frameworks (Rails, Django, Spring).

- **Discovery**
  - [ ] Detect frameworks with auto-binding (via fingerprinting).
  - [ ] Extract model schemas from API responses.
  - [ ] Identify privileged fields (role, admin, verified, balance).
- **Validation**
  - [ ] `/mcp/run_mass_assign_checks` endpoint:
    - [ ] Inject privileged fields in POST/PUT/PATCH.
    - [ ] HTTP Parameter Pollution (HPP) testing.
    - [ ] Array/object injection in form data.
- **Triage & Reporting**
  - [ ] Before/after state comparison.
  - [ ] Privilege escalation path documentation.

---

## P3.1 – Server-Side Template Injection (SSTI) – P2/P3
**Rationale:** SSTI often leads to RCE. Framework-aware detection improves accuracy.

- **Discovery**
  - [ ] Detect template engines via error messages and behavior.
  - [ ] Identify reflection points in rendered content.
- **Validation**
  - [ ] `/mcp/run_ssti_checks` endpoint:
    - [ ] Framework-specific polyglot payloads (Jinja2, Twig, Freemarker, etc.).
    - [ ] Blind SSTI via time-based detection.
    - [ ] Safe RCE confirmation (hostname/id output).
- **Triage & Reporting**
  - [ ] Confirmed engine and exploitation path.
  - [ ] RCE impact documentation.

---

## P3.2 – Path Traversal / LFI / RFI Testing – P2
**Rationale:** File inclusion bugs remain common, especially in legacy code and file handling features.

- **Discovery**
  - [ ] Identify file-related parameters (file, path, template, include, page).
  - [ ] Detect upload/download functionality.
- **Validation**
  - [ ] `/mcp/run_path_traversal_checks` endpoint:
    - [ ] OS-aware traversal payloads (Windows/Linux).
    - [ ] Encoding bypass attempts (URL, double, null byte).
    - [ ] Known sensitive file targets (/etc/passwd, web.config, .env).
    - [ ] RFI via external URL injection.
- **Triage & Reporting**
  - [ ] File content evidence (redacted if sensitive).
  - [ ] Exploitation chain (LFI → log poisoning → RCE).

---

## P3.3 – Prototype Pollution Scanner (Client-Side) – P2/P3
**Rationale:** Prototype pollution is a growing attack class, especially in Node.js and client-side JS.

- **Discovery**
  - [ ] Static analysis of JS for gadget patterns.
  - [ ] Detect vulnerable libraries (lodash, jQuery.extend, etc.).
- **Validation**
  - [ ] `/mcp/run_prototype_pollution_checks` endpoint:
    - [ ] DOM-based pollution detection.
    - [ ] Server-side Node.js pollution (JSON parsing).
    - [ ] Gadget chain identification for XSS/RCE.
- **Triage & Reporting**
  - [ ] Pollution vector and exploitable gadget.
  - [ ] Impact escalation (XSS, bypass, RCE).

---

## P3.4 – HackerOne/Bugcrowd Platform Integration – P3
**Rationale:** Streamline the submission workflow and reduce duplicates.

- **Integration Features**
  - [ ] H1/Bugcrowd API client for report submission drafts.
  - [ ] Duplicate detection via similarity search against past reports.
  - [ ] Scope change monitoring (new assets, wildcard additions).
  - [ ] Program metadata ingestion (payout ranges, response times).
- **Automation**
  - [ ] Auto-format reports for platform markdown.
  - [ ] Severity suggestion based on program payout history.
  - [ ] Track submission status and responses.

---

## P3.5 – JWT Security Analyzer – P2
**Rationale:** JWT misconfigurations are common and well-paying (alg:none, weak secrets, claim tampering).

- **Discovery**
  - [ ] Detect JWT usage in headers, cookies, and responses.
  - [ ] Extract and decode tokens for claim analysis.
- **Validation**
  - [ ] `/mcp/run_jwt_checks` endpoint:
    - [ ] Algorithm confusion attacks (none, HS256 with public key).
    - [ ] Weak secret brute force (common wordlist).
    - [ ] Claim tampering (sub, role, exp manipulation).
    - [ ] JWK injection attacks.
    - [ ] Kid parameter injection.
- **Triage & Reporting**
  - [ ] Token structure breakdown.
  - [ ] Exploitation PoC with modified token.

---

## P4.6 – Insecure Deserialization Detection – P3/P4
**Rationale:** Deserialization bugs often lead to RCE. Complex but high-value.

- **Discovery**
  - [ ] Detect serialization formats (Java, PHP, .NET, Python pickle).
  - [ ] Identify endpoints accepting serialized data.
- **Validation**
  - [ ] `/mcp/run_deser_checks` endpoint:
    - [ ] Framework-specific gadget chain payloads.
    - [ ] DNS/HTTP callback for blind detection.
    - [ ] Integration with ysoserial, phpggc.
- **Triage & Reporting**
  - [ ] Confirmed gadget chain and payload.
  - [ ] RCE evidence (callback, command output).

---

## P4.7 – CI/CD & DevOps Security Surface – P3/P4
**Rationale:** Exposed CI/CD systems are goldmines (Jenkins, GitLab CI, GitHub Actions artifacts).

- **Discovery**
  - [ ] Detect CI/CD panels (Jenkins, TeamCity, GitLab, CircleCI).
  - [ ] Identify exposed build artifacts, logs, and credentials.
  - [ ] GitHub Actions workflow analysis for secret exposure.
- **Validation**
  - [ ] `/mcp/run_cicd_checks` endpoint:
    - [ ] Default credential testing.
    - [ ] Public artifact enumeration.
    - [ ] Workflow injection vectors.
- **Triage & Reporting**
  - [ ] Exposed secrets and their scope.
  - [ ] Supply chain attack potential.

---

## P4.8 – API Fuzzing Engine (Schema-Aware) – P2/P3
**Rationale:** Intelligent API fuzzing based on OpenAPI/Swagger/GraphQL schemas increases coverage.

- **Discovery**
  - [ ] Auto-detect and parse API specifications.
  - [ ] Generate valid request templates from schemas.
- **Validation**
  - [ ] `/mcp/run_api_fuzz` endpoint:
    - [ ] Type confusion fuzzing (string→int, array→object).
    - [ ] Boundary value testing.
    - [ ] Required field omission.
    - [ ] Auth bypass via parameter manipulation.
- **AI Enhancement**
  - [ ] LLM-generated edge case inputs.
  - [ ] Anomaly detection in responses.

---

## P5.1 – Real-Time Collaboration Mode – P4/P5
**Rationale:** Enable team-based bug hunting with shared findings and deduplication.

- **Features**
  - [ ] Multi-user scan sessions with role-based access.
  - [ ] Real-time finding synchronization.
  - [ ] Team duplicate detection.
  - [ ] Finding assignment and status tracking.
- **Integration**
  - [ ] Slack/Discord notifications for team findings.
  - [ ] Shared knowledge base per program.

---

## Priority Summary (New Features)

| Feature | Priority | Estimated Bounty Impact |
|---------|----------|------------------------|
| OAuth/OIDC Analyzer | P0/P1 | $5K-$50K per bug |
| Race Condition Detection | P0/P1 | $10K-$100K per bug |
| HTTP Request Smuggling | P1 | $10K-$100K per bug |
| WebSocket Security | P1/P2 | $1K-$20K per bug |
| Subdomain Takeover | P1/P2 | $500-$5K per bug |
| Cache Poisoning | P1/P2 | $5K-$50K per bug |
| Business Logic (AI) | P2 | $5K-$100K per bug |
| Password Reset Analyzer | P1/P2 | $1K-$10K per bug |
| GraphQL Deep Testing | P1/P2 | $1K-$20K per bug |
| Mass Assignment | P2 | $1K-$10K per bug |
| SSTI Detection | P2/P3 | $5K-$50K per bug |
| Path Traversal/LFI | P2 | $1K-$20K per bug |
| Prototype Pollution | P2/P3 | $1K-$15K per bug |
| Platform Integration | P3 | Efficiency gain |
| JWT Analyzer | P2 | $1K-$20K per bug |
| Deserialization | P3/P4 | $10K-$100K per bug |
| CI/CD Security | P3/P4 | $5K-$50K per bug |
| API Fuzzing Engine | P2/P3 | $1K-$20K per bug |
