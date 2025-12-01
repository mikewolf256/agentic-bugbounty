# P0 Bug Bounty & Red-Team Roadmap

This roadmap tracks planned capabilities for the current P0 program across seven core bug bounty focus areas, plus red-team and platform features.

---

## Now / Next / Later

- **Now (immediate P0 focus)**
  - Solidify core pipeline and host deltas (`P0.0`).
  - Clean up XSS + Dalfox behavior and triage outputs (`P0.1`).
  - Ship a minimal, reliable full-scan-in-Docker path with clean reports.
- **Next (once core scans feel stable)**
  - Add SQLi + BAC validation endpoints (`P0.2`, `P0.3`).
  - Expand secrets/cloud/misconfig coverage (`P0.5`, `P0.6`).
  - Standardize triage schema + Markdown templates; start MITRE mapping (`P0.8`, `P4.1`).
- **Later (red-team & platform)**
  - ATT&CK Navigator export and exec PDF reporting (`P4.2`, `P4.3`).
  - Red-team simulation mode with attack graphs and high-value-path scoring (`P4.5`).
  - Continuous ASM, multi-tenancy, and client-facing portal (`P0.9`).

---

## P0.0 – Core Pipeline (Done / Ongoing Polish)

- **MCP + Runner foundation**
  - FastAPI MCP server in `mcp_zap_server.py` with ZAP integration.
  - `agentic_runner.py` with `full-scan` and `triage` modes.
  - Host profiling, prioritization, and host delta endpoints.
- **Containerization**
  - `Dockerfile.mcp` for MCP server.
  - `docker-compose.yml` for MCP + ZAP, wired via `ZAP_API_BASE`.
- **Cloud recon + basic secrets**
  - `/mcp/run_cloud_recon` endpoint and `cloud_findings_*.json` outputs.
  - LLM triage for cloud findings with simple secret/PII regex checks.

---

## P0.1 – XSS (Reflected, Stored, DOM)

- **Discovery**
  - [ ] Extend `host_profile` to track:
    - [ ] Reflected parameters and HTML injection points.
    - [ ] JS/DOM risk indicators (inline event handlers, dangerous sinks).
  - [ ] Tune ZAP policies / scan configs for XSS-heavy coverage.
- **Validation (Dalfox)**
  - [ ] Tighten Dalfox integration in `agentic_runner.py`:
    - [ ] Only run Dalfox when LLM or ZAP classifies a finding as XSS-like.
    - [ ] Add `validation_engine` and `validation_confidence` fields to triage.
    - [ ] Cache Dalfox results per URL + param + payload.
  - [ ] Skip Dalfox for cloud-only findings and hide Dalfox section in XSS-irrelevant markdown.
- **Triage & Reporting**
  - [ ] Update triage prompt to classify:
    - [ ] XSS type (reflected, stored, DOM).
    - [ ] Context (attribute, body, JS).
  - [ ] Standard XSS report template:
    - [ ] Reproduction steps with payload.
    - [ ] Impact narrative (session theft, account takeover).
    - [ ] Remediation guidance (output encoding, CSP, input validation).
- **Profiles / Modes**
  - [ ] Add `--profile xss-heavy` mode in `agentic_runner.py` focusing on:
    - [ ] ZAP XSS rules and Dalfox validation.
    - [ ] UI-heavy hosts or paths from scope.

---

## P0.2 – SQL Injection (SQLi)

- **Discovery**
  - [ ] Enhance recon to flag endpoints with:
    - [ ] DB-like error messages and stack traces.
    - [ ] Numeric or identifier-style parameters (`id`, `user_id`, etc.).
- **Validation (sqlmap)**
  - [ ] Implement `/mcp/run_sqlmap` endpoint:
    - [ ] Accept URL, method, params, cookies, headers.
    - [ ] Run `sqlmap` with safe defaults and timeouts.
    - [ ] Write `sqlmap_<host>_<hash>.json` or `.txt` under `output_zap/`.
  - [ ] Wire `agentic_runner.py` triage to:
    - [ ] Trigger `/mcp/run_sqlmap` for suspected SQLi findings.
    - [ ] Parse results into `dbms`, `vulnerable_params`, `dumped_data_summary`.
- **Triage & Reporting**
  - [ ] SQLi-specific triage prompts and Markdown template:
    - [ ] DBMS detected and exploitation method (boolean, time-based, UNION).
    - [ ] Example vulnerable request and parameter.
    - [ ] Data access capability and impact.
- **Profiles / Modes**
  - [ ] Add `--profile sqli-heavy` focused on identifier parameters and search endpoints.

---

## P0.3 – Broken Access Control (BAC)

- **Discovery**
  - [ ] Extend `host_profile` to capture:
    - [ ] Candidate admin or internal endpoints (`/admin`, `/internal`, etc.).
    - [ ] Object/tenant identifiers (project IDs, org IDs).
  - [ ] Define `access_model.yaml` (or similar) to describe:
    - [ ] Roles (user, admin, support, etc.).
    - [ ] Sample credentials or tokens.
- **Validation**
  - [ ] Implement `/mcp/run_bac_checks` endpoint:
    - [ ] IDOR checks by swapping IDs across users/tenants.
    - [ ] Vertical auth checks: low-priv tokens on admin endpoints.
    - [ ] Horizontal auth checks across accounts.
    - [ ] Output `bac_findings_<host>.json` with structured results.
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

## P0.4 – SSRF

- **Discovery**
  - [ ] Recon enhancements to identify SSRF candidates:
    - [ ] Parameters like `url`, `callback`, `redirect`, `target`.
    - [ ] Import-by-URL features and webhooks.
  - [ ] Add config for callback server:
    - [ ] `SSRF_CALLBACK_URL` env var or scope option.
- **Validation**
  - [ ] Implement `/mcp/run_ssrf_checks` endpoint:
    - [ ] Send payloads with callback URLs and variants (HTTP/HTTPS/DNS-only).
    - [ ] Correlate callbacks with requests (logs, DNS, webhook events).
    - [ ] Store `ssrf_findings_<host>.json`.
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

## P0.5 – Secrets, Sensitive Data & Info Disclosure

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

## P0.6 – Misconfig & Cloud Storage Surface

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

## P0.7 – Outdated Components & Dependency Issues

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

## P0.8 – Cross-Cutting: Orchestration, UX, and Testing

- **Orchestration & Telemetry**
  - [ ] Extend `program_run_<ts>.json` to record:
    - [ ] Modules/profiles executed.
    - [ ] Per-step runtime, errors, and status.
  - [ ] Define scan orders per profile (ZAP → recon → validators → triage).
- **Unified MCP API Surface**
  - [ ] Ensure each module has:
    - [ ] `/mcp/run_<module>` endpoint with clear request/response schema.
    - [ ] Documentation in `README.md` or a dedicated API doc.
- **Triage Schema & Templates**
  - [ ] Standardize triage JSON:
    - [ ] `category`, `subtype`, `confidence`, `validation_engine`, `validation_status`, `evidence_refs`.
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
  - [ ] Create static mapping rules for common bug classes (XSS, SQLi, BAC, SSRF, etc.).
  - [ ] Add `"mitre"` field to the unified triage JSON schema (techniques, tactics, confidence).
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

## P0.9 – Continuous ASM & Multi-Tenancy

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
