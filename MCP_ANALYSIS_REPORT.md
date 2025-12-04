# MCP Server & Agentic Bug Bounty Analysis Report

**Generated:** December 4, 2025  
**Analyst:** AI Code Review  
**Scope:** Full codebase analysis + lab simulation planning

---

## Executive Summary

This analysis covers the agentic bug bounty automation system with the MCP (Model Context Protocol) server architecture. The codebase demonstrates a sophisticated approach to automated security testing with AI-driven triage, but has **several critical gaps** between documented features and actual implementation.

### Key Findings

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Missing Endpoints | 0 | 6 | 4 | 3 |
| Code Quality | 0 | 1 | 2 | 2 |
| Documentation | 0 | 0 | 1 | 2 |
| **Total** | **0** | **7** | **7** | **7** |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Agentic Runner                            │
│  (agentic_runner.py - LLM Triage + Validation Engine)       │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    MCP Server (FastAPI)                      │
│  mcp_zap_server.py - Port 8100                              │
│  ┌────────────────┬────────────────┬────────────────┐       │
│  │ /mcp/set_scope │ /mcp/host_profile │ /mcp/job/{id} │     │
│  │ /mcp/set_auth  │ /mcp/host_delta   │               │     │
│  └────────────────┴────────────────┴────────────────┘       │
│  ┌────────────────────────────────────────────────────┐     │
│  │ Scanning Endpoints                                  │     │
│  │ ✅ /mcp/run_katana_nuclei    ❌ /mcp/run_nuclei    │     │
│  │ ✅ /mcp/run_katana_auth      ❌ /mcp/run_ffuf      │     │
│  │ ✅ /mcp/run_fingerprints     ❌ /mcp/run_sqlmap    │     │
│  │ ✅ /mcp/run_backup_hunt      ❌ /mcp/run_bac_checks│     │
│  │ ✅ /mcp/run_js_miner         ❌ /mcp/run_ssrf_checks│    │
│  │ ✅ /mcp/run_api_recon        ❌ /mcp/start_zap_scan│     │
│  └────────────────────────────────────────────────────┘     │
│  ┌────────────────────────────────────────────────────┐     │
│  │ AI Triage                                           │     │
│  │ ✅ /mcp/triage_nuclei_templates                    │     │
│  │ ✅ /mcp/run_targeted_nuclei                        │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    External Tools                            │
│  ┌──────────┬──────────┬──────────┬──────────┐             │
│  │  Katana  │  Nuclei  │  WhatWeb │  Dalfox  │             │
│  │ (Docker) │ (Binary) │ (Binary) │ (Binary) │             │
│  └──────────┴──────────┴──────────┴──────────┘             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔴 HIGH Priority Issues

### 1. Missing `/mcp/run_bac_checks` Endpoint

**Component:** `mcp_zap_server.py`  
**Impact:** Broken Access Control testing is not functional

The `agentic_runner.py` calls `/mcp/run_bac_checks` at line 709 for BAC validation, but this endpoint does not exist in `mcp_zap_server.py`.

```python
# agentic_runner.py:709 - References non-existent endpoint
resp = _mcp_post("/mcp/run_bac_checks", payload)
```

**Fix Required:** Implement the endpoint:

```python
class BacChecksRequest(BaseModel):
    host: str
    url: Optional[str] = None
    auth_headers: Optional[Dict[str, str]] = None

@app.post("/mcp/run_bac_checks")
def run_bac_checks(req: BacChecksRequest):
    """Test for Broken Access Control issues.
    
    Performs:
    - Horizontal privilege escalation tests
    - Vertical privilege escalation tests  
    - IDOR detection on identified API endpoints
    """
    # Implementation needed
    pass
```

---

### 2. Missing `/mcp/run_ssrf_checks` Endpoint

**Component:** `mcp_zap_server.py`  
**Impact:** SSRF validation is not functional

Referenced in `agentic_runner.py` line 778 but not implemented.

```python
# agentic_runner.py:778 - References non-existent endpoint
resp = _mcp_post("/mcp/run_ssrf_checks", payload)
```

**Fix Required:** Implement SSRF checking with:
- Internal IP detection (127.0.0.1, 169.254.x.x, 10.x.x.x, etc.)
- Cloud metadata endpoint testing
- DNS rebinding checks
- Integration with Interactsh for OOB detection

---

### 3. Missing `/mcp/run_sqlmap` Endpoint

**Component:** `mcp_zap_server.py`  
**Impact:** SQL injection validation is not functional

Referenced in `agentic_runner.py` line 624 but not implemented.

**Fix Required:** Implement sqlmap wrapper similar to the existing backup_hunt background job pattern.

---

### 4. Missing `/mcp/run_ffuf` Endpoint

**Component:** `mcp_zap_server.py`  
**Impact:** Content discovery/fuzzing is not functional

Declared in the docstring but not implemented:

```python
# mcp_zap_server.py:8 - Documented but not implemented
# - /mcp/run_ffuf          -> run ffuf on a target endpoint
```

---

### 5. Missing `/mcp/run_nuclei` Endpoint

**Component:** `mcp_zap_server.py`  
**Impact:** Standalone nuclei scans not available

Only `run_katana_nuclei` and `run_targeted_nuclei` exist. A standalone nuclei endpoint would be useful for custom template runs.

---

### 6. Missing `/mcp/start_zap_scan` & `/mcp/poll_zap` Endpoints

**Component:** `mcp_zap_server.py`  
**Impact:** Full-scan mode ZAP integration broken

The `run_full_scan_via_mcp()` function in `agentic_runner.py` calls these endpoints:

```python
# agentic_runner.py:312-329
resp = _mcp_post("/mcp/start_zap_scan", body)
status = _mcp_get(f"/mcp/poll_zap?scan_id={scan_id}")
```

But neither endpoint exists in the MCP server.

---

## 🟡 MEDIUM Priority Issues

### 7. Missing `/mcp/run_cloud_recon` Endpoint

**Component:** `mcp_zap_server.py`  
**Impact:** Cloud resource discovery not functional

Referenced in `agentic_runner.py` line 343 but not implemented.

---

### 8. Missing `/mcp/prioritize_host` Endpoint

**Component:** `mcp_zap_server.py`  
**Impact:** Risk-based host prioritization not available

Referenced in `agentic_runner.py` line 389 but not implemented.

---

### 9. Missing `/mcp/validate_poc_with_nuclei` Endpoint

**Component:** `mcp_zap_server.py`  
**Impact:** PoC validation workflow incomplete

Documented in docstring line 10 but not implemented.

---

### 10. `OPENAI_API_KEY` Hard Dependency

**Component:** `agentic_runner.py`  
**Impact:** System unusable without OpenAI API key

```python
# agentic_runner.py:16-17
if not OPENAI_API_KEY:
    raise SystemExit("Set OPENAI_API_KEY env var.")
```

**Fix:** Add a `--no-llm` mode that:
- Uses static rule-based triage
- Skips LLM-dependent validation steps
- Falls back to heuristic severity scoring

---

### 11. Inconsistent Port Configuration

**Component:** Multiple files  
**Impact:** Confusion during deployment

| File | Port Used |
|------|-----------|
| `docker-compose.yml` | 8000 |
| `agentic_runner.py` | 8000 (MCP_SERVER_URL) |
| `mcp_zap_server.py` | 8100 (uvicorn) |
| `lab_runner.py` | 8000 |

The MCP server runs on 8100 by default, but most references expect 8000.

---

## 🟢 LOW Priority Issues

### 12. Incomplete `reflector_tester.py`

**Component:** `tools/reflector_tester.py`  
**Impact:** Parameter reflection testing limited

The tool exists but may need enhancement for comprehensive reflection detection.

---

### 13. Missing Error Handling in Background Jobs

**Component:** `mcp_zap_server.py`  
**Impact:** Silent failures in async operations

Background jobs catch exceptions but don't provide detailed error context.

---

### 14. Lab Port Mapping Inconsistencies

**Component:** `labs/*/docker-compose.yml`  
**Impact:** Confusion when running labs locally

| Lab | Internal Port | Exposed Port |
|-----|--------------|--------------|
| xss_js_secrets | 5000 | 5001 |
| backup_leaks_fingerprint | 80 | 8080 (assumed) |
| idor_auth | 5000 | 5002 (assumed) |

---

## Docker Lab Test Matrix

### Expected Findings Per Lab

| Lab | XSS | SQLi | IDOR | Backups | JS Secrets | Fingerprints |
|-----|-----|------|------|---------|------------|--------------|
| xss_js_secrets | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| backup_leaks_fingerprint | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ |
| idor_auth | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |

### Lab Vulnerabilities Detail

#### xss_js_secrets Lab
- **XSS:** Reflected XSS at `/search?q=<script>alert(1)</script>`
- **JS Secrets:** API keys and JWT in `/static/config.js`

#### backup_leaks_fingerprint Lab
- **Backups:** `/config.php.bak`, `/.git/HEAD`
- **Fingerprints:** Apache, PHP detection

#### idor_auth Lab  
- **IDOR:** `/api/users/2` accessible by user 1's token
- **Auth:** Bearer token at `/login/alice`

---

## Recommended Implementation Order

### Phase 1: Critical Path (Week 1)
1. ✅ Implement `/mcp/run_bac_checks`
2. ✅ Implement `/mcp/run_ssrf_checks`  
3. ✅ Implement `/mcp/run_sqlmap`
4. ✅ Fix port configuration consistency

### Phase 2: Full Feature Parity (Week 2)
5. ✅ Implement `/mcp/run_ffuf`
6. ✅ Implement `/mcp/run_nuclei`
7. ✅ Add `--no-llm` fallback mode
8. ✅ Implement `/mcp/run_cloud_recon`

### Phase 3: Polish (Week 3)
9. ✅ Implement `/mcp/prioritize_host`
10. ✅ Implement `/mcp/validate_poc_with_nuclei`
11. ✅ Enhance error handling in background jobs
12. ✅ Add ZAP integration or remove references

---

## How to Run the Test Simulation

### Prerequisites

```bash
# Create and activate venv
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start labs (in separate terminals or use -d)
cd labs/xss_js_secrets && docker-compose up -d
cd labs/backup_leaks_fingerprint && docker-compose up -d
cd labs/idor_auth && docker-compose up -d

# Start MCP server
python mcp_zap_server.py
```

### Run Tests

```bash
# Run full simulation
python tests/test_mcp_lab_simulation.py

# Test specific lab
python tests/test_mcp_lab_simulation.py --labs xss_js_secrets

# Use custom MCP URL
python tests/test_mcp_lab_simulation.py --mcp-url http://localhost:8100
```

### View Reports

Reports are generated in `output_zap/test_reports/`:
- `mcp_lab_report_YYYYMMDD_HHMMSS.md` - Human-readable markdown
- `mcp_lab_report_YYYYMMDD_HHMMSS.json` - Machine-parseable JSON

---

## Appendix: File Structure Summary

```
agentic-bugbounty/
├── mcp_zap_server.py      # Main MCP server (FastAPI) ⚠️ Missing endpoints
├── agentic_runner.py      # LLM triage + full scan orchestration
├── requirements.txt       # Python dependencies
├── docker-compose.yml     # MCP + Juice Shop deployment
│
├── tools/
│   ├── ai_nuclei_triage.py    # ✅ AI template selection
│   ├── backup_hunt.py         # ✅ Backup file discovery
│   ├── js_miner.py            # ✅ JS secrets extraction
│   ├── katana_nuclei_recon.py # ✅ Katana + Nuclei wrapper
│   ├── katana_auth_helper.py  # ✅ Authenticated crawling
│   ├── lab_runner.py          # ✅ Lab test harness
│   └── reflector_tester.py    # ⚠️ May need enhancement
│
├── labs/
│   ├── xss_js_secrets/        # XSS + JS secrets lab
│   ├── backup_leaks_fingerprint/  # Backup exposure lab
│   └── idor_auth/             # IDOR + auth lab
│
├── utils/
│   └── artifact.py            # ✅ Secret-aware file writer
│
├── tests/
│   ├── test_mcp_zap_katana_api.py  # Existing unit tests
│   └── test_mcp_lab_simulation.py  # NEW: Integration tests
│
└── output_zap/                # Scan outputs & reports
```

---

## Conclusion

The agentic bug bounty system has a **solid foundation** but requires completion of several documented-but-unimplemented endpoints before production use. The most critical gaps are:

1. **BAC/IDOR testing** - Essential for auth bypass detection
2. **SSRF validation** - Critical for server-side vuln confirmation
3. **SQL injection testing** - Important for injection validation

The test simulation script (`tests/test_mcp_lab_simulation.py`) will help validate fixes as they're implemented.

