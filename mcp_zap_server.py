# mcp_zap_server.py
"""
MCP-style starter server using free tooling:
- OWASP ZAP (API) for crawling + active scanning
- ffuf for fast fuzzing
- sqlmap for SQLi checks
- interactsh-client (optional) for OAST / blind callback tests

Features:
- /mcp/set_scope      -> upload scope (json)
- /mcp/start_zap_scan -> start a ZAP spider + active scan (injects X-HackerOne-Research header)
- /mcp/run_ffuf       -> run ffuf on a target endpoint with header
- /mcp/run_sqlmap     -> run sqlmap on a target endpoint with header
- /mcp/poll_zap       -> poll ZAP for alerts and normalize
- /mcp/export_report  -> produce HackerOne markdown reports for alerts/findings

Notes:
- Requires local ZAP running with API accessible (default http://localhost:8080).
- ffuf and sqlmap must be installed and in PATH for the ffuf/sqlmap endpoints.
- For interactsh usage, install the interactsh-client binary and provide path in config.
"""
import os
import json
import time
import subprocess
import threading
from typing import List, Dict, Any, Optional
from uuid import uuid4

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# ========== CONFIG ==========
ZAP_API_BASE = os.environ.get("ZAP_API_BASE", "http://localhost:8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")  # optional if ZAP requires it
H1_ALIAS = os.environ.get("H1_ALIAS", "h1yourusername@wearehackerone.com")
MAX_REQ_PER_SEC = float(os.environ.get("MAX_REQ_PER_SEC", "3.0"))
INTERACTSH_CLIENT = os.environ.get("INTERACTSH_CLIENT", "")  # optional: path to interactsh-client
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "./output_zap")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ========== simple rate limiter ==========
_last_time = 0.0
_allowance = MAX_REQ_PER_SEC

def rate_limit_wait():
    global _last_time, _allowance
    current = time.time()
    elapsed = current - _last_time
    _last_time = current
    _allowance += elapsed * MAX_REQ_PER_SEC
    if _allowance > MAX_REQ_PER_SEC:
        _allowance = MAX_REQ_PER_SEC
    if _allowance < 1.0:
        time.sleep((1.0 - _allowance) / MAX_REQ_PER_SEC)
        _allowance = 0.0
    else:
        _allowance -= 1.0

# ========== FastAPI & models ==========
app = FastAPI(title="MCP ZAP Starter Server (Free tools)")

class ScopeConfig(BaseModel):
    program_name: str
    primary_targets: List[str]
    secondary_targets: List[str]
    rules: Dict[str, Any] = {}

class ZapScanRequest(BaseModel):
    targets: List[str]
    context_name: Optional[str] = "Default Context"
    scan_policy_name: Optional[str] = None  # leave None to use default

class FfufRequest(BaseModel):
    target: str
    wordlist: str
    headers: Optional[Dict[str, str]] = None
    rate: Optional[int] = None  # req/sec

class SqlmapRequest(BaseModel):
    target: str
    data: Optional[str] = None
    headers: Optional[Dict[str, str]] = None

# in-memory stores
SCOPE: Optional[ScopeConfig] = None
JOB_STORE: Dict[str, Dict[str, Any]] = {}
ZAP_SCAN_IDS: Dict[str, str] = {}  # our_scan_id -> zap_scan_id

# ========== helper ZAP API calls ==========
def zap_api(endpoint_path: str, params: Dict[str, Any] = None, method: str = "GET", json_body: Any = None):
    """
    Generic ZAP API requester. ZAP API has: /JSON/{component}/action/{name}
    Example: GET /JSON/core/view/alerts/?baseurl=...
    """
    if params is None:
        params = {}
    if ZAP_API_KEY:
        params["apikey"] = ZAP_API_KEY
    url = ZAP_API_BASE.rstrip("/") + endpoint_path
    rate_limit_wait()
    try:
        if method.upper() == "GET":
            r = requests.get(url, params=params, timeout=60)
        else:
            r = requests.post(url, params=params, json=json_body, timeout=60)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error contacting ZAP at {url}: {e}")
    if r.status_code >= 400:
        raise HTTPException(status_code=r.status_code, detail=f"ZAP API error {r.status_code}: {r.text}")
    try:
        return r.json()
    except ValueError:
        return r.text

# Add a simple httpsender script to inject header into outgoing requests.
# ZAP supports scripts with type 'httpsender' and engines like 'ECMAScript' or 'Oracle Nashorn'.
# We'll attempt to add one named 'h1_research_header' that adds X-HackerOne-Research header.
def ensure_zap_header_script():
    # Check existing scripts
    try:
        scripts = zap_api("/JSON/script/view/listScripts/")
    except Exception:
        # If script API not available, skip silently
        return False
    # scripts is like {"scripts": [...]}
    for s in scripts.get("scripts", []):
        if s.get("name") == "h1_research_header":
            return True
    # Create script body (ECMAScript example) - it prepends the header on each request
    script_body = f"""
function sendingRequest(msg, initiator, helper) {{
    var headers = msg.getRequestHeader();
    headers.setHeader("X-HackerOne-Research", "{H1_ALIAS}");
    msg.setRequestHeader(headers);
}}
function responseReceived(msg, initiator, helper) {{
    // no-op
}}
"""
    # Add script. engine=ECMAScript, type=httpsender
    params = {
        "scriptName": "h1_research_header",
        "scriptType": "httpsender",
        "scriptEngine": "ECMAScript",
        "script": script_body
    }
    try:
        zap_api("/JSON/script/action/addScript/", params=params, method="POST")
        return True
    except Exception as e:
        # some ZAP versions restrict script adding; return False but continue
        print("[!] Could not add ZAP header script:", e)
        return False

# ========== MCP endpoints ==========
@app.post("/mcp/set_scope")
def set_scope(cfg: dict):
    global SCOPE
    try:
        SCOPE = ScopeConfig(**cfg)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid scope JSON: {e}")
    with open(os.path.join(OUTPUT_DIR, "scope.json"), "w") as fh:
        json.dump(cfg, fh, indent=2)
    return {"status": "ok", "program": SCOPE.program_name}

@app.post("/mcp/start_zap_scan")
def start_zap_scan(req: ZapScanRequest):
    if SCOPE is None:
        raise HTTPException(status_code=400, detail="Scope not set. Call /mcp/set_scope first.")
    for t in req.targets:
        if t not in SCOPE.primary_targets and t not in SCOPE.secondary_targets:
            raise HTTPException(status_code=400, detail=f"Target {t} not in scope.")
    # Ensure header injection in ZAP via scripts (best-effort)
    ensure_zap_header_script()
    # First, spider each target
    zap_scan_ids = []
    for t in req.targets:
        # Spider
        spider_resp = zap_api("/JSON/spider/action/scan/", params={"url": f"https://{t}", "maxChildren": 0})
        scanid = spider_resp.get("scan") if isinstance(spider_resp, dict) else None
        zap_scan_ids.append(scanid)
        # Poll spider until done (background thread)
    # Start active scan for each base URL (use ascan)
    our_scan_id = str(uuid4())
    JOB_STORE[our_scan_id] = {"type": "zap", "targets": req.targets, "created": time.time(), "status": "started", "zap_ids": zap_scan_ids}
    def scan_worker(our_id, targets):
        try:
            # Wait a short time for spider to populate (conservative)
            time.sleep(5)
            # For each target start active scan
            active_ids = []
            for t in targets:
                params = {"url": f"https://{t}"}
                if ZAP_API_KEY:
                    params["apikey"] = ZAP_API_KEY
                resp = zap_api("/JSON/ascan/action/scan/", params=params)
                aid = resp.get("scan") if isinstance(resp, dict) else None
                active_ids.append(aid)
            JOB_STORE[our_id]["zap_ascan_ids"] = active_ids
            # Poll until scans finish (simple loop)
            finished = False
            while not finished:
                finished = True
                for aid in active_ids:
                    if not aid:
                        continue
                    status = zap_api("/JSON/ascan/view/status/", params={"scanId": aid})
                    pct = int(status.get("status") or 100)
                    JOB_STORE[our_id].setdefault("progress", {})[str(aid)] = pct
                    if pct < 100:
                        finished = False
                time.sleep(5)
            JOB_STORE[our_id]["status"] = "finished"
        except Exception as e:
            JOB_STORE[our_id]["status"] = f"error: {e}"
    threading.Thread(target=scan_worker, args=(our_scan_id, req.targets), daemon=True).start()
    return {"our_scan_id": our_scan_id, "zap_scan_ids": zap_scan_ids}

@app.get("/mcp/poll_zap/{our_scan_id}")
def poll_zap(our_scan_id: str):
    entry = JOB_STORE.get(our_scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No such scan")
    # Fetch alerts for each target
    findings = []
    for t in entry["targets"]:
        alerts = zap_api("/JSON/core/view/alerts/", params={"baseurl": f"https://{t}"})
        for a in alerts.get("alerts", []):
            fid = a.get("alertId") or str(uuid4())
            finding = {
                "id": fid,
                "name": a.get("alert"),
                "risk": a.get("risk"),
                "confidence": a.get("confidence"),
                "url": a.get("url"),
                "param": a.get("param"),
                "evidence": a.get("evidence"),
                "otherinfo": a.get("otherInfo"),
                "solution": a.get("solution"),
                "reference": a.get("reference"),
                "cweid": a.get("cweid"),
                "wascid": a.get("wascid"),
                "raw": a
            }
            findings.append(finding)
    # Save findings file
    out = os.path.join(OUTPUT_DIR, f"zap_findings_{our_scan_id}.json")
    with open(out, "w") as fh:
        json.dump(findings, fh, indent=2)
    return {"scan_id": our_scan_id, "count": len(findings), "findings_file": out}

@app.post("/mcp/run_ffuf")
def run_ffuf(req: FfufRequest):
    # ffuf must be installed. We'll call it with header injection.
    header_args = []
    headers = req.headers or {}
    headers["X-HackerOne-Research"] = H1_ALIAS
    for k,v in headers.items():
        header_args += ["-H", f"{k}: {v}"]
    rate = req.rate or int(MAX_REQ_PER_SEC)
    # Example ffuf usage: ffuf -u https://target/FUZZ -w wordlist -H "Header: value" -p 0
    output_file = os.path.join(OUTPUT_DIR, f"ffuf_{int(time.time())}.json")
    cmd = ["ffuf", "-u", req.target.replace("FUZZ", "FUZZ"), "-w", req.wordlist, "-t", str(rate), "-of", "json", "-o", output_file] + header_args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except FileNotFoundError:
        raise HTTPException(status_code=400, detail="ffuf not found. Install ffuf and ensure it's in PATH.")
    if p.returncode != 0:
        # still might have produced output; include stdout/stderr
        return {"status": "error", "returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    # parse output file if exists
    if os.path.exists(output_file):
        with open(output_file, "r") as fh:
            data = json.load(fh)
    else:
        data = {"stdout": p.stdout, "stderr": p.stderr}
    return {"cmd": cmd, "output": data, "file": output_file}

@app.post("/mcp/run_sqlmap")
def run_sqlmap(req: SqlmapRequest):
    # sqlmap must be installed. We'll call with --batch and headers
    headers = req.headers or {}
    headers["X-HackerOne-Research"] = H1_ALIAS
    header_str = "\\n".join([f"{k}: {v}" for k,v in headers.items()])
    output_dir = os.path.join(OUTPUT_DIR, f"sqlmap_{int(time.time())}")
    os.makedirs(output_dir, exist_ok=True)
    cmd = ["sqlmap", "-u", req.target, "--batch", "--output-dir", output_dir, "--headers", header_str]
    if req.data:
        cmd += ["--data", req.data]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except FileNotFoundError:
        raise HTTPException(status_code=400, detail="sqlmap not found. Install sqlmap and ensure it's in PATH.")
    return {"returncode": p.returncode, "stdout": p.stdout[:2000], "stderr": p.stderr[:2000], "output_dir": output_dir}

@app.post("/mcp/interactsh_new")
def interactsh_new():
    # Requires interactsh-client installed and in PATH (or use the env INTERACTSH_CLIENT)
    client = INTERACTSH_CLIENT or "interactsh-client"
    cmd = [client, "create", "--json"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except FileNotFoundError:
        raise HTTPException(status_code=400, detail="interactsh-client not found; set INTERACTSH_CLIENT or install it.")
    if p.returncode != 0:
        raise HTTPException(status_code=500, detail=f"interactsh create failed: {p.stderr}")
    try:
        data = json.loads(p.stdout)
    except Exception:
        raise HTTPException(status_code=500, detail="Could not parse interactsh output: " + p.stdout)
    # data should contain an 'id' and 'domain'
    return {"interact": data}

@app.get("/mcp/export_report/{scan_id}")
def export_report(scan_id: str):
    # Load findings file if present
    findings_path = os.path.join(OUTPUT_DIR, f"zap_findings_{scan_id}.json")
    if not os.path.exists(findings_path):
        raise HTTPException(status_code=404, detail="Findings file not found. Call /mcp/poll_zap first.")
    with open(findings_path, "r") as fh:
        findings = json.load(fh)
    reports = []
    for f in findings:
        md = generate_h1_markdown(SCOPE.program_name if SCOPE else "Program", f)
        fname = os.path.join(OUTPUT_DIR, f"{scan_id}_{f.get('id')}.md")
        with open(fname, "w") as of:
            of.write(md)
        reports.append(fname)
    index = os.path.join(OUTPUT_DIR, f"{scan_id}_reports_index.json")
    with open(index, "w") as fh:
        json.dump(reports, fh, indent=2)
    return {"reports": reports, "index": index}

# ========== report generation helpers ==========
def generate_h1_markdown(program: str, f: Dict[str, Any]) -> str:
    host = f.get("url") or "unknown"
    name = f.get("name") or f.get("alert") or "Finding"
    risk = f.get("risk") or "Medium"
    cwe = f.get("cweid") or "N/A"
    evidence = f.get("evidence") or f.get("otherinfo") or ""
    md = f"""# Vulnerability Report – {program}

**Target:** {host}  
**Vulnerability Type:** {name}  
**Severity (CVSS 3.0):** TBD ({risk})  
**Bounty Tier:** TBD

---

## Summary
A {name} vulnerability was identified on `{host}` within the authorized program scope.
The issue may allow an attacker to {shorten(evidence,200)}.

---

## Steps to Reproduce
1. Target: {host}
2. Observed: {shorten(evidence,400)}

**Evidence / Details:**

---

## Impact
{impact_guess_from_name(name)}

---

## Recommendation
{remediation_guess_from_name(name)}

---

**Scope Compliance:**  
All testing conducted against configured scope; header `X-HackerOne-Research: {H1_ALIAS}` used where possible.  
**Disclosure:** Private — do not disclose publicly without program consent.
"""
    return md

def shorten(s, n=400):
    if not s:
        return ""
    s = str(s)
    return s if len(s) <= n else s[:n] + "..."

def impact_guess_from_name(name: str):
    low = "Low-impact; likely informational or best-practice."
    name = name.lower()
    if "xss" in name: return "Client-side script injection: potential session theft, CSRF bypass, or user-targeted attacks."
    if "ssrf" in name: return "Server-side request forgery: may allow access to internal services or metadata services."
    if "sql" in name or "injection" in name: return "Database compromise or data exfiltration possible via SQL injection."
    if "rce" in name or "remote code" in name: return "Remote code execution; full system compromise possible."
    return low

def remediation_guess_from_name(name: str):
    name = name.lower()
    if "xss" in name: return "Sanitize and encode user-controlled output; implement CSP; review input handling."
    if "ssrf" in name: return "Implement allowlists, restrict URL schemes, and block internal address ranges."
    if "sql" in name: return "Use parameterized queries and ORM protections; validate input and escape where needed."
    if "rce" in name: return "Validate inputs, avoid unsafe eval/exec patterns, patch dependencies."
    return "Follow secure-coding best practices and fix per evidence."

# ========== startup ==========
if __name__ == "__main__":
    import uvicorn
    print("MCP ZAP server starting. Ensure ZAP is running (default http://localhost:8080).")
    uvicorn.run("mcp_zap_server:app", host="0.0.0.0", port=8100, reload=False)
