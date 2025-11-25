#!/usr/bin/env python3
# mcp_zap_server.py
"""
MCP-style starter server using free tooling:
- OWASP ZAP (API) for crawling + active scanning
- ffuf for fast fuzzing
- sqlmap for SQLi checks
- interactsh-client (optional) for OAST / blind callback tests

Features:
- /mcp/set_scope         -> upload scope (json)
- /mcp/start_zap_scan    -> start a ZAP spider + active scan (injects X-HackerOne-Research header)
- /mcp/run_ffuf          -> run ffuf on a target endpoint with header
- /mcp/run_sqlmap        -> run sqlmap on a target endpoint with header
- /mcp/poll_zap          -> poll ZAP for alerts and normalize
- /mcp/export_report     -> produce HackerOne markdown reports for alerts/findings

P0 add-ons (new):
- /mcp/run_js_miner      -> run JS/config miner as a background job
- /mcp/run_reflector     -> run parameter reflector tester as a background job
- /mcp/run_backup_hunt   -> run ffuf backup/VCS hunt as a background job
- /mcp/job/{id}          -> query background job status/results

Notes:
- Requires local ZAP running with API accessible (default http://localhost:8080).
- ffuf and sqlmap must be installed and in PATH for the ffuf/sqlmap endpoints.
- For interactsh usage, install the interactsh-client binary and provide path in config.
"""
import os
import sys
import json
import time
import subprocess
import threading
from typing import List, Dict, Any, Optional
from uuid import uuid4
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

def normalize_target(t: str) -> str:
    """Strip scheme, path, and port - keep only the hostname."""
    if "://" in t:
        u = urlparse(t)
        host = (u.netloc or u.path).split("/")[0]
    else:
        host = t.split("/")[0]
    return host.lower().strip().rstrip(".")


# ========== CONFIG ==========
ZAP_API_BASE = os.environ.get("ZAP_API_BASE", "http://localhost:8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")  # optional if ZAP requires it
H1_ALIAS = os.environ.get("H1_ALIAS", "h1yourusername@wearehackerone.com")
MAX_REQ_PER_SEC = float(os.environ.get("MAX_REQ_PER_SEC", "3.0"))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "./output_zap")
INTERACTSH_CLIENT = os.environ.get("INTERACTSH_CLIENT", "")  # optional: path to interactsh-client

os.makedirs(OUTPUT_DIR, exist_ok=True)
ARTIFACTS_DIR = os.path.join(OUTPUT_DIR, "artifacts")
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

# Curated nuclei recon template pack (high-value, low-noise)
NUCLEI_RECON_TEMPLATES: List[str] = [
    "technologies/",
    "ssl/",
    "http/exposed-panels/",
    "http/fingerprints/",
    "http/miscellaneous/",
    "exposures/apis/",
    "exposures/files/",
    "exposures/configs/",
    "exposures/logs/",
    "exposures/tokens/",
    "exposures/env/",
    "exposures/keys/",
    "http/auth-bypass/",
    "http/misconfig/cors/",
    "http/misconfig/backup/",
    "http/vulnerabilities/jwt/",
    "http/api/",
    "http/graphql/",
    "http/misconfig/openapi/",
    "cloud/metadata/",
    "cloud/firebase/",
    "default-logins/",
]

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


class NucleiRequest(BaseModel):
    """Request parameters for running a nuclei scan.

    This keeps things simple and CLI-aligned: you can specify a target URL or
    host, optional templates, severities, and tags. Results are written to a
    JSONL file and returned as structured data.
    """

    target: str
    templates: Optional[List[str]] = None
    severity: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    mode: Optional[str] = "recon"  # "recon" uses curated templates if none provided


class NucleiValidationRequest(BaseModel):
    """Simplified PoC validation request using nuclei.

    This is intended for LLM-driven PoC workflows: you provide a single target
    and one or more nuclei templates that represent the PoC. The server runs
    nuclei and returns a boolean `validated` flag plus a match count.
    """

    target: str
    templates: List[str]
    severity: Optional[List[str]] = None
    tags: Optional[List[str]] = None


class AuthConfig(BaseModel):
    """Per-host authentication configuration for ZAP scans.

    For P1 we keep this simple and header-based: provide a host and a set of
    headers (e.g. Authorization, Cookie) that ZAP should send on requests.
    """

    host: str
    type: str = "header"  # reserved for future auth types (forms, scripts, etc.)
    headers: Dict[str, str]

# in-memory stores
SCOPE: Optional[ScopeConfig] = None
JOB_STORE: Dict[str, Dict[str, Any]] = {}
ZAP_SCAN_IDS: Dict[str, str] = {}  # our_scan_id -> zap_scan_id
AUTH_CONFIGS: Dict[str, AuthConfig] = {}  # host -> auth configuration

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

def _build_auth_script_body() -> str:
    """Render a ZAP httpsender script that injects research + auth headers.

    The script maintains a simple per-host header map based on AUTH_CONFIGS.
    """

    # Build a JS object literal for authConfigs from AUTH_CONFIGS
    entries = []
    for host, cfg in AUTH_CONFIGS.items():
        header_entries = []
        for hk, hv in cfg.headers.items():
            # Basic escaping for quotes and backslashes
            safe_key = str(hk).replace("\\", "\\\\").replace("\"", "\\\"")
            safe_val = str(hv).replace("\\", "\\\\").replace("\"", "\\\"")
            header_entries.append(f'"{safe_key}": "{safe_val}"')
        headers_obj = ", ".join(header_entries)
        entries.append(f'"{host}": {{{headers_obj}}}')
    auth_map = ", ".join(entries)

    script_body = f"""
var authConfigs = {{{auth_map}}};

function sendingRequest(msg, initiator, helper) {{
    var headers = msg.getRequestHeader();
    var uri = msg.getRequestHeader().getURI();
    var host = uri.getHost();

    // Always add research header
    headers.setHeader("X-HackerOne-Research", "{H1_ALIAS}");

    // If we have auth config for this host, apply headers
    if (authConfigs[host]) {{
        var hmap = authConfigs[host];
        for (var key in hmap) {{
            if (hmap.hasOwnProperty(key)) {{
                headers.setHeader(key, hmap[key]);
            }}
        }}
    }}

    msg.setRequestHeader(headers);
}}

function responseReceived(msg, initiator, helper) {{
    // no-op
}}
"""
    return script_body


# Add / update a httpsender script to inject research + auth headers.
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
            # Best-effort update by removing and re-adding with latest config
            try:
                zap_api("/JSON/script/action/removeScript/", params={"scriptName": "h1_research_header"}, method="POST")
            except Exception:
                # If remove fails, continue and attempt to add new below
                pass
            break

    script_body = _build_auth_script_body()
    params = {
        "scriptName": "h1_research_header",
        "scriptType": "httpsender",
        "scriptEngine": "ECMAScript",
        "script": script_body,
    }
    try:
        zap_api("/JSON/script/action/addScript/", params=params, method="POST")
        return True
    except Exception as e:
        print("[!] Could not add ZAP header script:", e)
        return False

# ========== helpers ==========
def _scope_allowed_host(host_or_url: str) -> bool:
    if SCOPE is None:
        return False
    host = normalize_target(host_or_url)
    allowed = {normalize_target(x) for x in (SCOPE.primary_targets + SCOPE.secondary_targets)}
    return host in allowed

def _enforce_scope(host_or_url: str) -> str:
    if not _scope_allowed_host(host_or_url):
        raise HTTPException(status_code=400, detail=f"Target {normalize_target(host_or_url)} not in scope.")
    return normalize_target(host_or_url)

def _spawn_job(cmd_argv: List[str], job_kind: str, artifact_dir: Optional[str] = None) -> str:
    job_id = str(uuid4())
    JOB_STORE[job_id] = {
        "type": job_kind,
        "status": "started",
        "started_at": time.time(),
        "artifact_dir": artifact_dir,
        "cmd": cmd_argv,
    }
    def worker():
        try:
            if artifact_dir:
                os.makedirs(artifact_dir, exist_ok=True)
            p = subprocess.run(cmd_argv, capture_output=True, text=True, timeout=3600)
            JOB_STORE[job_id]["status"] = "finished" if p.returncode == 0 else f"error({p.returncode})"
            JOB_STORE[job_id]["result"] = {
                "returncode": p.returncode,
                "stdout": (p.stdout or "")[-4000:],
                "stderr": (p.stderr or "")[-4000:],
                "artifact_dir": artifact_dir
            }
        except subprocess.TimeoutExpired:
            JOB_STORE[job_id]["status"] = "timeout"
            JOB_STORE[job_id]["result"] = {"error": "timeout"}
        except Exception as e:
            JOB_STORE[job_id]["status"] = "error"
            JOB_STORE[job_id]["result"] = {"error": str(e)}
    threading.Thread(target=worker, daemon=True).start()
    return job_id


def summarize_nuclei_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Produce a lightweight PoC-oriented summary from nuclei findings.

    Each summary entry focuses on identifiers and a single matched location,
    which is easier for an LLM or UI to consume than the full nuclei JSON.
    """

    summaries: List[Dict[str, Any]] = []
    for f in findings:
        # Skip lines that were only captured as raw text
        if "raw" in f:
            continue

        info = f.get("info") or {}
        summaries.append(
            {
                "template_id": f.get("template-id") or f.get("id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "matched_at": f.get("matched-at") or f.get("host") or f.get("url"),
                "tags": info.get("tags", []),
            }
        )
    return summaries


def _load_nuclei_findings_for_host(host: str) -> List[Dict[str, Any]]:
    """Load all nuclei JSONL findings for a given host from OUTPUT_DIR.

    This is a best-effort helper: it scans nuclei_*.jsonl files, parses any
    JSON lines, and filters them where the matched host/URL appears to match
    the requested host. It is intentionally conservative to avoid coupling to
    nuclei internals.
    """

    host = normalize_target(host)
    findings: List[Dict[str, Any]] = []
    if not os.path.isdir(OUTPUT_DIR):
        return findings

    for name in os.listdir(OUTPUT_DIR):
        if not name.startswith("nuclei_") or not name.endswith(".jsonl"):
            continue
        path = os.path.join(OUTPUT_DIR, name)
        try:
            with open(path, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    matched = obj.get("matched-at") or obj.get("host") or obj.get("url")
                    if matched and normalize_target(str(matched)) == host:
                        findings.append(obj)
        except OSError:
            continue
    return findings


def _build_api_and_param_inventory_for_host(host: str) -> Dict[str, Any]:
    """Use ZAP core views to derive API-like endpoints and parameters for host.

    This function relies on ZAP having already crawled the host. It pulls the
    known URLs, then heuristically classifies API endpoints and extracts
    simple query parameter names for LLM triage.
    """

    host = normalize_target(host)
    api_endpoints: List[str] = []
    parameters: Dict[str, Dict[str, Any]] = {}

    try:
        sites_resp = zap_api("/JSON/core/view/sites/") or {}
    except HTTPException:
        sites_resp = {}
    sites = sites_resp.get("sites") or sites_resp.get("Sites") or []

    # If ZAP exposes a urls view, use that to pull concrete URLs
    urls: List[str] = []
    try:
        urls_resp = zap_api("/JSON/core/view/urls/") or {}
        urls = urls_resp.get("urls") or urls_resp.get("Urls") or []
    except HTTPException:
        # Fallback: sites list only
        urls = []

    def _is_api_like(url: str) -> bool:
        u = str(url).lower()
        return any(p in u for p in ["/api/", "/v1/", "/v2/", "/graphql", "/openapi", "/swagger"])

    from urllib.parse import urlparse, parse_qs

    for u in urls:
        try:
            parsed = urlparse(u)
        except Exception:
            continue
        if not parsed.netloc:
            continue
        if normalize_target(parsed.netloc) != host:
            continue

        full_url = u
        if _is_api_like(full_url):
            api_endpoints.append(full_url)

        qs = parse_qs(parsed.query or "")
        for pname in qs.keys():
            if pname not in parameters:
                parameters[pname] = {
                    "name": pname,
                    "locations": ["query"],
                    "example_url": full_url,
                }

    return {
        "api_endpoints": sorted(set(api_endpoints)),
        "parameters": sorted(parameters.values(), key=lambda x: x["name"]),
    }

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
    # Scope check
    allowed = {normalize_target(x) for x in (SCOPE.primary_targets + SCOPE.secondary_targets)}
    normalized_targets = [normalize_target(t) for t in req.targets]
    for t in normalized_targets:
        if t not in allowed:
            raise HTTPException(status_code=400, detail=f"Target {t} not in scope.")
    # Ensure header injection in ZAP via scripts (best-effort)
    ensure_zap_header_script()

    # Spider each target
    zap_scan_ids = []
    for t in normalized_targets:
        spider_resp = zap_api("/JSON/spider/action/scan/", params={"url": f"https://{t}", "maxChildren": 0})
        scanid = spider_resp.get("scan") if isinstance(spider_resp, dict) else None
        zap_scan_ids.append(scanid)

    # Start active scan in a background worker
    our_scan_id = str(uuid4())
    JOB_STORE[our_scan_id] = {"type": "zap", "targets": normalized_targets, "created": time.time(), "status": "started", "zap_ids": zap_scan_ids}
    def scan_worker(our_id, targets):
        try:
            time.sleep(5)  # allow spider to populate
            active_ids = []
            for t in targets:
                params = {"url": f"https://{t}"}
                if ZAP_API_KEY:
                    params["apikey"] = ZAP_API_KEY
                resp = zap_api("/JSON/ascan/action/scan/", params=params)
                aid = resp.get("scan") if isinstance(resp, dict) else None
                active_ids.append(aid)
            JOB_STORE[our_id]["zap_ascan_ids"] = active_ids
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
    threading.Thread(target=scan_worker, args=(our_scan_id, normalized_targets), daemon=True).start()
    return {"our_scan_id": our_scan_id, "zap_scan_ids": zap_scan_ids}


@app.post("/mcp/set_auth")
def set_auth(cfg: AuthConfig):
    """Set authentication configuration for a specific host.

    This is intentionally simple for P1: a host plus headers to send (e.g.
    Authorization, Cookie). We enforce that the host is in the current scope.
    """
    if SCOPE is None:
        raise HTTPException(status_code=400, detail="Scope not set. Call /mcp/set_scope first.")
    host = _enforce_scope(cfg.host)
    # Normalize and store
    normalized_cfg = AuthConfig(host=host, type=cfg.type, headers=cfg.headers)
    AUTH_CONFIGS[host] = normalized_cfg
    return {"status": "ok", "host": host, "type": normalized_cfg.type}


@app.post("/mcp/start_auth_scan")
def start_auth_scan(req: ZapScanRequest):
    """Start an authenticated ZAP scan.

    Behavior is currently identical to /mcp/start_zap_scan, but we additionally
    require that each target host has an AuthConfig registered. The actual
    header injection is handled by ZAP scripts (P1 focuses on control plane).
    """
    if SCOPE is None:
        raise HTTPException(status_code=400, detail="Scope not set. Call /mcp/set_scope first.")
    # Scope + auth check
    allowed = {normalize_target(x) for x in (SCOPE.primary_targets + SCOPE.secondary_targets)}
    normalized_targets = [normalize_target(t) for t in req.targets]
    for t in normalized_targets:
        if t not in allowed:
            raise HTTPException(status_code=400, detail=f"Target {t} not in scope.")
        if t not in AUTH_CONFIGS:
            # Fail fast on missing auth config before we talk to ZAP
            raise HTTPException(status_code=400, detail=f"No auth config set for host {t}. Call /mcp/set_auth first.")

    # Only after input is valid do we touch ZAP / scripts
    ensure_zap_header_script()

    zap_scan_ids = []
    for t in normalized_targets:
        spider_resp = zap_api("/JSON/spider/action/scan/", params={"url": f"https://{t}", "maxChildren": 0})
        scanid = spider_resp.get("scan") if isinstance(spider_resp, dict) else None
        zap_scan_ids.append(scanid)

    our_scan_id = str(uuid4())
    JOB_STORE[our_scan_id] = {
        "type": "zap-auth",
        "targets": normalized_targets,
        "created": time.time(),
        "status": "started",
        "zap_ids": zap_scan_ids,
        "auth_hosts": normalized_targets,
    }

    def scan_worker(our_id, targets):
        try:
            time.sleep(5)
            active_ids = []
            for t in targets:
                params = {"url": f"https://{t}"}
                if ZAP_API_KEY:
                    params["apikey"] = ZAP_API_KEY
                resp = zap_api("/JSON/ascan/action/scan/", params=params)
                aid = resp.get("scan") if isinstance(resp, dict) else None
                active_ids.append(aid)
            JOB_STORE[our_id]["zap_ascan_ids"] = active_ids
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

    threading.Thread(target=scan_worker, args=(our_scan_id, normalized_targets), daemon=True).start()
    return {"our_scan_id": our_scan_id, "zap_scan_ids": zap_scan_ids}

@app.get("/mcp/poll_zap/{our_scan_id}")
def poll_zap(our_scan_id: str):
    entry = JOB_STORE.get(our_scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No such scan")
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
    out = os.path.join(OUTPUT_DIR, f"zap_findings_{our_scan_id}.json")
    with open(out, "w") as fh:
        json.dump(findings, fh, indent=2)
    return {"scan_id": our_scan_id, "count": len(findings), "findings_file": out}

# ===== P0 background tool runners =====
@app.post("/mcp/run_js_miner")
def run_js_miner(body: Dict[str, Any]):
    base_url = body.get("base_url") or ""
    if not base_url:
        raise HTTPException(status_code=400, detail="base_url required")
    host = normalize_target(body.get("host") or base_url)
    _enforce_scope(host)
    subdir = body.get("subdir") or host
    outdir = os.path.join(ARTIFACTS_DIR, "js_miner", subdir)
    cmd = [sys.executable, "tools/js_miner.py", "--base-url", base_url, "--output", outdir]
    job_id = _spawn_job(cmd, job_kind="js_miner", artifact_dir=outdir)
    return {"job_id": job_id, "artifact_dir": outdir, "cmd": cmd}

@app.post("/mcp/run_reflector")
def run_reflector(body: Dict[str, Any]):
    url = body.get("url") or ""
    if not url:
        raise HTTPException(status_code=400, detail="url required")
    host = normalize_target(body.get("host") or url)
    _enforce_scope(host)
    subdir = body.get("subdir") or host
    outdir = os.path.join(ARTIFACTS_DIR, "reflector", subdir)
    cmd = [sys.executable, "tools/reflector_tester.py", "--url", url, "--output", outdir]
    job_id = _spawn_job(cmd, job_kind="reflector", artifact_dir=outdir)
    return {"job_id": job_id, "artifact_dir": outdir, "cmd": cmd}

@app.post("/mcp/run_backup_hunt")
def run_backup_hunt(body: Dict[str, Any]):
    target = body.get("target") or ""
    if not target:
        raise HTTPException(status_code=400, detail="target required")
    host = normalize_target(body.get("host") or target)
    _enforce_scope(host)
    subdir = body.get("subdir") or host
    outdir = os.path.join(ARTIFACTS_DIR, "backup_hunt", subdir)
    cmd = [sys.executable, "tools/backup_hunt.py", "--target", target, "--output", outdir]
    wordlist = body.get("wordlist")
    if wordlist:
        cmd += ["--wordlist", wordlist]
    job_id = _spawn_job(cmd, job_kind="backup_hunt", artifact_dir=outdir)
    return {"job_id": job_id, "artifact_dir": outdir, "cmd": cmd}

@app.get("/mcp/job/{job_id}")
def job_status(job_id: str):
    job = JOB_STORE.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="No such job")
    return {
        "job_id": job_id,
        "type": job.get("type"),
        "status": job.get("status"),
        "started_at": job.get("started_at"),
        "artifact_dir": job.get("artifact_dir"),
        "result": job.get("result", {}),
        "cmd": job.get("cmd"),
    }

@app.post("/mcp/run_ffuf")
def run_ffuf(req: FfufRequest):
    header_args = []
    headers = req.headers or {}
    headers["X-HackerOne-Research"] = H1_ALIAS
    for k, v in headers.items():
        header_args += ["-H", f"{k}: {v}"]
    rate = req.rate or int(MAX_REQ_PER_SEC)
    output_file = os.path.join(OUTPUT_DIR, f"ffuf_{int(time.time())}.json")
    cmd = ["ffuf", "-u", req.target.replace("FUZZ", "FUZZ"), "-w", req.wordlist, "-t", str(rate), "-of", "json", "-o", output_file] + header_args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except FileNotFoundError:
        raise HTTPException(status_code=400, detail="ffuf not found. Install ffuf and ensure it's in PATH.")
    if p.returncode != 0:
        return {"status": "error", "returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    if os.path.exists(output_file):
        with open(output_file, "r") as fh:
            data = json.load(fh)
    else:
        data = {"stdout": p.stdout, "stderr": p.stderr}
    return {"cmd": cmd, "output": data, "file": output_file}

@app.post("/mcp/run_sqlmap")
def run_sqlmap(req: SqlmapRequest):
    headers = req.headers or {}
    headers["X-HackerOne-Research"] = H1_ALIAS
    header_str = "\n".join([f"{k}: {v}" for k, v in headers.items()])
    output_dir = os.path.join(OUTPUT_DIR, f"sqlmap_{int(time.time())}")
    os.makedirs(output_dir, exist_ok=True)
    cmd = ["sqlmap", "-u", req.target, "--batch", "--output-dir", output_dir, "--headers", header_str, "--delay", str(1.0/MAX_REQ_PER_SEC)]
    if req.data:
        cmd += ["--data", req.data]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except FileNotFoundError:
        raise HTTPException(status_code=400, detail="sqlmap not found. Install sqlmap and ensure it's in PATH.")
    return {"returncode": p.returncode, "stdout": p.stdout[:2000], "stderr": p.stderr[:2000], "output_dir": output_dir}


@app.post("/mcp/run_nuclei")
def run_nuclei(req: NucleiRequest):
    """Run nuclei against a single target with optional templates/filters.

    This is a synchronous helper similar to run_ffuf/run_sqlmap; it enforces
    scope on the host, shells out to `nuclei`, and parses JSONL output (one
    JSON object per line) into a list of findings.
    """

    if not req.target:
        raise HTTPException(status_code=400, detail="target required")

    # Enforce that the host is in scope
    host = normalize_target(req.target)
    _enforce_scope(host)

    timestamp = int(time.time())
    output_file = os.path.join(OUTPUT_DIR, f"nuclei_{timestamp}.jsonl")

    cmd = ["nuclei", "-u", req.target, "-json", "-o", output_file]

    # Templates: use explicit list if provided, otherwise curated recon set for recon mode
    templates = req.templates
    if not templates and (req.mode or "recon") == "recon":
        templates = NUCLEI_RECON_TEMPLATES

    if templates:
        for t in templates:
            cmd += ["-t", t]
    if req.severity:
        cmd += ["-severity", ",".join(req.severity)]
    if req.tags:
        cmd += ["-tags", ",".join(req.tags)]

    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except FileNotFoundError:
        raise HTTPException(status_code=400, detail="nuclei not found. Install nuclei and ensure it's in PATH.")

    findings: List[Dict[str, Any]] = []
    if os.path.exists(output_file):
        with open(output_file, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except Exception:
                    # If a line cannot be parsed, include it as raw text
                    findings.append({"raw": line})
    else:
        # Fall back to stdout/stderr if file wasn't created
        findings.append({"stdout": p.stdout, "stderr": p.stderr})

    return {
        "cmd": cmd,
        "returncode": p.returncode,
        "file": output_file,
        "findings": findings,
    }


@app.post("/mcp/validate_poc_with_nuclei")
def validate_poc_with_nuclei(req: NucleiValidationRequest):
    """Validate a PoC by running nuclei with explicit templates.

    This is a thin wrapper over nuclei that is tailored for automated
    workflows. It always requires explicit templates (we do not apply the
    curated recon pack here) and returns a simple boolean `validated` flag
    alongside the raw nuclei findings.
    """

    if not req.target:
        raise HTTPException(status_code=400, detail="target required")
    if not req.templates:
        raise HTTPException(status_code=400, detail="at least one template is required")

    # Enforce that the host is in scope
    host = normalize_target(req.target)
    _enforce_scope(host)

    timestamp = int(time.time())
    output_file = os.path.join(OUTPUT_DIR, f"nuclei_validate_{timestamp}.jsonl")

    cmd = ["nuclei", "-u", req.target, "-json", "-o", output_file]

    # Always use the explicit templates passed in
    for t in req.templates:
        cmd += ["-t", t]
    if req.severity:
        cmd += ["-severity", ",".join(req.severity)]
    if req.tags:
        cmd += ["-tags", ",".join(req.tags)]

    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except FileNotFoundError:
        raise HTTPException(status_code=400, detail="nuclei not found. Install nuclei and ensure it's in PATH.")

    findings: List[Dict[str, Any]] = []
    if os.path.exists(output_file):
        with open(output_file, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except Exception:
                    findings.append({"raw": line})
    else:
        findings.append({"stdout": p.stdout, "stderr": p.stderr})

    match_count = len(findings)
    validated = match_count > 0

    return {
        "cmd": cmd,
        "returncode": p.returncode,
        "file": output_file,
        "findings": findings,
        "match_count": match_count,
        "validated": validated,
        "summaries": summarize_nuclei_findings(findings),
    }

@app.post("/mcp/interactsh_new")
def interactsh_new():
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
    return {"interact": data}

@app.get("/mcp/export_report/{scan_id}")
def export_report(scan_id: str):
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


@app.post("/mcp/host_profile")
def host_profile(body: Dict[str, Any]):
    """Aggregate recon data for a single host to help LLM triage.

    This endpoint pulls together best-effort signals from nuclei recon
    findings, ZAP URLs, and in-memory auth config to describe the attack
    surface of a host. It does not trigger new scans; it summarizes what we
    already know so far.
    """

    host_input = body.get("host") or body.get("target")
    if not host_input:
        raise HTTPException(status_code=400, detail="host is required")

    host = _enforce_scope(host_input)
    llm_view = bool(body.get("llm_view"))

    # Pull nuclei findings for this host and categorize them
    nuclei_all = _load_nuclei_findings_for_host(host)
    technologies: List[Dict[str, Any]] = []
    panels: List[Dict[str, Any]] = []
    exposures: List[Dict[str, Any]] = []
    auth_findings: List[Dict[str, Any]] = []
    api_related: List[Dict[str, Any]] = []

    def _add(cat_list: List[Dict[str, Any]], f: Dict[str, Any]):
        cat_list.append(
            {
                "template_id": f.get("template-id") or f.get("id"),
                "matched_at": f.get("matched-at") or f.get("host") or f.get("url"),
                "severity": (f.get("info") or {}).get("severity"),
                "name": (f.get("info") or {}).get("name"),
            }
        )

    for f in nuclei_all:
        tid = f.get("template-id") or ""
        # Template IDs often include their path; use simple prefix checks
        if "technologies/" in tid or "fingerprints/" in tid:
            _add(technologies, f)
        if "exposed-panels/" in tid or "default-logins/" in tid:
            _add(panels, f)
        if "exposures/" in tid or "cloud/" in tid:
            _add(exposures, f)
        if any(x in tid for x in ["auth-bypass/", "vulnerabilities/jwt/", "misconfig/cors/"]):
            _add(auth_findings, f)
        if any(x in tid for x in ["http/api/", "http/graphql/", "misconfig/openapi/"]):
            _add(api_related, f)

    # Derive API endpoints and parameter inventory from ZAP
    api_param = _build_api_and_param_inventory_for_host(host)

    # Include any configured auth headers for this host
    auth_cfg = AUTH_CONFIGS.get(host)
    auth_surface: Dict[str, Any] = {
        "has_auth_config": auth_cfg is not None,
        "auth_headers": sorted(list(auth_cfg.headers.keys())) if auth_cfg else [],
        "nuclei_findings": auth_findings,
    }

    full_profile = {
        "host": host,
        "technologies": technologies,
        "panels": panels,
        "exposures": exposures,
        "api_findings": api_related,
        "api_endpoints": api_param["api_endpoints"],
        "parameters": api_param["parameters"],
        "auth_surface": auth_surface,
    }

    if not llm_view:
        return full_profile

    # Build a compact, token-optimized view for LLM planning.
    def _names_from(findings: List[Dict[str, Any]]) -> List[str]:
        out: List[str] = []
        for f in findings:
            name = f.get("name") or f.get("template_id")
            sev = f.get("severity")
            if sev:
                out.append(f"{name} ({sev})")
            else:
                out.append(str(name))
        # Deduplicate while preserving order
        seen = set()
        uniq = []
        for x in out:
            if x in seen:
                continue
            seen.add(x)
            uniq.append(x)
        return uniq

    # Summarize parameters: only send a small sample of names.
    params = full_profile["parameters"]
    param_names = sorted({p.get("name") for p in params if p.get("name")})
    params_summary = {
        "count": len(param_names),
        "names_sample": param_names[:20],
    }

    # Summarize nuclei-like findings by category.
    llm_profile = {
        "host": host,
        "tech": _names_from(technologies),
        "key_panels": [p.get("matched_at") for p in panels][:10],
        "key_apis": [f.get("matched_at") for f in api_related][:20],
        "risky_exposures": _names_from(exposures)[:20],
        "params_summary": params_summary,
        "auth": {
            "headers": auth_surface["auth_headers"],
            "issues": _names_from(auth_surface["nuclei_findings"])[:10],
        },
    }

    return {"host": host, "llm_profile": llm_profile}

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
    print("MCP ZAP server starting. Ensure ZAP is running (default http://localhost:8080)."
    )
    uvicorn.run("mcp_zap_server:app", host="0.0.0.0", port=8100, reload=False)