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
- /mcp/start_zap_scan    -> start a ZAP spider + active scan
- /mcp/start_auth_scan   -> same but requires per-host auth config
- /mcp/poll_zap          -> poll ZAP for alerts and normalize
- /mcp/run_ffuf          -> run ffuf on a target endpoint
- /mcp/run_sqlmap        -> run sqlmap on a target endpoint
- /mcp/run_nuclei        -> run nuclei recon templates
- /mcp/validate_poc_with_nuclei -> PoC validation with nuclei
- /mcp/run_cloud_recon   -> lightweight cloud recon
- /mcp/host_profile      -> aggregate recon data per host
- /mcp/prioritize_host   -> compute risk score per host
- /mcp/host_delta        -> delta between current/previous host_profile
- /mcp/run_js_miner      -> JS/config miner (background job)
- /mcp/run_reflector     -> parameter reflector tester (background job)
- /mcp/run_backup_hunt   -> backup/VCS ffuf hunt (background job)
- /mcp/job/{id}          -> query background job status/results
- /mcp/run_katana_nuclei -> Katana + Nuclei web recon wrapper
- /mcp/export_report     -> HackerOne-style markdown reports

Notes:
- Requires ZAP accessible at ZAP_API_BASE (default http://localhost:8080).
- ffuf, sqlmap, nuclei, katana, interactsh-client must be in PATH where used.
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

# ---------- helpers ----------

def normalize_target(t: str) -> str:
    """Strip scheme, path, and port - keep only the hostname."""
    if "://" in t:
        u = urlparse(t)
        host = (u.netloc or u.path).split("/")[0]
    else:
        host = t.split("/")[0]
    return host.lower().strip().rstrip(".")

# ---------- CONFIG ----------

ZAP_API_BASE = os.environ.get("ZAP_API_BASE", "http://localhost:8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")
H1_ALIAS = os.environ.get("H1_ALIAS", "h1yourusername@wearehackerone.com")
MAX_REQ_PER_SEC = float(os.environ.get("MAX_REQ_PER_SEC", "3.0"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", os.path.join(BASE_DIR, "output_zap"))
os.makedirs(OUTPUT_DIR, exist_ok=True)

ARTIFACTS_DIR = os.path.join(OUTPUT_DIR, "artifacts")
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

HOST_HISTORY_DIR = os.path.join(OUTPUT_DIR, "host_history")
os.makedirs(HOST_HISTORY_DIR, exist_ok=True)

# Curated nuclei recon template pack
_NUCLEI_RECON_RELATIVE: List[str] = [
    "technologies/",
    "ssl/",
    "http/exposed-panels/",
    "http/fingerprints/",
    "exposures/files/",
    "exposures/configs/",
]

NUCLEI_TEMPLATES_DIR = os.environ.get("NUCLEI_TEMPLATES_DIR", "").strip()
if NUCLEI_TEMPLATES_DIR:
    NUCLEI_RECON_TEMPLATES: List[str] = [
        os.path.join(NUCLEI_TEMPLATES_DIR, p) for p in _NUCLEI_RECON_RELATIVE
    ]
else:
    NUCLEI_RECON_TEMPLATES: List[str] = list(_NUCLEI_RECON_RELATIVE)

# ---------- simple rate limiter ----------

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

# ---------- Models & FastAPI app ----------

app = FastAPI(title="MCP ZAP + Katana/Nuclei Server")

class BacChecksRequest(BaseModel):
    host: str
    url: Optional[str] = None

class ScopeConfig(BaseModel):
    program_name: str
    primary_targets: List[str]
    secondary_targets: List[str]
    rules: Dict[str, Any] = {}

class ZapScanRequest(BaseModel):
    targets: List[str]
    context_name: Optional[str] = "Default Context"
    scan_policy_name: Optional[str] = None

class FfufRequest(BaseModel):
    target: str
    wordlist: str
    headers: Optional[Dict[str, str]] = None
    rate: Optional[int] = None

class SqlmapRequest(BaseModel):
    target: str
    data: Optional[str] = None
    headers: Optional[Dict[str, str]] = None

class SsrfChecksRequest(BaseModel):
    target: str  # full URL the application will fetch from
    param: Optional[str] = None  # query/body parameter carrying the URL, if applicable

class NucleiRequest(BaseModel):
    target: str
    templates: Optional[List[str]] = None
    severity: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    mode: Optional[str] = "recon"

class NucleiValidationRequest(BaseModel):
    target: str
    templates: List[str]
    severity: Optional[List[str]] = None
    tags: Optional[List[str]] = None

class AuthConfig(BaseModel):
    host: str
    type: str = "header"
    headers: Dict[str, str]

class CloudReconRequest(BaseModel):
    host: str

class KatanaNucleiRequest(BaseModel):
    target: str  # full URL
    output_name: Optional[str] = None

class KatanaNucleiResult(BaseModel):
    target: str
    katana_count: int
    findings_file: str
    findings_count: int

class ApiReconRequest(BaseModel):
    host: str

class ApiReconResult(BaseModel):
    host: str
    endpoints_count: int
    findings_file: str

# ---------- in-memory stores ----------

SCOPE: Optional[ScopeConfig] = None
JOB_STORE: Dict[str, Dict[str, Any]] = {}
ZAP_SCAN_IDS: Dict[str, str] = {}
AUTH_CONFIGS: Dict[str, AuthConfig] = {}

# ---------- ZAP helpers ----------

def zap_api(endpoint_path: str, params: Dict[str, Any] = None, method: str = "GET", json_body: Any = None):
    if params is None:
        params = {}
    if ZAP_API_KEY:
        params["apikey"] = ZAP_API_KEY
    url = ZAP_API_BASE.rstrip("/") + endpoint_path
    rate_limit_wait()

    if endpoint_path == "/JSON/ascan/action/scan/":
        print(f"[DEBUG] ZAP ascan call: {url} params={params}", file=sys.stderr)

    try:
        if method.upper() == "GET":
            r = requests.get(url, params=params, timeout=60)
        else:
            # actions expect form-encoded
            r = requests.post(url, data=params, timeout=60)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error contacting ZAP at {url}: {e}")
    if r.status_code >= 400:
        raise HTTPException(status_code=r.status_code, detail=f"ZAP API error {r.status_code}: {r.text}")
    try:
        return r.json()
    except ValueError:
        return r.text

def _build_auth_script_body() -> str:
    entries = []
    for host, cfg in AUTH_CONFIGS.items():
        header_entries = []
        for hk, hv in cfg.headers.items():
            safe_key = str(hk).replace("\\", "\\\\").replace("\"", "\\\"")
            safe_val = str(hv).replace("\\", "\\\\").replace("\"", "\\\"")
            header_entries.append(f'"{safe_key}": "{safe_val}"')
        headers_obj = ", ".join(header_entries)
        entries.append(f'"{host}": {{{headers_obj}}}')
    auth_map = ", ".join(entries)
    return f"""
var authConfigs = {{{auth_map}}};

function sendingRequest(msg, initiator, helper) {{
    var headers = msg.getRequestHeader();
    var uri = msg.getRequestHeader().getURI();
    var host = uri.getHost();
    headers.setHeader("X-HackerOne-Research", "{H1_ALIAS}");
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
}}
"""

def ensure_zap_header_script():
    try:
        scripts = zap_api("/JSON/script/view/listScripts/")
    except Exception:
        # If script API not available, skip silently
        return False
    for s in scripts.get("scripts", []):
        if s.get("name") == "h1_research_header":
            try:
                zap_api("/JSON/script/action/removeScript/", params={"scriptName": "h1_research_header"}, method="POST")
            except Exception:
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

# ---------- scope helpers ----------

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


# ---------- background job helpers ----------

def _spawn_job(cmd_argv: List[str], job_kind: str, artifact_dir: str) -> str:
    """Spawn a background job and track it in JOB_STORE.

    This is intentionally simple: it runs the given command in a thread,
    captures stdout/stderr to files in ``artifact_dir``, and records
    basic status so callers can poll via /mcp/job/{id}.
    """

    os.makedirs(artifact_dir, exist_ok=True)

    job_id = str(uuid4())
    stdout_path = os.path.join(artifact_dir, f"{job_id}.out.log")
    stderr_path = os.path.join(artifact_dir, f"{job_id}.err.log")

    JOB_STORE[job_id] = {
        "id": job_id,
        "kind": job_kind,
        "cmd": cmd_argv,
        "artifact_dir": artifact_dir,
        "status": "queued",
        "stdout": stdout_path,
        "stderr": stderr_path,
        "returncode": None,
    }

    def _runner():
        JOB_STORE[job_id]["status"] = "running"
        try:
            with open(stdout_path, "w", encoding="utf-8") as so, open(
                stderr_path, "w", encoding="utf-8"
            ) as se:
                proc = subprocess.run(
                    cmd_argv,
                    cwd=os.path.dirname(__file__),
                    stdout=so,
                    stderr=se,
                    text=True,
                )
            JOB_STORE[job_id]["returncode"] = proc.returncode
            JOB_STORE[job_id]["status"] = "finished" if proc.returncode == 0 else "error"
        except Exception as e:
            JOB_STORE[job_id]["status"] = "error"
            JOB_STORE[job_id]["error"] = str(e)

    t = threading.Thread(target=_runner, daemon=True)
    t.start()

    return job_id

@app.post("/mcp/run_js_miner")
def run_js_miner(body: Dict[str, Any]):
    """Kick off a JS/config miner job for a given base URL.

    This is a thin MCP wrapper around ``tools/js_miner.py`` that
    enforces scope, spawns a background job, and returns a job id
    plus the artifact directory where results will be written.
    """

    base_url = body.get("base_url") or body.get("url")
    if not base_url:
        raise HTTPException(status_code=400, detail="Missing 'base_url' in request body.")

    host = _enforce_scope(base_url)

    artifact_dir = os.path.join(ARTIFACTS_DIR, "js_miner", host)

    script_path = os.path.join(os.path.dirname(__file__), "tools", "js_miner.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=500, detail=f"js_miner.py not found at {script_path}")

    cmd = [
        sys.executable,
        script_path,
        "--base-url",
        base_url,
        "--output-dir",
        artifact_dir,
    ]

    job_id = _spawn_job(cmd, job_kind="js_miner", artifact_dir=artifact_dir)
    return {"job_id": job_id, "artifact_dir": artifact_dir}


@app.post("/mcp/run_backup_hunt")
def run_backup_hunt(body: Dict[str, Any]):
    """Kick off a backup/VCS file hunter for a given base URL.

    This runs tools/backup_hunt.py in the background against a single
    base URL, looking for common backup/config artifacts.
    """

    base_url = body.get("base_url") or body.get("url")
    if not base_url:
        raise HTTPException(status_code=400, detail="Missing 'base_url' in request body.")

    host = _enforce_scope(base_url)

    artifact_dir = os.path.join(ARTIFACTS_DIR, "backup_hunt", host)

    script_path = os.path.join(os.path.dirname(__file__), "tools", "backup_hunt.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=500, detail=f"backup_hunt.py not found at {script_path}")

    cmd = [
        sys.executable,
        script_path,
        "--base-url",
        base_url,
        "--output-dir",
        artifact_dir,
    ]

    job_id = _spawn_job(cmd, job_kind="backup_hunt", artifact_dir=artifact_dir)
    return {"job_id": job_id, "artifact_dir": artifact_dir}


@app.get("/mcp/job/{job_id}")
def get_job(job_id: str):
    job = JOB_STORE.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job

# ---------- Katana + Nuclei MCP endpoint ----------

@app.post("/mcp/run_katana_nuclei", response_model=KatanaNucleiResult)
def run_katana_nuclei(req: KatanaNucleiRequest):
    """
    Run Katana + Nuclei recon via tools/katana_nuclei_recon.py for a single target.
    Returns a path to a JSON file containing nuclei findings and the count.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    host_key = req.target.replace("://", "_").replace("/", "_")
    out_name = req.output_name or f"katana_nuclei_{host_key}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)

    script_path = os.path.join(os.path.dirname(__file__), "tools", "katana_nuclei_recon.py")
    if not os.path.exists(script_path):
        raise HTTPException(
            status_code=500,
            detail=f"katana_nuclei_recon.py not found at {script_path}",
        )

    env = os.environ.copy()
    env.setdefault("OUTPUT_DIR", OUTPUT_DIR)

    cmd = [
        sys.executable,
        script_path,
        "--target",
        req.target,
        "--output",
        out_name,
    ]

    rate_limit_wait()
    try:
        proc = subprocess.run(
            cmd,
            env=env,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=3600,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running katana+nuclei: {e}")

    if proc.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail=f"katana_nuclei_recon.py failed: {proc.stderr.strip()}",
        )

    if not os.path.exists(out_path):
        raise HTTPException(
            status_code=500,
            detail=f"Expected output file not found: {out_path}",
        )

    with open(out_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    findings = data.get("nuclei_findings", [])
    findings_file = os.path.join(
        OUTPUT_DIR,
        os.path.splitext(out_name)[0] + "_findings.json",
    )
    with open(findings_file, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)

    return KatanaNucleiResult(
        target=req.target,
        katana_count=data.get("katana", {}).get("count", 0),
        findings_file=findings_file,
        findings_count=len(findings),
    )

@app.post("/mcp/host_profile")
def host_profile(req: CloudReconRequest):
    """
    Build or update a host profile from recon outputs (cloud, web, etc.).
    """
    host = _enforce_scope(req.host)

    profile: Dict[str, Any] = {
        "host": host,
        "created": time.time(),
        "cloud": {},
        "web": {},
    }

    # --- existing: load cloud findings, nuclei, etc. (if you have any here) ---

    # --- Katana HTTP surface ingestion ---
    katana_prefix = "katana_nuclei_"
    katana_files = [
        f for f in os.listdir(OUTPUT_DIR)
        if f.startswith(katana_prefix)
    ]

    all_urls: List[str] = []
    api_endpoints: List[Dict[str, Any]] = []

    for fname in katana_files:
        kpath = os.path.join(OUTPUT_DIR, fname)
        try:
            with open(kpath, "r", encoding="utf-8") as fh:
                kdata = json.load(fh)
        except Exception:
            continue

        target = kdata.get("target", "") or ""
        # crude match: host (e.g., "localhost:3000") must appear in target URL
        if host not in target:
            continue

        kat = kdata.get("katana", {}) or {}
        all_urls.extend(kat.get("all_urls", []) or [])
        api_endpoints.extend(kat.get("api_candidates", []) or [])

    if all_urls:
        profile["web"]["urls"] = sorted(set(all_urls))

    if api_endpoints:
        profile["web"]["api_endpoints"] = api_endpoints

    # --- Backup hunter ingestion ---
    backup_dir = os.path.join(ARTIFACTS_DIR, "backup_hunt", host)
    backups_exposed: list[Dict[str, Any]] = []
    if os.path.isdir(backup_dir):
        for fname in os.listdir(backup_dir):
            if not fname.endswith("_results.json") and not fname.endswith("backup_hunt_results.json"):
                continue
            fpath = os.path.join(backup_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception:
                continue
            for hit in data.get("hits", []) or []:
                if isinstance(hit, dict):
                    backups_exposed.append(hit)

    if backups_exposed:
        profile.setdefault("web", {})["backups"] = {
            "count": len(backups_exposed),
            "samples": backups_exposed[:20],
        }

    # Save snapshot
    _save_host_profile_snapshot(host, profile)
    return profile

@app.post("/mcp/host_delta")
def host_delta(req: CloudReconRequest):
    """
    Compute delta between current and previous host_profile snapshots.
    """
    host = _enforce_scope(req.host)

    current = _load_host_profile_snapshot(host, latest=True)
    previous = _load_host_profile_snapshot(host, latest=False)

    if not current or not previous:
        raise HTTPException(
            status_code=404,
            detail="Not enough history for host delta (need at least 2 snapshots).",
        )

    delta: Dict[str, Any] = {
        "host": host,
        "current_ts": current.get("created"),
        "previous_ts": previous.get("created"),
    }

    curr_web = current.get("web", {}) or {}
    prev_web = previous.get("web", {}) or {}

    curr_urls = set(curr_web.get("urls", []) or [])
    prev_urls = set(prev_web.get("urls", []) or [])

    urls_added = sorted(curr_urls - prev_urls)
    urls_removed = sorted(prev_urls - curr_urls)

    def _api_key(e: Dict[str, Any]) -> tuple:
        return (e.get("url"), (e.get("method") or "GET").upper())

    curr_api_raw = curr_web.get("api_endpoints", []) or []
    prev_api_raw = prev_web.get("api_endpoints", []) or []

    curr_api_set = {_api_key(e) for e in curr_api_raw if e.get("url")}
    prev_api_set = {_api_key(e) for e in prev_api_raw if e.get("url")}

    api_added = sorted(curr_api_set - prev_api_set)
    api_removed = sorted(prev_api_set - curr_api_set)

    delta["web"] = {
        "urls_added": urls_added,
        "urls_removed": urls_removed,
        "api_endpoints_added": [
            {"url": u, "method": m} for (u, m) in api_added
        ],
        "api_endpoints_removed": [
            {"url": u, "method": m} for (u, m) in api_removed
        ],
    }

    return delta

# ---------- startup ----------

@app.post("/mcp/run_api_recon", response_model=ApiReconResult)
def run_api_recon(req: ApiReconRequest):
    """
    Basic API recon over host_profile.web.api_endpoints:
    - GET + OPTIONS on each endpoint
    - Capture status codes, Allow header, and basic auth behavior.
    """
    host = _enforce_scope(req.host)

    # 1) Require existing snapshot
    profile = _load_host_profile_snapshot(host, latest=True)
    if not profile:
        raise HTTPException(status_code=404, detail="No host_profile snapshot found for host")

    web = profile.get("web", {}) or {}
    api_endpoints = web.get("api_endpoints", []) or []

    # 2) Require at least one API endpoint
    if not api_endpoints:
        raise HTTPException(status_code=404, detail="No api_endpoints in host_profile for host")

    probes: List[Dict[str, Any]] = []

    for ep in api_endpoints:
        url = ep.get("url")
        method = (ep.get("method") or "GET").upper()
        if not url:
            continue

        probe: Dict[str, Any] = {
            "url": url,
            "method": method,
            "status_get": None,
            "status_options": None,
            "allow_header": None,
            "requires_auth": None,
            "notes": None,
        }

        # GET
        try:
            rate_limit_wait()
            resp_get = requests.get(url, timeout=15)
            probe["status_get"] = resp_get.status_code
            if resp_get.status_code in (401, 403):
                probe["requires_auth"] = True
        except Exception as e:
            probe["notes"] = f"GET error: {e}"

        # OPTIONS
        try:
            rate_limit_wait()
            resp_opt = requests.options(url, timeout=15)
            probe["status_options"] = resp_opt.status_code
            allow = resp_opt.headers.get("Allow")
            if allow:
                probe["allow_header"] = allow
        except Exception as e:
            prev_notes = probe.get("notes") or ""
            suffix = f"; OPTIONS error: {e}" if prev_notes else f"OPTIONS error: {e}"
            probe["notes"] = (prev_notes + suffix).strip("; ")

        probes.append(probe)

    ts = int(time.time())
    out_name = f"api_recon_{host.replace(':', '_')}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(probes, fh, indent=2)

    return ApiReconResult(
        host=host,
        endpoints_count=len(probes),
        findings_file=out_path,
    )

# ---------- host history snapshots ----------

HOST_HISTORY_DIR = os.path.join(OUTPUT_DIR, "host_history")
os.makedirs(HOST_HISTORY_DIR, exist_ok=True)


def _host_history_dir() -> str:
    d = os.path.join(OUTPUT_DIR, "host_history")
    os.makedirs(d, exist_ok=True)
    return d


def _host_history_path(host: str, ts: int) -> str:
    base = host.replace(":", "_")
    return os.path.join(_host_history_dir(), f"{base}_{ts}.json")


def _save_host_profile_snapshot(host: str, profile: Dict[str, Any]) -> None:
    ts = int(profile.get("created") or time.time())
    path = _host_history_path(host, ts)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(profile, fh, indent=2)


def _load_host_profile_snapshot(host: str, latest: bool = True) -> Optional[Dict[str, Any]]:
    base = host.replace(":", "_")
    hist_dir = _host_history_dir()
    try:
        files = [
            f
            for f in os.listdir(hist_dir)
            if f.startswith(base + "_") and f.endswith(".json")
        ]
    except FileNotFoundError:
        return None

    if not files:
        return None

    files.sort()
    fname = files[-1] if latest else files[0]
    path = os.path.join(hist_dir, fname)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None

if __name__ == "__main__":
    import uvicorn
    print("MCP ZAP server starting. Ensure ZAP is running (default http://localhost:8080).")
    uvicorn.run("mcp_zap_server:app", host="0.0.0.0", port=8100, reload=False)
