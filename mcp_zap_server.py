#!/usr/bin/env python3
# mcp_server.py
"""MCP-style starter server using free tooling (no ZAP dependency).

Features:
- /mcp/set_scope         -> upload scope (json)
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
- /mcp/run_katana_auth   -> Dev-mode authenticated Katana via browser session
- /mcp/run_fingerprints  -> WhatWeb-style technology fingerprinting (local binary)
- /mcp/run_whatweb       -> WhatWeb fingerprinting via Docker with JSON output
- /mcp/run_api_recon     -> lightweight API surface probing
- /mcp/triage_nuclei_templates -> AI-driven template selection based on host_profile
- /mcp/run_targeted_nuclei     -> Run Nuclei with AI-selected templates

Notes:
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

H1_ALIAS = os.environ.get("H1_ALIAS", "h1yourusername@wearehackerone.com")
MAX_REQ_PER_SEC = float(os.environ.get("MAX_REQ_PER_SEC", "3.0"))

# Docker network for running external tool containers (katana, whatweb, etc.)
DOCKER_NETWORK = os.environ.get("DOCKER_NETWORK", "agentic-bugbounty_lab_network")

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

app = FastAPI(title="MCP Server (Katana/Nuclei, Recon)")

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


class KatanaAuthRequest(BaseModel):
    target: str  # full URL of authenticated app (e.g. https://example.com)
    session_ws_url: Optional[str] = None  # DevTools WebSocket URL (dev mode)
    output_name: Optional[str] = None


class KatanaAuthResult(BaseModel):
    target: str
    output_file: str
    auth_katana_count: int


class FingerprintRequest(BaseModel):
    target: str  # full URL


class FingerprintResult(BaseModel):
    target: str
    output_file: str
    technologies: List[str]

class ApiReconRequest(BaseModel):
    host: str

class ApiReconResult(BaseModel):
    host: str
    endpoints_count: int
    findings_file: str


class NucleiTriageRequest(BaseModel):
    host: str
    use_llm: bool = True  # Whether to use LLM for intelligent selection


class NucleiTriageResult(BaseModel):
    host: str
    mode: str  # "recon" or "targeted"
    templates: List[str]
    tags: List[str]
    exclude_tags: List[str]
    severity_filter: List[str]
    reasoning: str


class TargetedNucleiRequest(BaseModel):
    target: str  # Full URL to scan
    templates: List[str]  # Template paths/directories to use
    tags: Optional[List[str]] = None  # Optional tags to filter
    exclude_tags: Optional[List[str]] = None  # Tags to exclude
    severity: Optional[List[str]] = None  # Severity filter


class TargetedNucleiResult(BaseModel):
    target: str
    findings_count: int
    findings_file: str
    templates_used: int


class WhatWebRequest(BaseModel):
    target: str  # Full URL to fingerprint


class WhatWebResult(BaseModel):
    target: str
    output_file: str
    technologies: List[str]
    raw_plugins: Dict[str, Any]


# ---------- in-memory stores ----------

SCOPE: Optional[ScopeConfig] = None
JOB_STORE: Dict[str, Dict[str, Any]] = {}
AUTH_CONFIGS: Dict[str, AuthConfig] = {}

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


@app.post("/mcp/set_scope")
def set_scope(cfg: ScopeConfig):
    """Upload scope configuration used by _enforce_scope.

    Stores the ScopeConfig in-memory so later calls to endpoints that
    enforce scope (e.g., js_miner, backup_hunt, katana, auth, etc.)
    will accept only hosts listed in primary_targets/secondary_targets.
    """

    global SCOPE
    SCOPE = cfg
    return {"status": "ok", "program_name": cfg.program_name}


@app.post("/mcp/set_auth")
def set_auth(cfg: AuthConfig):
    """Register per-host auth configuration (currently header-based).

    This enforces that the host is within the current scope and stores
    auth configs in-memory for use by host_profile auth surface.
    """

    host = _enforce_scope(cfg.host)
    AUTH_CONFIGS[host] = AuthConfig(host=host, type=cfg.type, headers=cfg.headers)
    return {"status": "ok", "host": host}


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

# ---------- Katana (unauth + auth) + Fingerprinting MCP endpoints ----------

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


@app.post("/mcp/run_katana_auth", response_model=KatanaAuthResult)
def run_katana_auth(req: KatanaAuthRequest):
    """Dev-mode: run authenticated Katana helper against a live browser session.

    This is intentionally minimal for development:
    - Assumes the user has an existing Chrome instance with DevTools enabled
      and an authenticated session for the target.
    - Delegates to tools/katana_auth_helper.py which is responsible for
      talking to DevTools, extracting requests, and writing a JSON artifact.
    """

    target = _enforce_scope(req.target)

    # Derive host key and output path under ARTIFACTS_DIR/katana_auth/<host>/
    host_key = target.replace("://", "_").replace("/", "_")
    base_dir = os.path.join(ARTIFACTS_DIR, "katana_auth", host_key)
    os.makedirs(base_dir, exist_ok=True)

    out_name = req.output_name or f"katana_auth_{host_key}.json"
    out_path = os.path.join(base_dir, out_name)

    script_path = os.path.join(os.path.dirname(__file__), "tools", "katana_auth_helper.py")
    if not os.path.exists(script_path):
        raise HTTPException(
            status_code=500,
            detail=f"katana_auth_helper.py not found at {script_path}",
        )

    env = os.environ.copy()
    env.setdefault("OUTPUT_DIR", OUTPUT_DIR)
    env.setdefault("ARTIFACTS_DIR", ARTIFACTS_DIR)

    cmd = [
        sys.executable,
        script_path,
        "--target",
        target,
        "--output",
        out_path,
    ]

    if req.session_ws_url:
        cmd.extend(["--ws-url", req.session_ws_url])

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
        raise HTTPException(status_code=500, detail=f"Error running katana_auth_helper.py: {e}")

    if proc.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail=f"katana_auth_helper.py failed: {proc.stderr.strip()}",
        )

    if not os.path.exists(out_path):
        raise HTTPException(
            status_code=500,
            detail=f"Expected output file not found: {out_path}",
        )

    try:
        with open(out_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load katana_auth_helper output: {e}")

    urls = data.get("urls") or []

    return KatanaAuthResult(
        target=target,
        output_file=out_path,
        auth_katana_count=len(urls),
    )


def _run_whatweb_internal(target: str) -> Optional[Dict[str, Any]]:
    """Internal helper to run WhatWeb via Docker and return parsed results.
    
    Used by both /mcp/run_fingerprints and auto-trigger in host_profile.
    Returns dict with 'technologies' list and 'plugins' dict, or None on failure.
    """
    cmd = [
        "docker", "run", "--rm",
        "--network", DOCKER_NETWORK,
        "morningstar/whatweb:latest",
        "-v",
        target,
    ]
    
    try:
        proc = subprocess.run(
            cmd,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as e:
        print(f"[WHATWEB] Error running Docker: {e}", file=sys.stderr)
        return None
    
    if proc.returncode != 0:
        print(f"[WHATWEB] Non-zero exit: {proc.stderr or proc.stdout}", file=sys.stderr)
    
    # Parse technologies from output
    technologies: List[str] = []
    plugins: Dict[str, Any] = {}
    
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(" ")
        if not parts:
            continue
        for token in parts[1:]:
            if "[" in token and "]" in token:
                tech = token.split("[", 1)[0]
                if tech:
                    technologies.append(tech)
                    # Extract version if present
                    version_part = token.split("[", 1)[1].rstrip("]")
                    if version_part:
                        plugins[tech] = {"version": version_part}
    
    return {
        "technologies": technologies,
        "plugins": plugins,
        "raw_output": proc.stdout,
    }


@app.post("/mcp/run_fingerprints", response_model=FingerprintResult)
def run_fingerprints(req: FingerprintRequest):
    """Run basic technology fingerprinting using WhatWeb via Docker.

    Runs WhatWeb in a Docker container connected to DOCKER_NETWORK,
    writes raw output under ARTIFACTS_DIR/fingerprints/<host>/, then 
    parses a simple technology list when possible.
    """

    target = _enforce_scope(req.target)

    host_key = target.replace("://", "_").replace("/", "_")
    base_dir = os.path.join(ARTIFACTS_DIR, "fingerprints", host_key)
    os.makedirs(base_dir, exist_ok=True)

    ts = int(time.time())
    out_name = f"whatweb_{ts}.txt"
    out_path = os.path.join(base_dir, out_name)

    # Use Docker to run whatweb, connected to the lab network
    cmd = [
        "docker", "run", "--rm",
        "--network", DOCKER_NETWORK,
        "morningstar/whatweb:latest",
        "-v",
        target,
    ]

    rate_limit_wait()
    try:
        proc = subprocess.run(
            cmd,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Docker not found - required for WhatWeb fingerprinting")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running fingerprints: {e}")

    # Always write raw stdout/stderr for later inspection
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(proc.stdout)
        if proc.stderr:
            fh.write("\n\n# stderr:\n")
            fh.write(proc.stderr)

    if proc.returncode != 0:
        # We still return the artifact, but note that exit code was non-zero.
        raise HTTPException(
            status_code=500,
            detail=f"Fingerprinting tool failed (exit {proc.returncode}); see {out_path}",
        )

    # Heuristic parse: WhatWeb default output is of form:
    #   http://example.com [200 OK] Country[United States] HTTPServer[nginx]
    technologies: List[str] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(" ")
        if not parts:
            continue
        # Everything after the first token is a plugin-like label
        for token in parts[1:]:
            if "[" in token and "]" in token:
                tech = token.split("[", 1)[0]
                if tech:
                    technologies.append(tech)

    return FingerprintResult(
        target=target,
        output_file=out_path,
        technologies=sorted(sorted(set(technologies))),
    )


@app.post("/mcp/run_whatweb", response_model=WhatWebResult)
def run_whatweb(req: WhatWebRequest):
    """Run WhatWeb fingerprinting via Docker with structured JSON output.

    This endpoint runs WhatWeb in a Docker container and parses the JSON output
    to extract technology fingerprints. Results are stored in artifacts/fingerprints/<host>/
    and can be consumed by host_profile and AI triage.
    """
    # Validate target is in scope and get normalized hostname
    validated_host = _enforce_scope(req.target)

    # Reconstruct a safe URL using only the validated hostname
    # This prevents parser differential attacks where req.target could bypass scope
    parsed = urlparse(req.target)
    scheme = parsed.scheme or "http"
    # Use validated_host (not parsed.netloc) to ensure we scan what we validated
    safe_target = f"{scheme}://{validated_host}"
    if parsed.port and parsed.port not in (80, 443):
        safe_target = f"{scheme}://{validated_host}:{parsed.port}"

    host_key = validated_host.replace("://", "_").replace("/", "_")
    base_dir = os.path.join(ARTIFACTS_DIR, "fingerprints", host_key)
    os.makedirs(base_dir, exist_ok=True)

    ts = int(time.time())
    out_name = f"whatweb_{ts}.json"
    out_path = os.path.join(base_dir, out_name)

    # Run WhatWeb via Docker with JSON output
    # Use safe_target (reconstructed from validated components) to prevent scope bypass
    cmd = [
        "docker", "run", "--rm", "--network", DOCKER_NETWORK,
        "morningstar/whatweb:latest",
        "-a", "3",  # Aggression level 3 (stealthy)
        "--log-json=-",  # JSON output to stdout
        safe_target,
    ]

    print(f"[WHATWEB] Running: {' '.join(cmd)}", file=sys.stderr)

    rate_limit_wait()
    try:
        proc = subprocess.run(
            cmd,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Docker not found - required for WhatWeb")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="WhatWeb timed out after 5 minutes")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running WhatWeb: {e}")

    # Parse JSON output - WhatWeb outputs one JSON object per line
    technologies: List[str] = []
    raw_plugins: Dict[str, Any] = {}

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            # WhatWeb JSON structure: {"target": "...", "http_status": 200, "plugins": {...}}
            plugins = data.get("plugins", {}) or {}
            for plugin_name, plugin_data in plugins.items():
                technologies.append(plugin_name)
                # Store version info if available
                if isinstance(plugin_data, dict):
                    version = plugin_data.get("version")
                    if version:
                        raw_plugins[plugin_name] = {"version": version}
                    else:
                        raw_plugins[plugin_name] = plugin_data
                else:
                    raw_plugins[plugin_name] = {"detected": True}
        except json.JSONDecodeError:
            continue

    # Store structured result
    result_data = {
        "target": safe_target,  # Use validated target, not raw user input
        "timestamp": ts,
        "technologies": sorted(set(technologies)),
        "plugins": raw_plugins,
        "raw_stdout": proc.stdout,
        "raw_stderr": proc.stderr,
        "exit_code": proc.returncode,
    }

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result_data, fh, indent=2)

    if proc.returncode != 0 and not technologies:
        raise HTTPException(
            status_code=500,
            detail=f"WhatWeb failed (exit {proc.returncode}): {proc.stderr[:500]}",
        )

    return WhatWebResult(
        target=safe_target,  # Return the validated/safe target, not raw user input
        output_file=out_path,
        technologies=sorted(set(technologies)),
        raw_plugins=raw_plugins,
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

    # --- Katana HTTP surface ingestion (unauthenticated) ---
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

        # Skip if not a dict (e.g., old format files that are arrays)
        if not isinstance(kdata, dict):
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

    # --- Authenticated Katana HTTP surface ingestion (dev-mode) ---
    # Looks for artifacts emitted by /mcp/run_katana_auth under
    # ARTIFACTS_DIR/katana_auth/<host_key>/katana_auth_*.json.
    host_key = host.replace("://", "_").replace("/", "_")
    auth_base = os.path.join(ARTIFACTS_DIR, "katana_auth", host_key)
    auth_urls: List[str] = []
    auth_api_endpoints: List[Dict[str, Any]] = []

    if os.path.isdir(auth_base):
        for fname in sorted(os.listdir(auth_base)):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(auth_base, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception:
                continue

            urls = data.get("urls") or []
            if isinstance(urls, list):
                for u in urls:
                    if isinstance(u, str):
                        auth_urls.append(u)

            api_eps = data.get("api_endpoints") or []
            if isinstance(api_eps, list):
                for ep in api_eps:
                    if isinstance(ep, dict):
                        auth_api_endpoints.append(ep)

    if auth_urls or auth_api_endpoints:
        profile["web"]["auth_katana"] = {
            "urls": sorted(set(auth_urls)),
            "api_endpoints": auth_api_endpoints,
            "count": len(set(auth_urls)),
        }

    # --- Fingerprinting ingestion (WhatWeb/compatible) ---
    # Auto-trigger WhatWeb if no recent fingerprint data exists (within 24 hours)
    fp_base = os.path.join(ARTIFACTS_DIR, "fingerprints", host.replace("://", "_").replace("/", "_"))
    fp_tech: List[str] = []
    fp_plugins: Dict[str, Any] = {}
    fp_stale = True  # Assume stale until we find recent data
    
    if os.path.isdir(fp_base):
        # Prefer JSON files (new format), fall back to txt (old format)
        json_files = sorted([f for f in os.listdir(fp_base) if f.startswith("whatweb_") and f.endswith(".json")])
        txt_files = sorted([f for f in os.listdir(fp_base) if f.startswith("whatweb_") and f.endswith(".txt")])
        
        # Try JSON format first (new /mcp/run_whatweb output)
        if json_files:
            latest = os.path.join(fp_base, json_files[-1])
            try:
                with open(latest, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                fp_tech = data.get("technologies", []) or []
                fp_plugins = data.get("plugins", {}) or {}
                # Check freshness (24 hours)
                file_ts = data.get("timestamp", 0)
                if time.time() - file_ts < 86400:
                    fp_stale = False
            except Exception:
                pass
        
        # Fall back to txt format (old /mcp/run_fingerprints output)
        if not fp_tech and txt_files:
            latest = os.path.join(fp_base, txt_files[-1])
            try:
                with open(latest, "r", encoding="utf-8") as fh:
                    text = fh.read()
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(" ")
                    for token in parts[1:]:
                        if "[" in token and "]" in token:
                            tech = token.split("[", 1)[0]
                            if tech:
                                fp_tech.append(tech)
                # Check file age for freshness
                file_mtime = os.path.getmtime(latest)
                if time.time() - file_mtime < 86400:
                    fp_stale = False
            except Exception:
                pass
    
    # Auto-trigger WhatWeb if data is stale or missing
    if fp_stale and all_urls:
        # Use the first URL as target for fingerprinting
        target_url = all_urls[0] if all_urls else f"http://{host}"
        try:
            print(f"[HOST_PROFILE] Auto-triggering WhatWeb for {target_url}", file=sys.stderr)
            whatweb_result = _run_whatweb_internal(target_url)
            if whatweb_result:
                fp_tech = whatweb_result.get("technologies", [])
                fp_plugins = whatweb_result.get("plugins", {})
        except Exception as e:
            print(f"[HOST_PROFILE] WhatWeb auto-trigger failed: {e}", file=sys.stderr)

    if fp_tech:
        profile.setdefault("web", {})["fingerprints"] = {
            "technologies": sorted(set(fp_tech)),
            "plugins": fp_plugins,
        }

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

    # --- Auth surface ingestion (without exposing secrets) ---
    auth_cfg = AUTH_CONFIGS.get(host)
    if auth_cfg is not None:
        header_names = sorted(list(auth_cfg.headers.keys()))
        vals_lower = " ".join(str(v).lower() for v in auth_cfg.headers.values())
        has_bearer = "bearer " in vals_lower
        has_api_key_style = any(
            k.lower() in {"api-key", "x-api-key", "x-api-key-id", "authorization"}
            for k in header_names
        )
        profile.setdefault("web", {})["auth"] = {
            "type": auth_cfg.type,
            "header_names": header_names,
            "has_bearer": has_bearer,
            "has_api_key_style": has_api_key_style,
        }

    # --- JS miner (creds.json) ingestion with classification + redaction ---
    def _classify_js_secret(snippet: str) -> tuple[str, str, str]:
        """Return (kind, confidence, redacted_snippet) for a JS secret candidate."""
        s = snippet or ""

        # JWT-like: header.payload.signature
        parts = s.split(".")
        if len(parts) == 3 and all(parts):
            red = f"{parts[0]}.[redacted].[redacted]"
            return "jwt", "high", red

        lower = s.lower()

        # API key style
        if any(k in lower for k in ["api_key", "apikey", "x-api-key"]):
            # show only prefix + masked tail
            prefix = s[:6]
            suffix = s[-4:] if len(s) > 10 else ""
            red = f"{prefix}****{suffix}" if suffix else f"{prefix}****"
            return "api_key", "high", red

        # Bearer token
        if lower.startswith("bearer "):
            token = s.split(" ", 1)[1] if " " in s else ""
            if token:
                prefix = token[:4]
                suffix = token[-4:] if len(token) > 10 else ""
                red_token = f"{prefix}****{suffix}" if suffix else f"{prefix}****"
                return "bearer_token", "high", f"Bearer {red_token}"

        # Basic credential user:pass
        if ":" in s and s.count(":") == 1:
            user, pwd = s.split(":", 1)
            if user and pwd and len(pwd) >= 4:
                return "basic_credential", "medium", f"{user}:****"

        # Fallback: generic secret with partial redaction
        if len(s) > 12:
            prefix = s[:4]
            suffix = s[-4:]
            red = f"{prefix}****{suffix}"
        else:
            red = s[:4] + "****"
        # Rough confidence heuristic: longer/more complex strings treated as medium
        has_digit = any(c.isdigit() for c in s)
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        complexity = sum([has_digit, has_upper, has_lower])
        conf = "medium" if len(s) > 16 and complexity >= 2 else "low"
        return "generic_secret", conf, red

    js_dir = os.path.join(ARTIFACTS_DIR, "js_miner", host)
    js_creds: list[Dict[str, Any]] = []
    if os.path.isdir(js_dir):
        for root, _dirs, files in os.walk(js_dir):
            for fname in files:
                if fname != "creds.json":
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                except Exception:
                    continue
                if isinstance(data, list):
                    for entry in data:
                        if not isinstance(entry, dict):
                            continue
                        context = entry.get("context")
                        raw_snippet = entry.get("snippet") or ""
                        kind, confidence, redacted = _classify_js_secret(str(raw_snippet))
                        js_creds.append({
                            "context": context,
                            "snippet": redacted,
                            "kind": kind,
                            "confidence": confidence,
                        })

    if js_creds:
        by_kind: Dict[str, int] = {}
        for e in js_creds:
            k = e.get("kind") or "unknown"
            by_kind[k] = by_kind.get(k, 0) + 1

        profile.setdefault("web", {})["js_secrets"] = {
            "count": len(js_creds),
            "by_kind": by_kind,
            "samples": js_creds[:20],
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


# ---------- AI Nuclei Triage Endpoints ----------

@app.post("/mcp/triage_nuclei_templates", response_model=NucleiTriageResult)
def triage_nuclei_templates(req: NucleiTriageRequest):
    """
    AI-driven Nuclei template selection based on host_profile.

    This endpoint:
    1. Loads the latest host_profile snapshot for the given host
    2. Calls the AI triage helper to analyze technologies and attack surface
    3. Returns a curated list of templates/tags optimized for this host

    The output can be passed directly to /mcp/run_targeted_nuclei.
    """
    host = _enforce_scope(req.host)

    # Load latest host profile
    profile = _load_host_profile_snapshot(host, latest=True)
    if not profile:
        raise HTTPException(
            status_code=404,
            detail=f"No host_profile snapshot found for {host}. Run host_profile first.",
        )

    # Import and call the AI triage helper
    triage_script = os.path.join(os.path.dirname(__file__), "tools", "ai_nuclei_triage.py")
    if not os.path.exists(triage_script):
        raise HTTPException(
            status_code=500,
            detail=f"ai_nuclei_triage.py not found at {triage_script}",
        )

    # Write profile to temp file for the helper
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        json.dump(profile, tmp, indent=2)
        tmp_path = tmp.name

    try:
        cmd = [
            sys.executable,
            triage_script,
            "--host-profile",
            tmp_path,
        ]
        if not req.use_llm:
            cmd.append("--no-llm")

        rate_limit_wait()
        proc = subprocess.run(
            cmd,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=180,
        )

        if proc.returncode != 0:
            # Log error but try to parse any output
            print(f"[TRIAGE] ai_nuclei_triage.py warning: {proc.stderr}", file=sys.stderr)

        # Parse JSON output
        output = proc.stdout.strip()
        if not output:
            raise HTTPException(
                status_code=500,
                detail=f"Empty output from ai_nuclei_triage.py: {proc.stderr}",
            )

        try:
            result = json.loads(output)
        except json.JSONDecodeError as e:
            raise HTTPException(
                status_code=500,
                detail=f"Invalid JSON from ai_nuclei_triage.py: {e}\nOutput: {output[:500]}",
            )

    finally:
        # Cleanup temp file
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return NucleiTriageResult(
        host=host,
        mode=result.get("mode", "recon"),
        templates=result.get("templates", []),
        tags=result.get("tags", []),
        exclude_tags=result.get("exclude_tags", []),
        severity_filter=result.get("severity_filter", ["critical", "high", "medium"]),
        reasoning=result.get("reasoning", ""),
    )


@app.post("/mcp/run_targeted_nuclei", response_model=TargetedNucleiResult)
def run_targeted_nuclei(req: TargetedNucleiRequest):
    """
    Run Nuclei with AI-selected templates for targeted vulnerability discovery.

    This endpoint is designed to be called after /mcp/triage_nuclei_templates
    with the templates/tags returned by the AI triage.

    Unlike the recon-only mode, this runs deeper vulnerability checks on
    specific template categories relevant to the detected technology stack.
    """
    host = _enforce_scope(req.target)

    if not req.templates:
        raise HTTPException(
            status_code=400,
            detail="No templates specified. Call /mcp/triage_nuclei_templates first.",
        )

    # Resolve template paths
    nuclei_bin = os.environ.get("NUCLEI_BIN", "nuclei")
    templates_dir = NUCLEI_TEMPLATES_DIR or os.path.expanduser("~/nuclei-templates")

    # Build nuclei command
    cmd = [nuclei_bin, "-u", req.target]

    # Add templates
    templates_used = 0
    for tmpl in req.templates:
        abs_path = os.path.join(templates_dir, tmpl) if not os.path.isabs(tmpl) else tmpl
        if os.path.exists(abs_path):
            cmd.extend(["-t", abs_path])
            templates_used += 1
        else:
            print(f"[NUCLEI] Template path not found, skipping: {abs_path}", file=sys.stderr)

    if templates_used == 0:
        raise HTTPException(
            status_code=400,
            detail=f"No valid template paths found. Check NUCLEI_TEMPLATES_DIR={templates_dir}",
        )

    # Add tags filter
    if req.tags:
        cmd.extend(["-tags", ",".join(req.tags)])

    # Add exclude tags
    if req.exclude_tags:
        cmd.extend(["-etags", ",".join(req.exclude_tags)])

    # Add severity filter
    if req.severity:
        cmd.extend(["-severity", ",".join(req.severity)])

    # Output configuration
    ts = int(time.time())
    host_key = host.replace(":", "_").replace("/", "_")
    out_name = f"targeted_nuclei_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)

    cmd.extend(["-jsonl", "-silent", "-o", out_path])

    print(f"[NUCLEI] Running targeted scan: {' '.join(cmd)}", file=sys.stderr)

    rate_limit_wait()
    try:
        proc = subprocess.run(
            cmd,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour timeout for deep scans
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Nuclei scan timed out (1 hour)")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running nuclei: {e}")

    if proc.returncode != 0 and not os.path.exists(out_path):
        raise HTTPException(
            status_code=500,
            detail=f"Nuclei failed: {proc.stderr.strip()}",
        )

    # Count findings
    findings_count = 0
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    findings_count += 1

    return TargetedNucleiResult(
        target=req.target,
        findings_count=findings_count,
        findings_file=out_path,
        templates_used=templates_used,
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
    # Default port 8000 matches Dockerfile.mcp and agentic_runner.py defaults
    print("MCP server starting on port 8000 (no ZAP dependency).")
    uvicorn.run("mcp_server:app", host="0.0.0.0", port=8000, reload=False)
