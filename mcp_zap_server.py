#!/usr/bin/env python3
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
from urllib.parse import urlparse

def normalize_target(t: str) -> str:
    if "://" in t:
        u = urlparse(t)
        host = (u.netloc or u.path).split("/")[0]
    else:
        host = t.split("/")[0]
    return host.lower().strip().rstrip(".")

# ========== CONFIG ==========
ZAP_API_BASE = os.environ.get("ZAP_API_BASE", "http://localhost:8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")
H1_ALIAS = os.environ.get("H1_ALIAS", "h1yourusername@wearehackerone.com")
MAX_REQ_PER_SEC = float(os.environ.get("MAX_REQ_PER_SEC", "3.0"))
INTERACTSH_CLIENT = os.environ.get("INTERACTSH_CLIENT", "")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "./output_zap")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ==== NEW: scope + artifacts helpers ====
def current_scope_hosts() -> set[str]:
    if not SCOPE:
        return set()
    hosts = list(SCOPE.primary_targets or []) + list(SCOPE.secondary_targets or [])
    return {normalize_target(h) for h in hosts}

def enforce_in_scope(hosts: list[str]):
    normalized_scope = current_scope_hosts()
    if not normalized_scope:
        raise HTTPException(status_code=400, detail="Scope not set. Call /mcp/set_scope first.")
    bad = [h for h in (normalize_target(x) for x in hosts) if h not in normalized_scope]
    if bad:
        raise HTTPException(status_code=400, detail=f"Out-of-scope target(s): {', '.join(sorted(set(bad)))}")

ARTIFACTS_DIR = os.path.join(OUTPUT_DIR, "artifacts")
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

def write_artifact(tool: str, host: str, basename: str, content: str) -> str:
    safe_host = normalize_target(host) or "unknown"
    d = os.path.join(ARTIFACTS_DIR, tool, safe_host)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, basename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content or "")
    return path

def tool_versions() -> dict:
    def _ver(cmd):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return (p.stdout or p.stderr or "").strip().splitlines()[0][:200]
        except Exception:
            return "unknown"
    return {
        "zap": "via API",
        "ffuf": _ver(["ffuf", "-V"]),
        "sqlmap": _ver(["sqlmap", "--version"]),
    }

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

# ========== FastAPI ==========
app = FastAPI(title="MCP ZAP Server with Scope Guards")

class ScopeConfig(BaseModel):
    program_name: str
    primary_targets: List[str]
    secondary_targets: List[str]
    rules: Dict[str, Any] = {}

SCOPE: Optional[ScopeConfig] = None
JOB_STORE: Dict[str, Dict[str, Any]] = {}

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
def start_zap_scan(req: dict):
    targets = req.get("targets", [])
    enforce_in_scope(targets)
    return {"status": "started", "targets": targets}

if __name__ == "__main__":
    import uvicorn
    print("MCP ZAP server starting. Ensure ZAP is running (default http://localhost:8080).")
    uvicorn.run("mcp_zap_server:app", host="0.0.0.0", port=8100, reload=False)