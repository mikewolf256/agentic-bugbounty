#!/usr/bin/env python3
import os
import sys
import json
import time
import shlex
import subprocess
import argparse
from typing import Tuple, Optional, Dict, Any, List

import requests
import yaml

# ==== Config / Env ====
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")
H1_ALIAS = os.environ.get("H1_ALIAS", "h1yourusername@wearehackerone.com")
if not OPENAI_API_KEY:
    raise SystemExit("Set OPENAI_API_KEY env var.")

# Dalfox config
DALFOX_PATH = os.environ.get("DALFOX_BIN", os.path.expanduser("~/go/bin/dalfox"))
DALFOX_DOCKER = os.environ.get("DALFOX_DOCKER", "").lower() in ("1","true","yes")
DALFOX_TIMEOUT = int(os.environ.get("DALFOX_TIMEOUT_SECONDS", "30"))
DALFOX_THREADS = int(os.environ.get("DALFOX_THREADS", "5"))  # dalfox -t

# In-memory cache for Dalfox results within a single triage run
_DALFOX_CACHE: Dict[Tuple[str, Optional[str]], Tuple[bool, dict]] = {}

# MCP server config (for orchestrated scans / containerization)
# Default port 8000 matches Dockerfile.mcp and docker-compose.yml
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8000")

# K8s mode support
LOCAL_K8S_MODE = os.environ.get("LOCAL_K8S_MODE", "false").lower() in ("true", "1", "yes")
try:
    from tools.local_executor import LocalExecutor, is_local_k8s_mode
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    LocalExecutor = None

# Profile configuration
PROFILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")
ACTIVE_PROFILE: Optional[Dict[str, Any]] = None

# Default profile settings (used when no profile specified)
DEFAULT_PROFILE: Dict[str, Any] = {
    "name": "default",
    "description": "Default scan profile",
    "nuclei": {
        "tags": [],
        "exclude_tags": ["dos"],
        "severity": ["critical", "high", "medium"],
        "rate_limit": 150,
    },
    "validators": ["dalfox", "sqlmap", "ssrf", "bac", "oauth", "race", "smuggling", "graphql"],
    "skip_modules": [],
    "ai_triage": {
        "enabled": True,
        "use_llm": True,
        "confidence_threshold": "medium",
    },
    "phases": ["recon", "nuclei", "validators", "triage"],
}


def load_profile(profile_name: str) -> Dict[str, Any]:
    """Load a scan profile from YAML file.
    
    Args:
        profile_name: Name of the profile (without .yaml extension)
    
    Returns:
        Profile configuration dict
    
    Raises:
        SystemExit if profile not found
    """
    profile_path = os.path.join(PROFILES_DIR, f"{profile_name}.yaml")
    
    if not os.path.exists(profile_path):
        # List available profiles
        available = []
        if os.path.exists(PROFILES_DIR):
            available = [f.replace(".yaml", "") for f in os.listdir(PROFILES_DIR) if f.endswith(".yaml")]
        raise SystemExit(f"Profile '{profile_name}' not found at {profile_path}. Available: {', '.join(available)}")
    
    with open(profile_path, "r", encoding="utf-8") as f:
        profile = yaml.safe_load(f)
    
    print(f"[PROFILE] Loaded profile: {profile.get('name', profile_name)} - {profile.get('description', 'No description')}")
    return profile


def get_profile_setting(key: str, default: Any = None) -> Any:
    """Get a setting from the active profile or default.
    
    Args:
        key: Dot-notation key like 'nuclei.tags' or 'validators'
        default: Default value if key not found
    
    Returns:
        Setting value
    """
    profile = ACTIVE_PROFILE or DEFAULT_PROFILE
    
    # Handle dot notation
    parts = key.split(".")
    value = profile
    for part in parts:
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return default
    
    return value


def should_skip_module(module_name: str) -> bool:
    """Check if a module should be skipped based on profile."""
    skip_modules = get_profile_setting("skip_modules", [])
    return module_name in skip_modules


def should_run_validator(validator_name: str) -> bool:
    """Check if a validator should run based on profile."""
    validators = get_profile_setting("validators", [])
    skip = get_profile_setting("skip_modules", [])
    
    # If validators list is empty, run all (except skipped)
    if not validators:
        return validator_name not in skip
    
    return validator_name in validators and validator_name not in skip


SYSTEM_PROMPT = """You are a senior web security engineer and bug bounty triager.
Return STRICT JSON with keys: title, cvss_vector, cvss_score, summary, repro, impact, remediation, cwe, confidence, recommended_bounty_usd.
Additionally, when the issue appears to be XSS-like (cross-site scripting), also include:
- xss_type: one of ["reflected","stored","dom"]
- xss_context: one of ["attribute","html_body","script_block","other"].
Be conservative. If low-value/noisy, confidence="low", recommended_bounty_usd=0. No leaked-credential validation or SE.

When historical vulnerability examples are provided, use them as reference for:
- Severity assessment and CVSS scoring
- Impact descriptions and exploitation scenarios
- Recommended bounty ranges based on similar accepted reports
- Reproduction steps and payload patterns that have worked before"""

USER_TMPL = """Program scope:
{scope}

Finding JSON:
{finding}
"""

USER_TMPL_WITH_RAG = """Program scope:
{scope}

{rag_context}

Finding JSON:
{finding}
"""

# RAG configuration
RAG_ENABLED = os.environ.get("RAG_ENABLED", "true").lower() in ("1", "true", "yes")
RAG_MAX_EXAMPLES = int(os.environ.get("RAG_MAX_EXAMPLES", "3"))

# Lazy-loaded RAG client
_rag_client_instance = None


def _get_rag_context(finding: Dict[str, Any], max_examples: int = 3) -> str:
    """
    Get RAG context for a finding.
    
    This function queries the RAG knowledge base for similar historical
    vulnerabilities and returns a formatted context string for LLM injection.
    
    Returns empty string if RAG is disabled or fails.
    """
    global _rag_client_instance
    
    if not RAG_ENABLED:
        return ""
    
    try:
        # Try to use the RAG client directly
        if _rag_client_instance is None:
            try:
                from tools.rag_client import RAGClient
                _rag_client_instance = RAGClient()
            except Exception as e:
                print(f"[RAG] Failed to initialize client: {e}", file=sys.stderr)
                return ""
        
        return _rag_client_instance.get_context_for_triage(
            finding=finding,
            max_examples=max_examples,
        )
    except Exception as e:
        # RAG failures should not break triage
        print(f"[RAG] Warning: Failed to get context: {e}", file=sys.stderr)
        return ""


def _get_rag_context_via_mcp(finding: Dict[str, Any], max_examples: int = 3) -> str:
    """
    Get RAG context via MCP endpoint (for when running in full-scan mode).
    
    Falls back to empty string if MCP is unavailable.
    """
    if not RAG_ENABLED:
        return ""
    
    try:
        url = MCP_SERVER_URL.rstrip("/") + "/mcp/rag_similar_vulns"
        payload = {
            "finding": finding,
            "top_k": max_examples + 2,  # Get a few extra for filtering
            "min_similarity": 0.35,
        }
        
        resp = requests.post(url, json=payload, timeout=30)
        if resp.status_code != 200:
            return ""
        
        data = resp.json()
        return data.get("context_string", "")
    except Exception as e:
        print(f"[RAG] Warning: MCP RAG call failed: {e}", file=sys.stderr)
        return ""

# ==== Helpers ====
def map_mitre(t: Dict[str, Any]) -> Dict[str, Any]:
    """Static MITRE ATT&CK mapping based on CWE/category/title.

    This is intentionally minimal and deterministic; it can be extended or
    refined later (including LLM-based mapping). For now we just cover a few
    core bug classes with high-level techniques.
    """

    title = (t.get("title") or "").lower()
    cwe = (t.get("cwe") or "").lower()
    category = (t.get("category") or "").lower()

    techniques: List[Dict[str, Any]] = []
    tactics: List[str] = []

    # XSS-like
    if (
        "xss" in title
        or "cross-site scripting" in title
        or "xss" in category
        or "cross-site scripting" in category
        or "cwe-79" in cwe
        or "cwe-80" in cwe
    ):
        techniques.append({
            "id": "T1059.007",
            "name": "Command and Scripting Interpreter: JavaScript",
            "confidence": "medium",
        })
        tactics.append("Execution")

    # SQLi-like
    if "sql injection" in title or "sqli" in title or "sql injection" in category or "cwe-89" in cwe:
        techniques.append({
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "confidence": "high",
        })
        tactics.append("Initial Access")

    # Broken access control / IDOR
    if "idor" in title or "insecure direct object" in title or "broken access" in title or "cwe-284" in cwe:
        techniques.append({
            "id": "T1078",
            "name": "Valid Accounts (abuse of authorization)",
            "confidence": "medium",
        })
        tactics.extend(["Privilege Escalation", "Defense Evasion"])

    # Secrets / sensitive data exposure
    if "secret" in title or "api key" in title or "token" in title or "sensitive" in title or "cwe-200" in cwe:
        techniques.append({
            "id": "T1552",
            "name": "Unsecured Credentials",
            "confidence": "medium",
        })
        tactics.append("Credential Access")

    # SSRF-like
    if "ssrf" in title or "server-side request forgery" in title or "cwe-918" in cwe:
        techniques.append({
            "id": "T1190",
            "name": "Exploit Public-Facing Application (SSRF)",
            "confidence": "medium",
        })
        tactics.append("Initial Access")

    if not techniques:
        return {"techniques": [], "tactics": [], "notes": "no_static_mapping"}

    # Deduplicate tactics
    uniq_tactics = []
    for tac in tactics:
        if tac not in uniq_tactics:
            uniq_tactics.append(tac)

    return {
        "techniques": techniques,
        "tactics": uniq_tactics,
        "notes": "static_mapping_v1",
    }

def openai_chat(msgs):
    r = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type":"application/json"},
        json={"model": LLM_MODEL, "messages": msgs, "temperature": 0.0, "max_tokens": 1600},
        timeout=180,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()

def run_dalfox_check(target_url: str, param_name: Optional[str] = None) -> Tuple[bool, dict]:
    """
    Safe Dalfox confirmation for XSS-like issues.
    Returns (confirmed, evidence_dict).
    """
    evidence = {"engine_result": None, "payload": None, "proof_snippet": None, "raw_output": None, "cmd": None}
    safe_payload = "<svg/onload=console.log('h1-xss')>"
    tmp_out = os.path.join("output_zap", f"dalfox_{int(time.time())}.json")

    # --- ensure run_url contains FUZZ ---
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    u = urlparse(target_url)
    qs = dict(parse_qsl(u.query, keep_blank_values=True))
    if param_name:
        qs[param_name] = "FUZZ"
    else:
        if "FUZZ" not in u.query:
            qs["x"] = "FUZZ"
    run_url = urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(qs, doseq=True), u.fragment))
    # -----------------------------------

    # Check cache first to avoid re-running Dalfox on identical inputs
    cache_key = (run_url, param_name)
    if cache_key in _DALFOX_CACHE:
        return _DALFOX_CACHE[cache_key]

    if DALFOX_DOCKER:
        cmd = [
            "docker","run","--rm","--network","host","ghcr.io/hahwul/dalfox:latest",
            "dalfox","url",run_url,"--simple","--json","-o","/tmp/dalfox_out.json","-t",str(DALFOX_THREADS)
        ]
        tmp_out_fs = "/tmp/dalfox_out.json"
    else:
        cmd = [DALFOX_PATH,"url",run_url,"--simple","--json","-o",tmp_out,"-t",str(DALFOX_THREADS)]
        tmp_out_fs = tmp_out

    evidence["cmd"] = " ".join(shlex.quote(x) for x in cmd)
    print(f"[DALFOX] {evidence['cmd']}")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=DALFOX_TIMEOUT)
    except subprocess.TimeoutExpired:
        evidence["engine_result"] = "timeout"
        _DALFOX_CACHE[cache_key] = (False, evidence)
        return False, evidence

    # Try to read JSON output
    if os.path.exists(tmp_out_fs):
        try:
            raw_out = open(tmp_out_fs, "r", encoding="utf-8").read()
            evidence["raw_output"] = raw_out
            j = json.loads(raw_out) if raw_out.strip() else {}
            results = j.get("results") if isinstance(j, dict) else None

            # Dalfox JSON schema: look for any result with type "xss"
            confirmed = False
            if isinstance(results, list):
                for r in results:
                    rtype = (r.get("type") or "").lower()
                    if "xss" in rtype:
                        confirmed = True
                        evidence["payload"] = r.get("payload") or safe_payload
                        evidence["proof_snippet"] = r.get("evidence") or r.get("poC") or ""
                        break

            if confirmed:
                evidence["engine_result"] = "confirmed"
                _DALFOX_CACHE[cache_key] = (True, evidence)
                return True, evidence

        except Exception as e:
            # JSON or parse failure – fall back to text heuristics
            evidence["raw_output"] = (evidence.get("raw_output") or "") + f"\n[parse_error] {e}"

    out_text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    evidence["raw_output"] = (evidence.get("raw_output") or "") + "\n" + out_text

    # Heuristic text check
    if "xss" in out_text.lower() or "found" in out_text.lower():
        evidence["engine_result"] = "maybe"
        _DALFOX_CACHE[cache_key] = (False, evidence)
        return False, evidence

    evidence["engine_result"] = "not_found"
    _DALFOX_CACHE[cache_key] = (False, evidence)
    return False, evidence


# ==== MCP client helpers ====
def _mcp_post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    url = MCP_SERVER_URL.rstrip("/") + path
    r = requests.post(url, json=payload, timeout=600)
    try:
        r.raise_for_status()
    except Exception:
        raise SystemExit(f"MCP POST {url} failed: {r.status_code} {r.text[:4000]}")
    try:
        return r.json()
    except ValueError:
        raise SystemExit(f"MCP POST {url} returned non-JSON: {r.text[:4000]}")


def _mcp_get(path: str) -> Dict[str, Any]:
    url = MCP_SERVER_URL.rstrip("/") + path
    r = requests.get(url, timeout=600)
    try:
        r.raise_for_status()
    except Exception:
        raise SystemExit(f"MCP GET {url} failed: {r.status_code} {r.text[:4000]}")
    try:
        return r.json()
    except ValueError:
        raise SystemExit(f"MCP GET {url} returned non-JSON: {r.text[:4000]}")


def wait_for_mcp_ready(max_wait: int = 30) -> None:
    """Best-effort wait for MCP server to become reachable.

    We don't require a dedicated health endpoint; a simple GET to /docs (or root)
    being reachable with 200 is enough for our purposes.
    """

    url = MCP_SERVER_URL.rstrip("/") + "/docs"
    start = time.time()
    while time.time() - start < max_wait:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code < 500:
                return
        except Exception:
            pass
        time.sleep(1)
    raise SystemExit(f"MCP server not ready at {MCP_SERVER_URL} after {max_wait}s")


def _run_katana_stage(mcp_base_url: str, target_url: str) -> dict:
    payload = {"target": target_url}
    resp = requests.post(f"{mcp_base_url}/mcp/run_katana_nuclei", json=payload, timeout=600)
    resp.raise_for_status()
    return resp.json()

def run_full_scan_via_mcp(scope: Dict[str, Any]) -> Dict[str, Any]:
    """Orchestrate a full scan pipeline via the MCP server.

    High-level steps (all best-effort):
    - Call /mcp/set_scope with the provided scope.json
    - For each in-scope host, start a ZAP scan (basic) and poll until done
    - Optionally run nuclei recon for each host
    - Run Katana+Nuclei web recon per host
    - Build host_profile, prioritize_host, and host_delta for each host
    - Return a summary object with per-host metadata and artifact paths
    
    Respects ACTIVE_PROFILE settings for module/validator selection.
    """

    wait_for_mcp_ready()

    # Get profile settings
    phases = get_profile_setting("phases", ["recon", "nuclei", "validators", "triage"])
    use_llm = get_profile_setting("ai_triage.use_llm", True)
    profile_name = get_profile_setting("name", "default")
    
    print(f"[RUNNER] Using profile: {profile_name}")
    print(f"[RUNNER] Phases: {phases}")

    # container for overall run summary (including modules like katana_nuclei)
    summary: Dict[str, Any] = {"scope": scope, "profile": profile_name}

    # 1) Set scope
    _mcp_post("/mcp/set_scope", scope)

    hosts: List[str] = []
    in_scope = scope.get("in_scope") or []
    for entry in in_scope:
        url = entry.get("url") or entry.get("target") or ""
        if url:
            hosts.append(url)

    summary_hosts: List[Dict[str, Any]] = []

    # 2) Start ZAP scans for each host
    zap_scans: Dict[str, str] = {}
    for h in hosts:
        body = {"targets": [h]}
        try:
            resp = _mcp_post("/mcp/start_zap_scan", body)
            zap_scans[h] = resp.get("scan_id") or ""
        except SystemExit as e:
            print(f"[MCP] Failed to start ZAP scan for {h}: {e}")

    # 3) Poll ZAP scans
    for h, scan_id in zap_scans.items():
        if not scan_id:
            continue
        while True:
            time.sleep(3)
            try:
                status = _mcp_get(f"/mcp/poll_zap?scan_id={scan_id}")
            except SystemExit as e:
                print(f"[MCP] poll_zap error for {h}: {e}")
                break
            if status.get("status") in ("done", "error"):
                break

    # 4) Nuclei recon per host (best-effort)
    # Try K8s mode first if available
    if LOCAL_K8S_MODE and K8S_AVAILABLE and is_local_k8s_mode():
        try:
            executor = LocalExecutor()
            for h in hosts:
                try:
                    print(f"[K8S] Running Nuclei recon for {h}...")
                    result = executor.submit_and_wait("nuclei", h, options={"mode": "recon"})
                    if result:
                        print(f"[K8S] Nuclei recon completed for {h}")
                except Exception as e:
                    print(f"[K8S] Nuclei recon failed for {h}: {e}, falling back to MCP")
                    try:
                        _mcp_post("/mcp/run_nuclei", {"target": h, "mode": "recon"})
                    except SystemExit:
                        pass
        except Exception as e:
            print(f"[K8S] K8s executor failed: {e}, using MCP")
            for h in hosts:
                try:
                    _mcp_post("/mcp/run_nuclei", {"target": h, "mode": "recon"})
                except SystemExit as e:
                    print(f"[MCP] nuclei recon failed for {h}: {e}")
    else:
        for h in hosts:
            try:
                _mcp_post("/mcp/run_nuclei", {"target": h, "mode": "recon"})
            except SystemExit as e:
                print(f"[MCP] nuclei recon failed for {h}: {e}")

    # 4b) Cloud recon per host (best-effort)
    for h in hosts:
        try:
            _mcp_post("/mcp/run_cloud_recon", {"host": h})
        except SystemExit as e:
            print(f"[MCP] cloud recon failed for {h}: {e}")

    # --- NEW: Katana + Nuclei web recon stage ---
    for host in hosts:
        target_url = f"http://{host}"
        # Katana/Nuclei recon
        # Try K8s mode first if available
        katana_result = None
        if LOCAL_K8S_MODE and K8S_AVAILABLE and is_local_k8s_mode():
            try:
                executor = LocalExecutor()
                print(f"[K8S] Running Katana for {target_url}...")
                katana_result_k8s = executor.submit_and_wait("katana", target_url)
                if katana_result_k8s:
                    # Also run nuclei via k8s
                    print(f"[K8S] Running Nuclei for {target_url}...")
                    nuclei_result_k8s = executor.submit_and_wait("nuclei", target_url)
                    katana_result = {
                        "katana": katana_result_k8s,
                        "nuclei": nuclei_result_k8s,
                        "source": "k8s"
                    }
            except Exception as e:
                print(f"[K8S] K8s execution failed for {target_url}: {e}, falling back to MCP")
        
        # Fall back to MCP if K8s didn't work
        if not katana_result:
            try:
                katana_result = _run_katana_stage(MCP_SERVER_URL, target_url)
            except Exception as e:
                katana_result = {"error": str(e)}

        # stash in full-scan summary structure under modules
        summary.setdefault("modules", {})
        summary["modules"].setdefault(host, {})
        summary["modules"][host]["katana_nuclei"] = katana_result

        # --- Authenticated Katana recon (if Chrome DevTools available) ---
        # Try to run authenticated recon - will auto-detect Chrome DevTools on port 9222
        try:
            print(f"[AUTH-KATANA] Attempting authenticated recon for {target_url}...")
            auth_katana_result = _mcp_post("/mcp/run_katana_auth", {
                "target": target_url,
                "session_ws_url": None,  # Auto-detect
            })
            summary["modules"][host]["katana_auth"] = {
                "auth_katana_count": auth_katana_result.get("auth_katana_count", 0),
                "output_file": auth_katana_result.get("output_file"),
            }
            if auth_katana_result.get("auth_katana_count", 0) > 0:
                print(f"[AUTH-KATANA] Discovered {auth_katana_result['auth_katana_count']} authenticated URLs")
        except SystemExit as e:
            print(f"[AUTH-KATANA] Authenticated recon skipped for {host}: {e}")
            summary["modules"][host]["katana_auth"] = {"error": "Chrome DevTools not available or no authenticated session"}
        except Exception as e:
            print(f"[AUTH-KATANA] Authenticated recon failed for {host}: {e}")
            summary["modules"][host]["katana_auth"] = {"error": str(e)}

        # --- JS miner (best-effort, non-blocking) ---
        try:
            js_resp = _mcp_post("/mcp/run_js_miner", {"base_url": target_url})
            summary["modules"][host]["js_miner"] = {
                "job_id": js_resp.get("job_id"),
                "artifact_dir": js_resp.get("artifact_dir"),
            }
        except SystemExit as e:
            print(f"[MCP] js_miner failed for {host}: {e}")

        # --- Backup hunter (best-effort, non-blocking) ---
        try:
            bh_resp = _mcp_post("/mcp/run_backup_hunt", {"base_url": target_url})
            summary["modules"][host]["backup_hunt"] = {
                "job_id": bh_resp.get("job_id"),
                "artifact_dir": bh_resp.get("artifact_dir"),
            }
        except SystemExit as e:
            print(f"[MCP] backup_hunt failed for {host}: {e}")

    # 5) Build host_profile, prioritize_host, and host_delta per host
    for h in hosts:
        try:
            profile = _mcp_post("/mcp/host_profile", {"host": h, "llm_view": True})
        except SystemExit as e:
            print(f"[MCP] host_profile failed for {h}: {e}")
            profile = {}

        try:
            prio = _mcp_post("/mcp/prioritize_host", {"host": h})
        except SystemExit as e:
            print(f"[MCP] prioritize_host failed for {h}: {e}")
            prio = {}

        try:
            delta = _mcp_post("/mcp/host_delta", {"host": h})
        except SystemExit as e:
            print(f"[MCP] host_delta failed for {h}: {e}")
            delta = {}

        # --- NEW: AI-driven targeted Nuclei scan ---
        # After Katana+WhatWeb, use AI to select optimal templates and run a targeted scan
        ai_triage_result: Dict[str, Any] = {}
        targeted_nuclei_result: Dict[str, Any] = {}
        
        # Check if nuclei phase is enabled
        run_nuclei = "nuclei" in phases
        ai_triage_enabled = get_profile_setting("ai_triage.enabled", True)
        
        if profile and run_nuclei and ai_triage_enabled:
            try:
                print(f"[AI-TRIAGE] Selecting Nuclei templates for {h} (use_llm={use_llm})...")
                ai_triage_result = _mcp_post("/mcp/triage_nuclei_templates", {"host": h, "use_llm": use_llm})
                print(f"[AI-TRIAGE] Mode: {ai_triage_result.get('mode')}, Templates: {len(ai_triage_result.get('templates', []))}")
                print(f"[AI-TRIAGE] Reasoning: {ai_triage_result.get('reasoning', 'N/A')}")
                
                # Run targeted Nuclei scan with AI-selected templates
                templates = ai_triage_result.get("templates", [])
                if templates:
                    target_url = f"http://{h}"
                    print(f"[AI-TRIAGE] Running targeted Nuclei scan on {target_url}...")
                    targeted_nuclei_result = _mcp_post("/mcp/run_targeted_nuclei", {
                        "target": target_url,
                        "templates": templates,
                        "tags": ai_triage_result.get("tags"),
                        "exclude_tags": ai_triage_result.get("exclude_tags"),
                        "severity": ai_triage_result.get("severity_filter"),
                    })
                    print(f"[AI-TRIAGE] Targeted scan complete: {targeted_nuclei_result.get('findings_count', 0)} findings")
                else:
                    print(f"[AI-TRIAGE] No specific templates selected, skipping targeted scan")
                    
            except SystemExit as e:
                print(f"[AI-TRIAGE] Failed for {h}: {e}")
            except Exception as e:
                print(f"[AI-TRIAGE] Error for {h}: {e}")

        # --- NEW: Open Redirect Checks ---
        # Check discovered URLs for redirect parameters
        open_redirect_results: Dict[str, Any] = {}
        if profile:
            web = profile.get("web", {}) or {}
            urls = web.get("urls", []) or []
            
            # Common redirect parameter names
            redirect_params = ["redirect", "return", "next", "url", "target", "dest", "goto", "r", "redirect_uri", "callback"]
            
            # Find URLs with redirect-like parameters
            redirect_urls = []
            for url in urls[:20]:  # Limit to first 20 URLs for performance
                from urllib.parse import urlparse, parse_qsl
                parsed = urlparse(url)
                params = dict(parse_qsl(parsed.query))
                for param in redirect_params:
                    if param in params:
                        redirect_urls.append(url)
                        break
            
            # Test each URL with redirect params
            if redirect_urls:
                try:
                    print(f"[OPEN_REDIRECT] Testing {len(redirect_urls)} URLs for open redirect vulnerabilities...")
                    for test_url in redirect_urls[:10]:  # Limit to 10 for performance
                        try:
                            redirect_result = _mcp_post("/mcp/run_open_redirect_checks", {
                                "url": test_url,
                            })
                            if redirect_result.get("vulnerable"):
                                open_redirect_results[test_url] = redirect_result
                                print(f"[OPEN_REDIRECT] Found vulnerable: {test_url}")
                        except Exception as e:
                            continue
                except Exception as e:
                    print(f"[OPEN_REDIRECT] Error checking redirects: {e}")

        # --- NEW: OAuth/OIDC Security Checks ---
        # Run OAuth security checks if OAuth endpoints detected
        oauth_results: Dict[str, Any] = {}
        if profile:
            web = profile.get("web", {}) or {}
            # Check if OAuth endpoints might be present (check for common patterns)
            urls = web.get("urls", []) or []
            oauth_indicators = any(
                "oauth" in url.lower() or "openid" in url.lower() or ".well-known" in url.lower()
                for url in urls
            )
            
            if oauth_indicators or "validators" in phases:
                try:
                    print(f"[OAUTH] Running OAuth security checks for {h}...")
                    oauth_result = _mcp_post("/mcp/run_oauth_checks", {
                        "host": h,
                    })
                    oauth_results = {
                        "vulnerable_count": oauth_result.get("vulnerable_count", 0),
                        "findings_file": oauth_result.get("findings_file"),
                        "meta": oauth_result.get("meta", {}),
                    }
                    if oauth_result.get("vulnerable_count", 0) > 0:
                        print(f"[OAUTH] Found {oauth_result['vulnerable_count']} OAuth vulnerabilities")
                except SystemExit as e:
                    print(f"[OAUTH] OAuth checks failed for {h}: {e}")
                except Exception as e:
                    print(f"[OAUTH] OAuth checks error for {h}: {e}")

        # --- NEW: Subdomain Takeover Checks ---
        # Run subdomain enumeration and takeover checks (recon phase)
        takeover_results: Dict[str, Any] = {}
        if "recon" in phases:
            try:
                # Extract base domain from host
                base_domain = h.split("://")[-1].split("/")[0].split(":")[0]
                # Remove www. prefix if present
                if base_domain.startswith("www."):
                    base_domain = base_domain[4:]
                
                print(f"[TAKEOVER] Checking subdomain takeovers for {base_domain}...")
                
                # Enumerate subdomains (best-effort)
                subdomains = []
                try:
                    script_path = os.path.join(os.path.dirname(__file__), "tools", "subdomain_enum.py")
                    if os.path.exists(script_path):
                        proc = subprocess.run(
                            [sys.executable, script_path, "--domain", base_domain],
                            capture_output=True,
                            text=True,
                            timeout=120,
                        )
                        if proc.returncode == 0:
                            subdomains = [s.strip() for s in proc.stdout.splitlines() if s.strip()]
                except Exception as e:
                    print(f"[TAKEOVER] Subdomain enum failed: {e}")
                
                # Run takeover checks
                if subdomains or True:  # Always try even without enum (uses common subs)
                    takeover_result = _mcp_post("/mcp/run_takeover_checks", {
                        "domain": base_domain,
                        "subdomains": subdomains[:50] if subdomains else None,  # Limit to 50
                    })
                    takeover_results = takeover_result
                    if takeover_result.get("vulnerable_subdomains"):
                        print(f"[TAKEOVER] Found {len(takeover_result['vulnerable_subdomains'])} vulnerable subdomains")
            except Exception as e:
                print(f"[TAKEOVER] Error: {e}")

        # Store AI triage results in modules
        summary.setdefault("modules", {})
        summary["modules"].setdefault(h, {})
        summary["modules"][h]["ai_triage"] = ai_triage_result
        summary["modules"][h]["targeted_nuclei"] = targeted_nuclei_result
        summary["modules"][h]["open_redirect"] = {
            "vulnerable_count": len(open_redirect_results),
            "results": open_redirect_results,
        }
        summary["modules"][h]["oauth"] = oauth_results
        summary["modules"][h]["takeover"] = takeover_results

        # --- NEW: Race Condition Checks ---
        # Run race condition checks for fintech/e-commerce targets or race-heavy profile
        race_results: Dict[str, Any] = {}
        profile_name = get_profile_setting("name", "default")
        is_race_heavy = profile_name == "race-heavy" or "race" in profile_name.lower()
        
        if is_race_heavy or "validators" in phases:
            try:
                print(f"[RACE] Running race condition checks for {h}...")
                race_result = _mcp_post("/mcp/run_race_checks", {
                    "host": h,
                    "num_requests": 10,
                })
                race_results = {
                    "vulnerable_count": race_result.get("vulnerable_count", 0),
                    "findings_file": race_result.get("findings_file"),
                    "meta": race_result.get("meta", {}),
                }
                if race_result.get("vulnerable_count", 0) > 0:
                    print(f"[RACE] Found {race_result['vulnerable_count']} race condition vulnerabilities")
            except SystemExit as e:
                print(f"[RACE] Race checks failed for {h}: {e}")
            except Exception as e:
                print(f"[RACE] Race checks error for {h}: {e}")
        
        summary["modules"][h]["race"] = race_results

        summary_hosts.append(
            {
                "host": h,
                "host_profile": profile,
                "prioritization": prio,
                "delta": delta,
                # Compact view of JS-derived secrets from host_profile (if any)
                "js_secrets": (profile.get("web", {}) or {}).get("js_secrets"),
                # AI triage summary
                "ai_triage": {
                    "mode": ai_triage_result.get("mode"),
                    "templates_count": len(ai_triage_result.get("templates", [])),
                    "reasoning": ai_triage_result.get("reasoning"),
                },
                "targeted_nuclei": {
                    "findings_count": targeted_nuclei_result.get("findings_count", 0),
                    "findings_file": targeted_nuclei_result.get("findings_file"),
                },
            }
        )

    summary["hosts"] = summary_hosts
    summary["zap_scans"] = zap_scans
    return summary


# ==== Triage helpers ====
def run_triage_for_findings(findings_file: str, scope: Dict[str, Any], out_dir: str = "output_zap") -> str:
    """Run LLM + Dalfox triage for a single ZAP findings JSON file.

    Returns the path to the written triage JSON file.
    """

    os.makedirs(out_dir, exist_ok=True)
    findings = json.load(open(findings_file))

    # Deduplicate findings before triage
    try:
        print(f"[DEDUP] Deduplicating {len(findings)} findings before triage...", file=sys.stderr)
        dedup_result = _mcp_post("/mcp/deduplicate_findings", {
            "findings": findings,
            "use_semantic": True,
        })
        findings = dedup_result.get("deduplicated_findings", findings)
        print(f"[DEDUP] Deduplicated to {len(findings)} findings ({dedup_result.get('duplicates_removed', 0)} removed)", file=sys.stderr)
        
        # Store correlation graph if available
        if dedup_result.get("correlation_graph"):
            print(f"[CORRELATION] Vulnerability chains detected: {len(dedup_result['correlation_graph'].get('chains_detected', []))}", file=sys.stderr)
    except Exception as e:
        print(f"[DEDUP] Deduplication failed, continuing with original findings: {e}", file=sys.stderr)

    triaged = []
    for f in findings:
        # Be defensive: ignore non-dict entries (e.g. summary objects)
        if not isinstance(f, dict):
            continue
        
        # Get RAG context for similar historical vulnerabilities
        rag_context = ""
        if RAG_ENABLED:
            try:
                rag_context = _get_rag_context(f, max_examples=RAG_MAX_EXAMPLES)
                if rag_context:
                    print(f"[RAG] Found similar historical vulnerabilities for finding", file=sys.stderr)
            except Exception as e:
                print(f"[RAG] Context retrieval failed: {e}", file=sys.stderr)
        
        # Build the user message with or without RAG context
        if rag_context:
            user_content = USER_TMPL_WITH_RAG.format(
                scope=json.dumps(scope, indent=2),
                rag_context=rag_context,
                finding=json.dumps(f, indent=2),
            )
        else:
            user_content = USER_TMPL.format(
                scope=json.dumps(scope, indent=2),
                finding=json.dumps(f, indent=2),
            )
        
        msgs = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]
        
        # LLM triage
        try:
            raw = openai_chat(msgs)

            # Strip common Markdown code fences (```json ... ```)
            txt = raw.strip()
            if txt.startswith("```"):
                # Remove leading ```... line
                first_newline = txt.find("\n")
                if first_newline != -1:
                    txt = txt[first_newline+1:]
                if txt.endswith("```"):
                    txt = txt[: -3].strip()

            try:
                t = json.loads(txt)
            except json.JSONDecodeError:
                # If the model returns non-strict JSON, wrap it
                t = {"title": "LLM parse error", "summary": raw}
        except Exception as e:
            t = {
                "title": "LLM triage failure",
                "summary": f"Error during triage: {e}",
                "cvss_vector": "TBD",
                "cvss_score": "TBD",
                "impact": "",
                "repro": "",
                "remediation": "",
                "cwe": "N/A",
                "confidence": "low",
                "recommended_bounty_usd": 0,
            }

        # Attach raw
        t["_raw_finding"] = f

        # Attach static MITRE mapping (best-effort)
        try:
            t["mitre"] = map_mitre(t)
        except Exception:
            # Keep failures non-fatal; missing MITRE is fine
            t["mitre"] = {"techniques": [], "tactics": [], "notes": "mapping_error"}
        
        # Calculate business impact score and bounty estimate
        try:
            from tools.impact_scorer import calculate_impact_score
            from tools.bounty_estimator import estimate_bounty
            
            # Merge triage result with raw finding for impact calculation
            finding_with_triage = {**f, **t}
            impact_score = calculate_impact_score(finding_with_triage)
            t["business_impact_score"] = impact_score
            
            # Estimate bounty
            bounty_estimate = estimate_bounty(finding_with_triage)
            t["bounty_estimate"] = bounty_estimate
            # Update recommended_bounty if not set or if estimate is higher
            if not t.get("recommended_bounty_usd") or bounty_estimate.get("estimated", 0) > t.get("recommended_bounty_usd", 0):
                t["recommended_bounty_usd"] = bounty_estimate.get("estimated", t.get("recommended_bounty_usd", 0))
        except Exception as e:
            # Impact scoring failures should not break triage
            print(f"[IMPACT] Warning: Failed to calculate impact score: {e}", file=sys.stderr)

        # Skip Dalfox/SQLmap for cloud storage findings
        name = (f.get("name") or "").lower()
        if "cloud storage surface" in name or "cloud" in name and "storage" in name:
            t.setdefault("validation", {})
            t["validation"]["dalfox"] = {
                "engine_result": "skipped_not_applicable",
                "validation_confidence": "low",
                "raw_output": "",
                "cmd": None,
            }
            t["validation"]["dalfox_confirmed"] = False
            t["validation"]["sqlmap"] = {
                "engine_result": "skipped_not_applicable",
                "output_dir": None,
                "returncode": None,
            }
            triaged.append(t)
            time.sleep(0.4)
            continue

        # === Dalfox validation for XSS ===
        # Only run Dalfox when the LLM is at least medium confidence AND
        # the issue looks XSS-like based on category/CWE/title.
        try:
            confidence = (t.get("confidence") or "").lower()
        except Exception:
            confidence = ""

        try:
            title = (t.get("title") or "").lower()
            cwe = (t.get("cwe") or "").lower()
            category = (t.get("category") or "").lower()

            looks_xss = (
                "xss" in title
                or "cross-site scripting" in title
                or "xss" in category
                or "cross-site scripting" in category
                or "cwe-79" in cwe
                or "cwe-80" in cwe
            )

            # Check profile to see if Dalfox validator is enabled
            if not should_run_validator("dalfox"):
                t.setdefault("validation", {})
                t["validation"]["dalfox"] = {
                    "engine_result": "skipped_profile_disabled",
                    "validation_confidence": "low",
                    "raw_output": "",
                    "cmd": None,
                    "endpoint": None,
                }
                t["validation"]["dalfox_confirmed"] = False
            elif confidence not in ("medium", "high", "very_high", "very high") or not looks_xss:
                # Skip expensive Dalfox for clearly low-confidence / non-XSS findings
                t.setdefault("validation", {})
                t["validation"]["dalfox"] = {
                    "engine_result": "skipped_not_xss_or_low_confidence",
                    "validation_confidence": "low",
                    "raw_output": "",
                    "cmd": None,
                    "endpoint": None,
                }
                t["validation"]["dalfox_confirmed"] = False
            else:
                url = f.get("url") or f.get("request", {}).get("url")
                param = f.get("parameter") or f.get("param")
                if url:
                    confirmed, evidence = run_dalfox_check(url, param)
                    t.setdefault("validation", {})
                    # annotate raw Dalfox evidence with validation metadata
                    evidence["engine_result"] = "confirmed" if confirmed else evidence.get("engine_result") or "ran"
                    evidence["validation_confidence"] = "high" if confirmed else "medium"
                    t["validation"]["dalfox"] = evidence
                    t["validation"]["dalfox_confirmed"] = confirmed
        except Exception as e:
            t.setdefault("validation", {})
            t["validation"]["dalfox"] = {
                "engine_result": "error",
                "raw_output": str(e),
                "cmd": None,
                "endpoint": None,
            }
            t["validation"]["dalfox_confirmed"] = False
        # === end Dalfox validation ===

        # === SQLi validation via MCP / sqlmap ===
        try:
            title = (t.get("title") or "").lower()
            cwe = (t.get("cwe") or "").lower()
            category = (t.get("category") or "").lower()
            confidence = (t.get("confidence") or "").lower()

            looks_sqli = (
                "sql injection" in title
                or "sqli" in title
                or "sql injection" in category
                or "cwe-89" in cwe
            )

            # Check profile to see if SQLmap validator is enabled
            if not should_run_validator("sqlmap"):
                t.setdefault("validation", {})
                t["validation"]["sqlmap"] = {
                    "engine_result": "skipped_profile_disabled",
                    "output_dir": None,
                    "returncode": None,
                    "endpoint": "/mcp/run_sqlmap",
                }
            elif looks_sqli and confidence in ("medium", "high", "very_high", "very high"):
                url = f.get("url") or f.get("request", {}).get("url")
                payload = {"target": url} if url else None
                if payload:
                    try:
                        resp = _mcp_post("/mcp/run_sqlmap", payload)
                        t.setdefault("validation", {})

                        # Base SQLmap metadata
                        sqlmap_meta: Dict[str, Any] = {
                            "engine_result": "ran",
                            "output_dir": resp.get("output_dir"),
                            "returncode": resp.get("returncode"),
                            "endpoint": "/mcp/run_sqlmap",
                            "target": url,
                        }

                        # Optional richer summary if MCP exposes it
                        meta = resp.get("meta") or {}
                        if isinstance(meta, dict):
                            if meta.get("dbms"):
                                sqlmap_meta["dbms"] = meta.get("dbms")
                            if meta.get("vulnerable_params"):
                                sqlmap_meta["vulnerable_params"] = meta.get("vulnerable_params")
                            if meta.get("dumped_data_summary"):
                                sqlmap_meta["dumped_data_summary"] = meta.get("dumped_data_summary")

                        # Heuristic validation confidence: higher when DBMS/params detected
                        if sqlmap_meta.get("dbms") or sqlmap_meta.get("vulnerable_params"):
                            sqlmap_meta["validation_confidence"] = "high"
                        else:
                            sqlmap_meta["validation_confidence"] = "medium"

                        t["validation"]["sqlmap"] = sqlmap_meta
                    except SystemExit as e:
                        t.setdefault("validation", {})
                        t["validation"]["sqlmap"] = {
                            "engine_result": "error",
                            "output_dir": None,
                            "returncode": None,
                            "error": str(e),
                            "endpoint": "/mcp/run_sqlmap",
                            "target": url,
                        }
            else:
                t.setdefault("validation", {})
                t["validation"]["sqlmap"] = {
                    "engine_result": "skipped_not_sqli_or_low_confidence",
                    "output_dir": None,
                    "returncode": None,
                    "endpoint": "/mcp/run_sqlmap",
                    "target": None,
                }
        except Exception as e:
            t.setdefault("validation", {})
            t["validation"]["sqlmap"] = {
                "engine_result": "error",
                "output_dir": None,
                "returncode": None,
                "error": str(e),
                "endpoint": "/mcp/run_sqlmap",
                "target": None,
            }

        # === BAC validation via MCP / run_bac_checks (summary only) ===
        try:
            title = (t.get("title") or "").lower()
            cwe = (t.get("cwe") or "").lower()
            category = (t.get("category") or "").lower()
            confidence = (t.get("confidence") or "").lower()

            looks_bac = (
                "broken access" in title
                or "access control" in title
                or "idor" in title
                or "insecure direct object" in title
                or "authorization" in title
                or "broken access" in category
                or "access control" in category
                or "idor" in category
                or "insecure direct object" in category
                or "cwe-284" in cwe
                or "cwe-285" in cwe
            )

            # Check profile to see if BAC validator is enabled
            if not should_run_validator("bac"):
                t.setdefault("validation", {})
                t["validation"]["bac"] = {
                    "engine_result": "skipped_profile_disabled",
                    "endpoint": "/mcp/run_bac_checks",
                    "host": None,
                }
            elif looks_bac and confidence in ("medium", "high", "very_high", "very high"):
                host = (f.get("host") or f.get("request", {}).get("url") or "").split("//")[-1].split("/")[0]
                payload = {"host": host} if host else None
                if payload:
                    try:
                        resp = _mcp_post("/mcp/run_bac_checks", payload)
                        t.setdefault("validation", {})

                        meta = resp.get("meta") or {}
                        checks_count = meta.get("checks_count")
                        confirmed_count = meta.get("confirmed_issues_count")
                        summary_txt = meta.get("summary")

                        bac_meta: Dict[str, Any] = {
                            "engine_result": "confirmed" if (confirmed_count or 0) > 0 else "ran",
                            "checks_count": checks_count,
                            "confirmed_issues_count": confirmed_count,
                            "summary": summary_txt,
                            "endpoint": "/mcp/run_bac_checks",
                            "host": host,
                        }

                        # Treat any confirmed BAC as high-confidence validation
                        if (confirmed_count or 0) > 0:
                            bac_meta["validation_confidence"] = "high"
                        elif checks_count:
                            bac_meta["validation_confidence"] = "medium"

                        t["validation"]["bac"] = bac_meta
                    except SystemExit as e:
                        t.setdefault("validation", {})
                        t["validation"]["bac"] = {
                            "engine_result": "error",
                            "error": str(e),
                            "endpoint": "/mcp/run_bac_checks",
                            "host": host,
                        }
            else:
                t.setdefault("validation", {})
                t["validation"]["bac"] = {
                    "engine_result": "skipped_not_bac_or_low_confidence",
                    "endpoint": "/mcp/run_bac_checks",
                    "host": None,
                }
        except Exception as e:
            t.setdefault("validation", {})
            t["validation"]["bac"] = {
                "engine_result": "error",
                "error": str(e),
                "endpoint": "/mcp/run_bac_checks",
                "host": None,
            }

        # === SSRF validation via MCP ===
        try:
            title = (t.get("title") or "").lower()
            cwe = (t.get("cwe") or "").lower()
            category = (t.get("category") or "").lower()
            confidence = (t.get("confidence") or "").lower()

            looks_ssrf = (
                "ssrf" in title
                or "server-side request forgery" in title
                or "ssrf" in category
                or "server-side request forgery" in category
                or "cwe-918" in cwe
            )

            # Check profile to see if SSRF validator is enabled
            if not should_run_validator("ssrf"):
                t.setdefault("validation", {})
                t["validation"]["ssrf"] = {
                    "engine_result": "skipped_profile_disabled",
                    "endpoint": "/mcp/run_ssrf_checks",
                }
            elif looks_ssrf and confidence in ("medium", "high", "very_high", "very high"):
                url = f.get("url") or f.get("request", {}).get("url") or ""
                param = f.get("parameter") or f.get("param") or "url"
                t.setdefault("validation", {})
                try:
                    payload = {"target": url, "param": param}
                    resp = _mcp_post("/mcp/run_ssrf_checks", payload)
                    meta = resp.get("meta") or {}
                    checks_count = meta.get("checks_count")
                    confirmed_count = meta.get("confirmed_issues_count")
                    summary_txt = meta.get("summary")
                    targets_reached = meta.get("targets_reached") or []

                    ssrf_meta: Dict[str, Any] = {
                        "engine_result": "confirmed" if (confirmed_count or 0) > 0 else "ran",
                        "checks_count": checks_count,
                        "confirmed_issues_count": confirmed_count,
                        "summary": summary_txt,
                        "endpoint": "/mcp/run_ssrf_checks",
                        "target": url,
                        "param": param,
                    }

                    if targets_reached:
                        ssrf_meta["targets_reached"] = targets_reached

                    if (confirmed_count or 0) > 0:
                        ssrf_meta["validation_confidence"] = "high"
                    elif checks_count:
                        ssrf_meta["validation_confidence"] = "medium"

                    t["validation"]["ssrf"] = ssrf_meta
                except SystemExit as e:
                    t["validation"]["ssrf"] = {
                        "engine_result": "error",
                        "error": str(e),
                        "endpoint": "/mcp/run_ssrf_checks",
                        "target": url,
                        "param": param,
                    }
        except Exception:
            # SSRF validation is best-effort; ignore errors.
            pass

        # === OAuth validation via MCP ===
        try:
            title = (t.get("title") or "").lower()
            cwe = (t.get("cwe") or "").lower()
            category = (t.get("category") or "").lower()
            confidence = (t.get("confidence") or "").lower()
            summary_txt = (t.get("summary") or "").lower()

            looks_oauth = (
                "oauth" in title
                or "oidc" in title
                or "openid" in title
                or "oauth" in category
                or ("authorization" in title and "oauth" in summary_txt)
            )

            if not should_run_validator("oauth"):
                t.setdefault("validation", {})
                t["validation"]["oauth"] = {
                    "engine_result": "skipped_profile_disabled",
                    "endpoint": "/mcp/run_oauth_checks",
                }
            elif looks_oauth and confidence in ("medium", "high", "very_high", "very high"):
                host = (f.get("host") or f.get("request", {}).get("url") or "").split("//")[-1].split("/")[0]
                payload = {"host": host} if host else None
                if payload:
                    try:
                        resp = _mcp_post("/mcp/run_oauth_checks", payload)
                        t.setdefault("validation", {})
                        meta = resp.get("meta") or {}
                        vulnerable_count = resp.get("vulnerable_count", 0)
                        oauth_meta: Dict[str, Any] = {
                            "engine_result": "confirmed" if vulnerable_count > 0 else "ran",
                            "vulnerable_count": vulnerable_count,
                            "endpoint": "/mcp/run_oauth_checks",
                            "host": host,
                        }
                        if meta.get("vulnerable_tests"):
                            oauth_meta["vulnerable_tests"] = meta.get("vulnerable_tests")
                        if vulnerable_count > 0:
                            oauth_meta["validation_confidence"] = "high"
                        else:
                            oauth_meta["validation_confidence"] = "medium"
                        t["validation"]["oauth"] = oauth_meta
                    except SystemExit as e:
                        t.setdefault("validation", {})
                        t["validation"]["oauth"] = {
                            "engine_result": "error",
                            "error": str(e),
                            "endpoint": "/mcp/run_oauth_checks",
                        }
            else:
                t.setdefault("validation", {})
                t["validation"]["oauth"] = {
                    "engine_result": "skipped_not_oauth_or_low_confidence",
                    "endpoint": "/mcp/run_oauth_checks",
                }
        except Exception:
            pass

        # === Race Condition validation via MCP ===
        try:
            title = (t.get("title") or "").lower()
            cwe = (t.get("cwe") or "").lower()
            category = (t.get("category") or "").lower()
            confidence = (t.get("confidence") or "").lower()

            looks_race = (
                "race condition" in title
                or "race" in title
                or "toctou" in title
                or "time-of-check" in title
                or "race" in category
            )

            if not should_run_validator("race"):
                t.setdefault("validation", {})
                t["validation"]["race"] = {
                    "engine_result": "skipped_profile_disabled",
                    "endpoint": "/mcp/run_race_checks",
                }
            elif looks_race and confidence in ("medium", "high", "very_high", "very high"):
                host = (f.get("host") or f.get("request", {}).get("url") or "").split("//")[-1].split("/")[0]
                payload = {"host": host} if host else None
                if payload:
                    try:
                        resp = _mcp_post("/mcp/run_race_checks", payload)
                        t.setdefault("validation", {})
                        vulnerable_count = resp.get("vulnerable_count", 0)
                        race_meta: Dict[str, Any] = {
                            "engine_result": "confirmed" if vulnerable_count > 0 else "ran",
                            "vulnerable_count": vulnerable_count,
                            "endpoint": "/mcp/run_race_checks",
                            "host": host,
                        }
                        meta = resp.get("meta") or {}
                        if meta.get("vulnerable_tests"):
                            race_meta["vulnerable_tests"] = meta.get("vulnerable_tests")
                        if vulnerable_count > 0:
                            race_meta["validation_confidence"] = "high"
                        else:
                            race_meta["validation_confidence"] = "medium"
                        t["validation"]["race"] = race_meta
                    except SystemExit as e:
                        t.setdefault("validation", {})
                        t["validation"]["race"] = {
                            "engine_result": "error",
                            "error": str(e),
                            "endpoint": "/mcp/run_race_checks",
                        }
            else:
                t.setdefault("validation", {})
                t["validation"]["race"] = {
                    "engine_result": "skipped_not_race_or_low_confidence",
                    "endpoint": "/mcp/run_race_checks",
                }
        except Exception:
            pass

        # === Request Smuggling validation via MCP ===
        try:
            title = (t.get("title") or "").lower()
            cwe = (t.get("cwe") or "").lower()
            category = (t.get("category") or "").lower()
            confidence = (t.get("confidence") or "").lower()

            looks_smuggling = (
                "request smuggling" in title
                or "http request smuggling" in title
                or "smuggling" in title
                or "smuggling" in category
            )

            if not should_run_validator("smuggling"):
                t.setdefault("validation", {})
                t["validation"]["smuggling"] = {
                    "engine_result": "skipped_profile_disabled",
                    "endpoint": "/mcp/run_smuggling_checks",
                }
            elif looks_smuggling and confidence in ("medium", "high", "very_high", "very high"):
                host = (f.get("host") or f.get("request", {}).get("url") or "").split("//")[-1].split("/")[0]
                payload = {"host": host} if host else None
                if payload:
                    try:
                        resp = _mcp_post("/mcp/run_smuggling_checks", payload)
                        t.setdefault("validation", {})
                        vulnerable = resp.get("vulnerable", False)
                        smuggling_meta: Dict[str, Any] = {
                            "engine_result": "confirmed" if vulnerable else "ran",
                            "vulnerable": vulnerable,
                            "endpoint": "/mcp/run_smuggling_checks",
                            "host": host,
                        }
                        meta = resp.get("meta") or {}
                        if meta.get("tests"):
                            smuggling_meta["tests"] = meta.get("tests")
                        if vulnerable:
                            smuggling_meta["validation_confidence"] = "high"
                        else:
                            smuggling_meta["validation_confidence"] = "medium"
                        t["validation"]["smuggling"] = smuggling_meta
                    except SystemExit as e:
                        t.setdefault("validation", {})
                        t["validation"]["smuggling"] = {
                            "engine_result": "error",
                            "error": str(e),
                            "endpoint": "/mcp/run_smuggling_checks",
                        }
            else:
                t.setdefault("validation", {})
                t["validation"]["smuggling"] = {
                    "engine_result": "skipped_not_smuggling_or_low_confidence",
                    "endpoint": "/mcp/run_smuggling_checks",
                }
        except Exception:
            pass

        # === GraphQL validation via MCP ===
        try:
            title = (t.get("title") or "").lower()
            cwe = (t.get("cwe") or "").lower()
            category = (t.get("category") or "").lower()
            confidence = (t.get("confidence") or "").lower()
            url = f.get("url") or f.get("request", {}).get("url") or ""

            looks_graphql = (
                "graphql" in title
                or "graphql" in category
                or "/graphql" in url.lower()
                or "/api/graphql" in url.lower()
            )

            if not should_run_validator("graphql"):
                t.setdefault("validation", {})
                t["validation"]["graphql"] = {
                    "engine_result": "skipped_profile_disabled",
                    "endpoint": "/mcp/run_graphql_security",
                }
            elif looks_graphql and confidence in ("medium", "high", "very_high", "very high") and url:
                try:
                    resp = _mcp_post("/mcp/run_graphql_security", {"endpoint": url})
                    t.setdefault("validation", {})
                    vulnerable = resp.get("vulnerable", False)
                    graphql_meta: Dict[str, Any] = {
                        "engine_result": "confirmed" if vulnerable else "ran",
                        "vulnerable": vulnerable,
                        "endpoint": "/mcp/run_graphql_security",
                        "graphql_endpoint": url,
                    }
                    meta = resp.get("meta") or {}
                    if meta:
                        graphql_meta.update(meta)
                    if vulnerable:
                        graphql_meta["validation_confidence"] = "high"
                    else:
                        graphql_meta["validation_confidence"] = "medium"
                    t["validation"]["graphql"] = graphql_meta
                except SystemExit as e:
                    t.setdefault("validation", {})
                    t["validation"]["graphql"] = {
                        "engine_result": "error",
                        "error": str(e),
                        "endpoint": "/mcp/run_graphql_security",
                    }
            else:
                t.setdefault("validation", {})
                t["validation"]["graphql"] = {
                    "engine_result": "skipped_not_graphql_or_low_confidence",
                    "endpoint": "/mcp/run_graphql_security",
                }
        except Exception:
            pass

        # === Simple XSS classification (type + context heuristics) ===
        try:
            title_txt = (t.get("title") or "").lower()
            summary_txt = (t.get("summary") or "").lower()
            evidence_txt = str((f.get("evidence") or f.get("otherinfo") or "")).lower()

            is_xss_like = (
                "xss" in title_txt
                or "cross-site scripting" in title_txt
                or "xss" in summary_txt
                or "cross-site scripting" in summary_txt
            )

            xss_type = None
            if is_xss_like:
                if "stored xss" in title_txt or "stored" in summary_txt:
                    xss_type = "stored"
                elif "dom" in title_txt or "dom-based" in title_txt or "dom" in summary_txt:
                    xss_type = "dom"
                else:
                    xss_type = "reflected"

            xss_context = None
            if is_xss_like:
                if "<script" in evidence_txt:
                    xss_context = "script_block"
                elif "onload=" in evidence_txt or "onclick=" in evidence_txt or "onerror=" in evidence_txt:
                    xss_context = "attribute"
                else:
                    xss_context = "html_body"

            if xss_type:
                t["xss_type"] = xss_type
            if xss_context:
                t["xss_context"] = xss_context
        except Exception:
            # XSS classification is best-effort and non-fatal
            pass

        # === Derive overall validation_status and per-engine summary ===
        v = t.get("validation") or {}
        engines: list[str] = []
        results: list[str] = []
        per_engine_summaries: list[str] = []
        for eng_name, eng_data in v.items():
            if not isinstance(eng_data, dict):
                continue
            engines.append(eng_name)
            res = str(eng_data.get("engine_result") or "").lower()
            if res:
                results.append(res)

            # Build a human-readable per-engine line when useful
            pieces: list[str] = []
            if res:
                pieces.append(f"result={res}")
            conf = str(eng_data.get("validation_confidence") or "").lower()
            if conf:
                pieces.append(f"confidence={conf}")
            # include a very small hint if present (e.g., dbms or payload)
            if "dbms" in eng_data:
                pieces.append(f"dbms={eng_data.get('dbms')}")
            if "payload" in eng_data:
                pieces.append("payload_present")
            if "confirmed_issues_count" in eng_data:
                pieces.append(f"confirmed={eng_data.get('confirmed_issues_count')}")
            if pieces:
                per_engine_summaries.append(f"- {eng_name}: " + ", ".join(pieces))

        status = "unknown"
        if results:
            if any(r in ("confirmed", "ran") for r in results):
                status = "validated"
            elif any(r == "planned" for r in results):
                status = "planned"
            elif all(r.startswith("skipped") for r in results):
                status = "skipped"
            elif any(r == "error" for r in results):
                status = "error"

        # Always expose validation_status/validation_engines for downstream consumers
        t["validation_status"] = status
        t["validation_engines"] = sorted(engines) if engines else []
        t["validation_per_engine"] = per_engine_summaries
        # === end SQLi validation ===

        triaged.append(t)
        time.sleep(0.4)

    # === POC Validation Gate ===
    # Validate POCs before including in reports
    try:
        from tools.poc_validator import validate_findings as validate_poc_findings
        print("[POC-VALIDATOR] Validating POCs before report generation...", file=sys.stderr)
        validation_result = validate_poc_findings(triaged, require_validation=False)
        
        # Add POC validation metadata to each finding
        for finding in triaged:
            poc_validation = finding.get("_poc_validation", {})
            if poc_validation:
                finding["poc_validated"] = poc_validation.get("poc_validated", False)
                finding["poc_quality_score"] = poc_validation.get("poc_quality_score", "low")
                finding["validation_evidence_complete"] = poc_validation.get("validation_evidence_complete", False)
        
        stats = validation_result["stats"]
        print(f"[POC-VALIDATOR] Validated: {stats['validated']}, Rejected: {stats['rejected']}", file=sys.stderr)
        print(f"[POC-VALIDATOR] Quality: High: {stats['high_quality']}, Medium: {stats['medium_quality']}, Low: {stats['low_quality']}", file=sys.stderr)
        
        # Filter to only validated findings if configured
        require_poc_validation = get_profile_setting("poc_validation.require_validation", False)
        if require_poc_validation:
            original_count = len(triaged)
            triaged = validation_result["validated"]
            print(f"[POC-VALIDATOR] Filtered to {len(triaged)} validated findings (from {original_count})", file=sys.stderr)
    except ImportError:
        print("[POC-VALIDATOR] poc_validator module not available, skipping validation", file=sys.stderr)
    except Exception as e:
        print(f"[POC-VALIDATOR] POC validation failed: {e}, continuing with all findings", file=sys.stderr)

    scan_id = os.path.basename(findings_file).replace("zap_findings_", "").replace(".json", "")
    triage_path = os.path.join(out_dir, f"triage_{scan_id}.json")
    
    # Sort by business impact score (if available) or CVSS score
    try:
        from tools.impact_scorer import score_findings
        triaged = score_findings(triaged)
        print("[IMPACT] Findings prioritized by business impact", file=sys.stderr)
    except Exception as e:
        # Fallback to CVSS sorting
        triaged.sort(key=lambda x: float(x.get("cvss_score", 0) or 0), reverse=True)
        print(f"[IMPACT] Impact scoring failed, using CVSS: {e}", file=sys.stderr)
    
    json.dump(triaged, open(triage_path, "w"), indent=2)
    print("[TRIAGE] Wrote", triage_path)

    # Markdown rendering
    def md(t, scope_obj):
        dal = (t.get("validation") or {}).get("dalfox") or {}
        dal_result = dal.get("engine_result", "")
        dal_conf = (t.get("validation") or {}).get("dalfox_confirmed", False)
        dal_payload = dal.get("payload", "")
        dal_raw = (dal.get("raw_output", "") or "")[:4000]

        # If there is no real Dalfox data, omit the whole section
        show_dalfox = bool(dal_result or dal_payload or dal_raw)

        # Validation + MITRE summary
        validation_status = t.get("validation_status", "unknown")
        validation_engines = t.get("validation_engines") or []
        if validation_engines:
            engines_str = ", ".join(map(str, validation_engines))
        else:
            engines_str = "none"
        per_engine_lines = t.get("validation_per_engine") or []

        mitre = t.get("mitre") or {}
        mitre_line = "None"
        if isinstance(mitre, dict) and mitre:
            parts = []
            techs = mitre.get("techniques") or []
            if techs:
                # techniques may be list of dicts from map_mitre
                if techs and isinstance(techs[0], dict):
                    tech_ids = [str(x.get("id") or "") for x in techs if x.get("id")]
                else:
                    tech_ids = list(map(str, techs))
                if tech_ids:
                    parts.append("Techniques: " + ", ".join(tech_ids))
            tactics = mitre.get("tactics") or []
            if tactics:
                parts.append("Tactics: " + ", ".join(map(str, tactics)))
            if parts:
                mitre_line = "; ".join(parts)

        body = f"""# {t.get('title','Finding')}

**Severity (CVSS v3):** {t.get('cvss_score','TBD')} ({t.get('cvss_vector','TBD')})
**CWE:** {t.get('cwe','N/A')}
**Confidence:** {t.get('confidence','low')}
**Suggested bounty (USD):** ${t.get('recommended_bounty_usd',0)}

"""

        xss_type = t.get("xss_type")
        xss_context = t.get("xss_context")
        if xss_type:
            body += f"**XSS classification:** Type: {xss_type}; Context: {xss_context or 'unknown'}\n\n"

        body += f"""

## Summary
{t.get('summary','')}

## Validation & MITRE Context
**Validation:** Status: {validation_status}; Engines: {engines_str}
"""

        if per_engine_lines:
            body += "\n" + "\n".join(per_engine_lines) + "\n"

        body += f"""
**MITRE ATT&CK:** {mitre_line}

## Steps to reproduce
{t.get('repro','')}

## Impact
{t.get('impact','')}

## Recommended remediation
{t.get('remediation','')}
"""

        # Extract validation data for Proof of Concept section
        bacv = (t.get("validation") or {}).get("bac") or {}
        ssrfv = (t.get("validation") or {}).get("ssrf") or {}
        sqlv = (t.get("validation") or {}).get("sqlmap") or {}
        oauthv = (t.get("validation") or {}).get("oauth") or {}
        racev = (t.get("validation") or {}).get("race") or {}
        smugglingv = (t.get("validation") or {}).get("smuggling") or {}
        graphqlv = (t.get("validation") or {}).get("graphql") or {}

        # === Comprehensive Proof of Concept Section ===
        has_any_validation = bool(validation_engines)
        poc_validated = t.get("poc_validated", False)
        poc_quality = t.get("poc_quality_score", "low")
        
        if has_any_validation or poc_validated:
            body += """

## Proof of Concept

"""
            # Validation status
            if validation_status == "validated":
                body += "✅ **Validation Status:** Confirmed by automated validation engine(s)\n\n"
            elif validation_status == "planned":
                body += "⏳ **Validation Status:** Validation planned\n\n"
            elif validation_status == "error":
                body += "❌ **Validation Status:** Validation error occurred\n\n"
            else:
                body += f"ℹ️ **Validation Status:** {validation_status}\n\n"
            
            # POC Quality
            if poc_validated:
                quality_emoji = "🟢" if poc_quality == "high" else "🟡" if poc_quality == "medium" else "🔴"
                body += f"{quality_emoji} **POC Quality:** {poc_quality.upper()}\n\n"
            
            # Validation engines summary
            if validation_engines:
                body += "**Validation Engines Used:** " + ", ".join(validation_engines) + "\n\n"
            
            # Evidence summary
            evidence_parts = []
            if show_dalfox and dal_conf:
                evidence_parts.append("Dalfox confirmed XSS")
            if sqlv and sqlv.get("dbms"):
                evidence_parts.append(f"SQLmap detected {sqlv.get('dbms')}")
            if bacv and bacv.get("confirmed_issues_count", 0) > 0:
                evidence_parts.append("BAC checks confirmed access control issues")
            if ssrfv and ssrfv.get("confirmed_issues_count", 0) > 0:
                evidence_parts.append("SSRF checks confirmed request forgery")
            if oauthv and oauthv.get("vulnerable_count", 0) > 0:
                evidence_parts.append("OAuth checks confirmed misconfigurations")
            if racev and racev.get("vulnerable_count", 0) > 0:
                evidence_parts.append("Race condition checks confirmed vulnerabilities")
            if smugglingv and smugglingv.get("vulnerable", False):
                evidence_parts.append("Request smuggling checks confirmed vulnerability")
            if graphqlv and graphqlv.get("vulnerable", False):
                evidence_parts.append("GraphQL security checks confirmed vulnerabilities")
            
            if evidence_parts:
                body += "**Evidence Summary:**\n"
                for part in evidence_parts:
                    body += f"- {part}\n"
                body += "\n"

        if show_dalfox:
            body += f"""

## Validation Evidence (Automated)
- Dalfox result: {dal_result}
- Dalfox confirmed: {dal_conf}
- Dalfox payload: `{dal_payload}`

<details><summary>Raw Dalfox output</summary>

{dal_raw}

</details>
"""

        # BAC-specific validation evidence (when present)
        # (bacv already defined above for Proof of Concept section)
        # Render a BAC section whenever we have a BAC validation dict;
        # the test path patches _mcp_post to return meta only, so
        # engine_result may be missing.
        if bacv and isinstance(bacv, dict):
            body += """

## BAC Validation Details
"""
            body += f"- BAC result: {bacv.get('engine_result')}\n"
            checks = bacv.get("checks_count")
            confirmed = bacv.get("confirmed_issues_count")
            if checks is not None:
                body += f"- Checks run: {checks}\n"
            if confirmed is not None:
                body += f"- Confirmed issues: {confirmed}\n"
            if bacv.get("summary"):
                body += f"- Summary: {bacv.get('summary')}\n"

        # SSRF-specific validation evidence (when present)
        # (ssrfv already defined above for Proof of Concept section)
        if ssrfv and isinstance(ssrfv, dict) and ssrfv.get("engine_result"):
            body += """

## SSRF Validation Details
"""
            body += f"- SSRF result: {ssrfv.get('engine_result')}\n"
            checks = ssrfv.get("checks_count")
            confirmed = ssrfv.get("confirmed_issues_count")
            targets_reached = ssrfv.get("targets_reached") or []
            if checks is not None:
                body += f"- Checks run: {checks}\n"
            if confirmed is not None:
                body += f"- Confirmed issues: {confirmed}\n"
            if targets_reached:
                body += f"- Targets reached: {', '.join(map(str, targets_reached))}\n"
            if ssrfv.get("summary"):
                body += f"- Summary: {ssrfv.get('summary')}\n"

        # SQLmap-specific validation evidence (when present)
        # (sqlv already defined above for Proof of Concept section)
        if sqlv and isinstance(sqlv, dict) and sqlv.get("engine_result"):
            dbms = sqlv.get("dbms")
            vuln_params = sqlv.get("vulnerable_params") or []
            dump_summary = sqlv.get("dumped_data_summary")
            body += """

## SQLmap Validation Details
"""
            body += f"- SQLmap result: {sqlv.get('engine_result')}\n"
            if dbms:
                body += f"- Detected DBMS: {dbms}\n"
            if vuln_params:
                if isinstance(vuln_params, (list, tuple)):
                    vp_str = ", ".join(map(str, vuln_params))
                else:
                    vp_str = str(vuln_params)
                body += f"- Vulnerable parameters: {vp_str}\n"
            if dump_summary:
                body += f"- Data dump summary: {dump_summary}\n"

        # OAuth-specific validation evidence (when present)
        # (oauthv already defined above for Proof of Concept section)
        if oauthv and isinstance(oauthv, dict) and oauthv.get("engine_result"):
            body += """

## OAuth Validation Details
"""
            body += f"- OAuth result: {oauthv.get('engine_result')}\n"
            vulnerable_count = oauthv.get("vulnerable_count", 0)
            if vulnerable_count is not None:
                body += f"- Vulnerable tests: {vulnerable_count}\n"
            vulnerable_tests = oauthv.get("vulnerable_tests") or []
            if vulnerable_tests:
                body += f"- Vulnerable test types: {', '.join(map(str, vulnerable_tests))}\n"

        # Race Condition validation evidence (when present)
        # (racev already defined above for Proof of Concept section)
        if racev and isinstance(racev, dict) and racev.get("engine_result"):
            body += """

## Race Condition Validation Details
"""
            body += f"- Race condition result: {racev.get('engine_result')}\n"
            vulnerable_count = racev.get("vulnerable_count", 0)
            if vulnerable_count is not None:
                body += f"- Vulnerable endpoints: {vulnerable_count}\n"
            vulnerable_tests = racev.get("vulnerable_tests") or []
            if vulnerable_tests:
                body += f"- Vulnerable endpoints: {', '.join(map(str, vulnerable_tests[:5]))}\n"

        # Request Smuggling validation evidence (when present)
        # (smugglingv already defined above for Proof of Concept section)
        if smugglingv and isinstance(smugglingv, dict) and smugglingv.get("engine_result"):
            body += """

## Request Smuggling Validation Details
"""
            body += f"- Smuggling result: {smugglingv.get('engine_result')}\n"
            vulnerable = smugglingv.get("vulnerable", False)
            body += f"- Vulnerable: {vulnerable}\n"
            tests = smugglingv.get("tests") or []
            if tests:
                for test in tests[:3]:  # Show first 3 tests
                    if test.get("vulnerable"):
                        body += f"- Test {test.get('type')}: Vulnerable (elapsed: {test.get('elapsed', 'N/A')}s)\n"

        # GraphQL validation evidence (when present)
        # (graphqlv already defined above for Proof of Concept section)
        if graphqlv and isinstance(graphqlv, dict) and graphqlv.get("engine_result"):
            body += """

## GraphQL Security Validation Details
"""
            body += f"- GraphQL result: {graphqlv.get('engine_result')}\n"
            vulnerable = graphqlv.get("vulnerable", False)
            body += f"- Vulnerable: {vulnerable}\n"
            depth_attack = graphqlv.get("depth_attack") or {}
            if depth_attack.get("vulnerable"):
                body += f"- Depth attack: Vulnerable (depth: {depth_attack.get('depth', 'N/A')})\n"
            batching = graphqlv.get("batching") or {}
            if batching.get("vulnerable"):
                body += f"- Batching attack: Vulnerable (batches: {batching.get('batches_sent', 'N/A')})\n"

        # Request/Response Capture (when available)
        request_capture = (t.get("validation") or {}).get("request_capture") or t.get("request_capture")
        if request_capture:
            try:
                from tools.poc_capture import POCCapture
                capture = POCCapture()
                formatted = capture.format_for_report(request_capture)
                body += f"""

## Request/Response Capture

{formatted}
"""
            except Exception:
                pass

        # Screenshot (when available)
        screenshot = (t.get("validation") or {}).get("screenshot") or t.get("screenshot")
        if screenshot and os.path.exists(screenshot):
            body += f"""

## Screenshot Evidence

![POC Screenshot]({screenshot})
"""

        body += f"""

**Scope compliance:** Tested only within configured scope. Research header used: {H1_ALIAS}. Rate ≤ program rules.
"""
        return body

    for t in triaged:
        name = (t.get("title", "finding") or "finding").replace(" ", "_")[:80]
        path = os.path.join(out_dir, f"{scan_id}__{name}.md")
        open(path, "w").write(md(t, scope))
        print("[TRIAGE] Wrote", path)

    return triage_path


def _load_jsonl_findings(filepath: str) -> List[Dict[str, Any]]:
    """Load findings from a JSONL file (one JSON object per line).
    
    Used for targeted nuclei output which uses JSONL format.
    """
    findings: List[Dict[str, Any]] = []
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    # Tag the finding source for tracking
                    finding["_source"] = "targeted_nuclei"
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[RUNNER] Error loading JSONL from {filepath}: {e}")
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Agentic Bug Bounty Runner - Orchestrate security scans and triage findings"
    )
    parser.add_argument("--findings_file", help="ZAP findings JSON (for triage mode)")
    parser.add_argument("--scope_file", default="scope.json", help="Program scope JSON")
    parser.add_argument(
        "--mode",
        choices=["triage", "full-scan"],
        default="triage",
        help="Runner mode: triage existing findings or orchestrate full scan via MCP",
    )
    parser.add_argument("--mcp-url", help="Base URL for MCP server (default from MCP_BASE env)")
    parser.add_argument(
        "--profile",
        help="Scan profile to use (e.g., xss-heavy, sqli-heavy, full, recon-only)",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available scan profiles and exit",
    )
    args = parser.parse_args()

    # Handle --list-profiles
    if args.list_profiles:
        print("Available scan profiles:")
        if os.path.exists(PROFILES_DIR):
            for fname in sorted(os.listdir(PROFILES_DIR)):
                if fname.endswith(".yaml"):
                    profile_path = os.path.join(PROFILES_DIR, fname)
                    try:
                        with open(profile_path, "r", encoding="utf-8") as f:
                            p = yaml.safe_load(f)
                        name = fname.replace(".yaml", "")
                        desc = p.get("description", "No description")
                        print(f"  {name:15} - {desc}")
                    except Exception:
                        print(f"  {fname.replace('.yaml', ''):15} - (error loading)")
        else:
            print("  No profiles directory found")
        return

    # Load scan profile if specified
    global ACTIVE_PROFILE
    if args.profile:
        ACTIVE_PROFILE = load_profile(args.profile)
    else:
        print("[PROFILE] Using default profile settings")

    # Allow overriding MCP server base URL at runtime
    global MCP_SERVER_URL
    if args.mcp_url:
        MCP_SERVER_URL = args.mcp_url

    print(f"[TRIAGE] Using DALFOX_BIN={DALFOX_PATH} (docker={DALFOX_DOCKER})")

    scope = json.load(open(args.scope_file))
    out_dir = "output_zap"
    os.makedirs(out_dir, exist_ok=True)

    if args.mode == "full-scan":
        print(f"[RUNNER] Starting full-scan via MCP at {MCP_SERVER_URL}")
        summary = run_full_scan_via_mcp(scope)
        ts = int(time.time())
        summary_path = os.path.join(out_dir, f"program_run_{ts}.json")
        json.dump(summary, open(summary_path, "w"), indent=2)
        print("[RUNNER] Wrote full-scan summary", summary_path)

        # Auto-triage findings from all sources:
        # - zap_findings_*.json - ZAP scan results
        # - cloud_findings_*.json - Cloud recon results  
        # - targeted_nuclei_*.json - AI-driven targeted nuclei scans (JSONL format)
        # - katana_nuclei_*.json - Katana+Nuclei recon results
        for fname in os.listdir(out_dir):
            if not fname.endswith(".json"):
                continue
            
            findings_path = os.path.join(out_dir, fname)
            
            # Handle standard JSON findings (ZAP, cloud)
            if fname.startswith("zap_findings_") or fname.startswith("cloud_findings_"):
                print(f"[RUNNER] Auto-triaging findings from {findings_path}")
                run_triage_for_findings(findings_path, scope, out_dir=out_dir)
                continue
            
            # Handle targeted nuclei findings (JSONL format from AI-driven scans)
            # Skip already-converted files to prevent reprocessing JSON arrays as JSONL
            if fname.startswith("targeted_nuclei_") and not fname.endswith("_converted.json"):
                print(f"[RUNNER] Processing targeted nuclei findings from {findings_path}")
                nuclei_findings = _load_jsonl_findings(findings_path)
                if nuclei_findings:
                    # Write as standard JSON array for triage
                    converted_path = findings_path.replace(".json", "_converted.json")
                    with open(converted_path, "w", encoding="utf-8") as fh:
                        json.dump(nuclei_findings, fh, indent=2)
                    print(f"[RUNNER] Auto-triaging {len(nuclei_findings)} targeted nuclei findings")
                    run_triage_for_findings(converted_path, scope, out_dir=out_dir)
                continue
            
            # Handle Katana+Nuclei findings (nested JSON structure)
            if fname.startswith("katana_nuclei_") and not fname.endswith("_findings.json"):
                print(f"[RUNNER] Processing katana+nuclei findings from {findings_path}")
                try:
                    with open(findings_path, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                    nuclei_findings = data.get("nuclei_findings", [])
                    if nuclei_findings:
                        # Write findings as separate file for triage (always overwrite with fresh data)
                        findings_only_path = findings_path.replace(".json", "_findings.json")
                        with open(findings_only_path, "w", encoding="utf-8") as fh:
                            json.dump(nuclei_findings, fh, indent=2)
                        print(f"[RUNNER] Auto-triaging {len(nuclei_findings)} katana+nuclei findings")
                        run_triage_for_findings(findings_only_path, scope, out_dir=out_dir)
                except Exception as e:
                    print(f"[RUNNER] Error processing {fname}: {e}")
                continue
        
        return

    # Triaging an existing findings file
    if not args.findings_file:
        raise SystemExit("--findings_file is required in triage mode")

    run_triage_for_findings(args.findings_file, scope, out_dir=out_dir)


if __name__ == "__main__":
    main()

def _load_katana_nuclei_findings(output_dir: str, host: str) -> list[dict]:
    # simple heuristic: pick latest katana_nuclei_* file for that host
    files = [
        f for f in os.listdir(output_dir)
        if f.startswith("katana_nuclei_") and host.replace(":", "_") in f
    ]
    if not files:
        return []
    files.sort()
    path = os.path.join(output_dir, files[-1])
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("nuclei_findings", []) or []


def _load_targeted_nuclei_findings(output_dir: str, host: str) -> list[dict]:
    """Load findings from AI-driven targeted Nuclei scans (JSONL format)."""
    host_key = host.replace(":", "_").replace("/", "_")
    files = [
        f for f in os.listdir(output_dir)
        if f.startswith("targeted_nuclei_") and host_key in f and f.endswith(".json")
    ]
    if not files:
        return []
    files.sort()
    # Load the latest targeted nuclei output (JSONL format)
    path = os.path.join(output_dir, files[-1])
    findings: list[dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                # Tag the finding as coming from AI-targeted scan
                finding["_source"] = "targeted_nuclei"
                findings.append(finding)
            except json.JSONDecodeError:
                continue
    return findings


def gather_findings_for_triage(host: str, output_dir: str) -> list[dict]:
    findings: list[dict] = []

    # ...existing sources (cloud, zap, sqlmap, bac, ssrf, etc.)...

    # --- Nuclei findings from Katana run (recon-only) ---
    nuclei_from_katana = _load_katana_nuclei_findings(output_dir, host)
    findings.extend(nuclei_from_katana)

    # --- NEW: Nuclei findings from AI-targeted scan ---
    nuclei_from_targeted = _load_targeted_nuclei_findings(output_dir, host)
    findings.extend(nuclei_from_targeted)

    return findings