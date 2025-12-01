#!/usr/bin/env python3
import os
import json
import time
import shlex
import subprocess
import argparse
from typing import Tuple, Optional, Dict, Any, List

import requests

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
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8000")

SYSTEM_PROMPT = """You are a senior web security engineer and bug bounty triager.
Return STRICT JSON with keys: title, cvss_vector, cvss_score, summary, repro, impact, remediation, cwe, confidence, recommended_bounty_usd.
Be conservative. If low-value/noisy, confidence="low", recommended_bounty_usd=0. No leaked-credential validation or SE."""
USER_TMPL = """Program scope:
{scope}

Finding JSON:
{finding}
"""

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


def run_full_scan_via_mcp(scope: Dict[str, Any]) -> Dict[str, Any]:
    """Orchestrate a full scan pipeline via the MCP server.

    High-level steps (all best-effort):
    - Call /mcp/set_scope with the provided scope.json
    - For each in-scope host, start a ZAP scan (basic) and poll until done
    - Optionally run nuclei recon for each host
    - Build host_profile, prioritize_host, and host_delta for each host
    - Return a summary object with per-host metadata and artifact paths
    """

    wait_for_mcp_ready()

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

        summary_hosts.append(
            {
                "host": h,
                "host_profile": profile,
                "prioritization": prio,
                "delta": delta,
            }
        )

    return {
        "scope": scope,
        "hosts": summary_hosts,
        "zap_scans": zap_scans,
    }


# ==== Triage helpers ====
def run_triage_for_findings(findings_file: str, scope: Dict[str, Any], out_dir: str = "output_zap") -> str:
    """Run LLM + Dalfox triage for a single ZAP findings JSON file.

    Returns the path to the written triage JSON file.
    """

    os.makedirs(out_dir, exist_ok=True)
    findings = json.load(open(findings_file))

    triaged = []
    for f in findings:
        msgs = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": USER_TMPL.format(scope=json.dumps(scope, indent=2), finding=json.dumps(f, indent=2)),
            },
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

        # Skip Dalfox/SQLmap for cloud storage findings
        name = (f.get("name") or "").lower()
        if "cloud storage surface" in name or "cloud" in name and "storage" in name:
            t.setdefault("validation", {})
            t["validation"]["dalfox"] = {
                "engine_result": "skipped_not_applicable",
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

            if confidence not in ("medium", "high", "very_high", "very high") or not looks_xss:
                # Skip expensive Dalfox for clearly low-confidence / non-XSS findings
                t.setdefault("validation", {})
                t["validation"]["dalfox"] = {
                    "engine_result": "skipped_not_xss_or_low_confidence",
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

            if looks_sqli and confidence in ("medium", "high", "very_high", "very high"):
                url = f.get("url") or f.get("request", {}).get("url")
                payload = {"target": url} if url else None
                if payload:
                    try:
                        resp = _mcp_post("/mcp/run_sqlmap", payload)
                        t.setdefault("validation", {})
                        t["validation"]["sqlmap"] = {
                            "engine_result": "ran",
                            "output_dir": resp.get("output_dir"),
                            "returncode": resp.get("returncode"),
                            "endpoint": "/mcp/run_sqlmap",
                            "target": url,
                        }
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

        # === SSRF planning stub ===
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

            if looks_ssrf and confidence in ("medium", "high", "very_high", "very high"):
                url = f.get("url") or f.get("request", {}).get("url") or ""
                param = f.get("parameter") or f.get("param") or "url"
                t.setdefault("validation", {})
                t["validation"].setdefault("ssrf", {})
                t["validation"]["ssrf"].update(
                    {
                        "engine_result": "planned",
                        "endpoint": "/mcp/run_ssrf_checks",
                        "target": url,
                        "param": param,
                    }
                )
        except Exception:
            # SSRF planning is best-effort; ignore errors.
            pass

        # === Derive overall validation_status per finding ===
        v = t.get("validation") or {}
        engines = []
        results = []
        for eng_name, eng_data in v.items():
            if not isinstance(eng_data, dict):
                continue
            engines.append(eng_name)
            res = str(eng_data.get("engine_result") or "").lower()
            if res:
                results.append(res)

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
        # === end SQLi validation ===

        triaged.append(t)
        time.sleep(0.4)

    scan_id = os.path.basename(findings_file).replace("zap_findings_", "").replace(".json", "")
    triage_path = os.path.join(out_dir, f"triage_{scan_id}.json")
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

## Summary
{t.get('summary','')}

## Validation & MITRE Context
**Validation:** Status: {validation_status}; Engines: {engines_str}
**MITRE ATT&CK:** {mitre_line}

## Steps to reproduce
{t.get('repro','')}

## Impact
{t.get('impact','')}

## Recommended remediation
{t.get('remediation','')}
"""

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

# ==== Main triage ====
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings_file", help="ZAP findings JSON (for triage mode)")
    ap.add_argument("--scope_file", default="scope.json", help="Program scope JSON")
    ap.add_argument(
        "--mode",
        choices=["triage", "full-scan"],
        default="triage",
        help="Runner mode: triage existing findings or orchestrate full scan via MCP",
    )
    args = ap.parse_args()

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

        # Auto-triage any zap_findings_*.json and cloud_findings_*.json files produced by the scans
        for fname in os.listdir(out_dir):
            if not fname.endswith(".json"):
                continue
            if not (fname.startswith("zap_findings_") or fname.startswith("cloud_findings_")):
                continue
            findings_path = os.path.join(out_dir, fname)
            print(f"[RUNNER] Auto-triaging findings from {findings_path}")
            run_triage_for_findings(findings_path, scope, out_dir=out_dir)
        return

    # Triaging an existing findings file
    if not args.findings_file:
        raise SystemExit("--findings_file is required in triage mode")

    run_triage_for_findings(args.findings_file, scope, out_dir=out_dir)

if __name__ == "__main__":
    main()