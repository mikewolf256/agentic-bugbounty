#!/usr/bin/env python3
"""
Agentic runner for MCP -> LLM triage + HackerOne report generation.

- Reads scope from local scope.json (project root or output folder)
- Optionally starts a ZAP scan via the MCP server
- Polls for findings and loads findings JSON
- Calls an OpenAI-compatible LLM to triage and produce HackerOne-ready submission drafts
- Produces combined report JSON + per-finding Markdown ready to paste into HackerOne

Usage:
    export OPENAI_API_KEY="sk-..."
    export H1_ALIAS="h1yourusername@wearehackerone.com"
    python agentic_runner.py --scan_id <SCAN_ID>          # triage existing scan
    python agentic_runner.py --start_scan api.23andme.com  # start a scan then triage when done
"""
import os
import time
import json
import argparse
import requests
from typing import List, Dict, Any, Optional

# ========== Configuration ==========
MCP_BASE = os.environ.get("MCP_BASE", "http://localhost:8100")
H1_ALIAS = os.environ.get("H1_ALIAS", "h1yourusername@wearehackerone.com")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")  # adjust if needed
POLL_INTERVAL = int(os.environ.get("AGENT_POLL_INTERVAL", "8"))
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.0"))

if not OPENAI_API_KEY:
    print("ERROR: set OPENAI_API_KEY in env before running.")
    raise SystemExit(1)

HEADERS = {"Content-Type": "application/json"}

# ---------- Helpers ----------
def call_mcp(path: str, method="GET", json_body: Optional[dict]=None, params: dict=None):
    url = MCP_BASE.rstrip("/") + path
    try:
        if method.upper() == "GET":
            r = requests.get(url, params=params, timeout=600)
        else:
            r = requests.post(url, json=json_body, params=params, timeout=600)
    except Exception as e:
        raise SystemExit(f"Error calling MCP {url}: {e}")
    if r.status_code >= 400:
        raise SystemExit(f"MCP returned {r.status_code}: {r.text}")
    try:
        return r.json()
    except Exception:
        return r.text

def openai_chat(messages: List[dict], model: str = LLM_MODEL, temperature: float = LLM_TEMPERATURE):
    """
    Minimal OpenAI Chat call using REST. If you use another LLM provider,
    replace this function with the appropriate API call.
    """
    url = "https://api.openai.com/v1/chat/completions"
    payload = {"model": model, "messages": messages, "temperature": temperature, "max_tokens": 1600}
    r = requests.post(url, headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}, json=payload, timeout=180)
    if r.status_code >= 400:
        raise SystemExit(f"LLM error {r.status_code}: {r.text}")
    js = r.json()
    return js["choices"][0]["message"]["content"].strip()

# ========== LLM prompt templates ==========
SYSTEM_PROMPT = """You are a senior web security engineer and a professional bug bounty triage reviewer.
You will be given: program scope, and a single raw finding JSON from ZAP (or similar).
Produce a strict JSON object with these keys:
 - title: short one-line title
 - cvss_vector: CVSS v3 vector string (or "TBD")
 - cvss_score: numeric score 0.0-10.0 (or 0)
 - summary: one- or two-sentence summary
 - repro: exact minimal reproduction steps (curl or HTTP request) with the required research header included where applicable
 - impact: prioritized impact paragraph
 - remediation: concise actionable remediation (1-3 lines)
 - cwe: CWE id or "N/A"
 - confidence: "high" | "medium" | "low"
 - recommended_bounty_usd: integer amount or 0
Return only valid JSON. Be conservative with scoring and recommended_bounty_usd. If the finding is noisy/low-value, set confidence to \"low\" and recommended_bounty_usd to 0.
Do NOT suggest or instruct on validating leaked credentials or performing social engineering.
"""

LLM_USER_PROMPT = """
Program scope (JSON):
{scope_json}

ZAP finding (raw JSON):
{finding_json}

Focus Areas: Sensitive Data Exposure, RCE, Authentication Bypass, Broken Access Control, SQLi, SSRF, File Uploads, XXE, XSS, cloud credentials, misconfigured cloud.

Now triage and produce the required JSON result.
"""

# ---------- LLM triage ----------
def triage_finding_with_llm(scope: dict, finding: dict) -> dict:
    msg_system = {"role": "system", "content": SYSTEM_PROMPT}
    user = LLM_USER_PROMPT.format(scope_json=json.dumps(scope, indent=2), finding_json=json.dumps(finding, indent=2))
    msg_user = {"role": "user", "content": user}
    resp_text = openai_chat([msg_system, msg_user])
    # try to parse JSON from LLM response
    try:
        parsed = json.loads(resp_text)
        return parsed
    except Exception:
        # fallback: wrap summarised text into a low-confidence structure
        return {
            "title": finding.get("name", "Finding"),
            "cvss_vector": "TBD",
            "cvss_score": 0,
            "summary": resp_text[:400],
            "repro": "See raw evidence in '_raw_finding'.",
            "impact": "See raw evidence",
            "remediation": "See raw evidence",
            "cwe": finding.get("cweid") or "N/A",
            "confidence": "low",
            "recommended_bounty_usd": 0
        }

# ---------- File / scope helpers ----------
def read_scope_local() -> dict:
    candidates = ["./output/scope.json", "./scope.json", "./output_zap/scope.json"]
    for p in candidates:
        if os.path.exists(p):
            return json.load(open(p))
    raise SystemExit("Scope JSON not found locally. Save scope.json in project root or output/")

def start_zap_and_get_scan_id(target: str) -> str:
    print(f"Starting ZAP scan for {target} ...")
    resp = call_mcp("/mcp/start_zap_scan", method="POST", json_body={"targets":[target]})
    scan_id = resp.get("our_scan_id")
    print("started:", scan_id)
    return scan_id

def poll_scan_results(scan_id: str, poll_interval: int = POLL_INTERVAL, timeout: int = 60*30) -> str:
    print("Polling MCP for scan results (this may take minutes)...")
    start = time.time()
    while True:
        out = call_mcp(f"/mcp/poll_zap/{scan_id}")
        if isinstance(out, dict) and out.get("findings_file"):
            return out["findings_file"]
        if time.time() - start > timeout:
            raise SystemExit("Timeout waiting for scan results")
        time.sleep(poll_interval)

def load_findings_from_file(path: str) -> List[dict]:
    return json.load(open(path))

# ---------- Output helpers ----------
def build_h1_markdown_from_triage(t: dict, scope: dict) -> str:
    title = t.get("title", "Finding")
    cvss_vector = t.get("cvss_vector", "TBD")
    cvss_score = t.get("cvss_score", "TBD")
    summary = t.get("summary", "")
    repro = t.get("repro", "")
    impact = t.get("impact", "")
    remediation = t.get("remediation", "")
    cwe = t.get("cwe", "N/A")
    md = f"""# {title}

**Severity (CVSS v3):** {cvss_score} ({cvss_vector})  
**CWE:** {cwe}

## Summary
{summary}

## Steps to reproduce
{repro}

## Impact
{impact}

## Recommended remediation
{remediation}

**Scope compliance:** Tested only within configured program scope. Research header used: {H1_ALIAS}. Rate limit honored per program rules.
"""
    return md

# ---------- Main agent flow ----------
def run_agent_for_scan(scan_id: Optional[str], start_scan_targets: Optional[List[str]]):
    scope = read_scope_local()
    if start_scan_targets:
        # basic scope enforcement
        for t in start_scan_targets:
            if t not in scope.get("primary_targets", []) and t not in scope.get("secondary_targets", []):
                raise SystemExit(f"Target {t} not in scope.json")
        scan_id = start_zap_and_get_scan_id(start_scan_targets[0])
    elif scan_id:
        pass
    else:
        raise SystemExit("Either pass --scan_id or --start_scan target(s)")

    findings_file = poll_scan_results(scan_id)
    print("Findings file:", findings_file)
    findings = load_findings_from_file(findings_file)
    print(f"Loaded {len(findings)} findings")

    triaged = []
    for f in findings:
        print("Triaging:", (f.get("name") or "finding")[:80])
        t = triage_finding_with_llm(scope, f)
        t["_raw_finding"] = f
        triaged.append(t)
        # be polite to LLM
        time.sleep(1.0)

    out_path = f"./output_zap/triage_{scan_id}.json"
    with open(out_path, "w") as fh:
        json.dump(triaged, fh, indent=2)
    print("Triage saved to", out_path)

    # write per-finding markdown
    for idx, t in enumerate(triaged):
        md = build_h1_markdown_from_triage(t, scope)
        safe_name = t.get("title", f"finding_{idx}").replace(" ", "_")[:80]
        fname = f"./output_zap/{scan_id}__{safe_name}.md"
        with open(fname, "w") as fh:
            fh.write(md)
        print("Wrote", fname)

    print("Agent run complete. Inspect output_zap/*.md for HackerOne-ready drafts.")

# ---------- CLI ----------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan_id", help="Existing our_scan_id to triage")
    parser.add_argument("--start_scan", nargs="+", help="Start a new scan on provided target(s) then triage first target")
    args = parser.parse_args()
    if args.start_scan:
        run_agent_for_scan(None, args.start_scan)
    else:
        if not args.scan_id:
            parser.print_help()
            raise SystemExit(1)
        run_agent_for_scan(args.scan_id, None)
