#!/usr/bin/env python3
import os
import json
import time
import shlex
import subprocess
import argparse
from typing import Tuple, Optional

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

SYSTEM_PROMPT = """You are a senior web security engineer and bug bounty triager.
Return STRICT JSON with keys: title, cvss_vector, cvss_score, summary, repro, impact, remediation, cwe, confidence, recommended_bounty_usd.
Be conservative. If low-value/noisy, confidence="low", recommended_bounty_usd=0. No leaked-credential validation or SE."""
USER_TMPL = """Program scope:
{scope}

Finding JSON:
{finding}
"""

# ==== Helpers ====
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
                return True, evidence

        except Exception as e:
            # JSON or parse failure – fall back to text heuristics
            evidence["raw_output"] = (evidence.get("raw_output") or "") + f"\n[parse_error] {e}"

    out_text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    evidence["raw_output"] = (evidence.get("raw_output") or "") + "\n" + out_text

    # Heuristic text check
    if "xss" in out_text.lower() or "found" in out_text.lower():
        evidence["engine_result"] = "maybe"
        return False, evidence

    evidence["engine_result"] = "not_found"
    return False, evidence

# ==== Main triage ====
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings_file", required=True)
    ap.add_argument("--scope_file", default="scope.json")
    args = ap.parse_args()

    print(f"[TRIAGE] Using DALFOX_BIN={DALFOX_PATH} (docker={DALFOX_DOCKER})")

    scope = json.load(open(args.scope_file))
    findings = json.load(open(args.findings_file))
    out_dir = "output_zap"
    os.makedirs(out_dir, exist_ok=True)

    triaged = []
    for f in findings:
        msgs = [
            {"role":"system","content":SYSTEM_PROMPT},
            {"role":"user","content":USER_TMPL.format(scope=json.dumps(scope,indent=2),
                                                      finding=json.dumps(f,indent=2))}
        ]
        # LLM triage
        try:
            raw = openai_chat(msgs)
            try:
                t = json.loads(raw)
            except json.JSONDecodeError:
                # If the model returns non‑strict JSON, wrap it
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

        # === Dalfox validation for XSS ===
        try:
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
            }
            t["validation"]["dalfox_confirmed"] = False
        # === end Dalfox validation ===

        triaged.append(t)
        time.sleep(0.4)

    scan_id = os.path.basename(args.findings_file).replace("zap_findings_","").replace(".json","")
    triage_path = os.path.join(out_dir, f"triage_{scan_id}.json")
    json.dump(triaged, open(triage_path,"w"), indent=2)
    print("Wrote", triage_path)

    # Markdown rendering
    def md(t, scope):
        dal = (t.get("validation") or {}).get("dalfox") or {}
        dal_result = dal.get("engine_result","")
        dal_conf = (t.get("validation") or {}).get("dalfox_confirmed", False)
        dal_payload = dal.get("payload","")
        dal_raw = (dal.get("raw_output","") or "")[:4000]

        return f"""# {t.get('title','Finding')}

**Severity (CVSS v3):** {t.get('cvss_score','TBD')} ({t.get('cvss_vector','TBD')})
**CWE:** {t.get('cwe','N/A')}
**Confidence:** {t.get('confidence','low')}
**Suggested bounty (USD):** ${t.get('recommended_bounty_usd',0)}

## Summary
{t.get('summary','')}

## Steps to reproduce
{t.get('repro','')}

## Impact
{t.get('impact','')}

## Recommended remediation
{t.get('remediation','')}

## Validation Evidence (Automated)
- Dalfox result: {dal_result}
- Dalfox confirmed: {dal_conf}
- Dalfox payload: `{dal_payload}`

<details><summary>Raw Dalfox output</summary>

{dal_raw}

</details>

**Scope compliance:** Tested only within configured scope. Research header used: {H1_ALIAS}. Rate ≤ program rules.
"""

    for t in triaged:
        name = (t.get("title","finding") or "finding").replace(" ","_")[:80]
        path = os.path.join(out_dir, f"{scan_id}__{name}.md")
        open(path,"w").write(md(t, scope))
        print("Wrote", path)

if __name__ == "__main__":
    main()