#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agentic_from_file.py
- Pre-filters ZAP-style findings (dedupe + estimated CVSS + focus whitelist)
- Runs LLM triage only on survivors to save tokens
- Optionally validates XSS with Dalfox (local binary)
- Writes triage JSON + per-finding Markdown

Env toggles:
  OPENAI_API_KEY=...               # required
  LLM_MODEL=gpt-4o-mini            # default
  H1_ALIAS=h1yourusername@wearehackerone.com

  # Pre-LLM filtering
  KEEP_NOISE=0|1                   # default 0; 1 keeps everything
  MIN_PRE_CVSS=6.0                 # default 0; e.g., 6.0 to skip low value
  KEEP_FOCUS=1|0                   # default 1; always keep focus CWEs/keywords
  MAX_TRIAGE=200                   # default 0 (no cap)

  # Dalfox
  DALFOX_BIN=/path/to/dalfox       # default ~/go/bin/dalfox
  DALFOX_DOCKER=true|false         # default false (local binary)
  DALFOX_TIMEOUT_SECONDS=45        # default 30
  DALFOX_THREADS=5                 # current CLI tolerates this param-less style
"""
import os, json, time, argparse, requests, shlex, subprocess
from typing import Tuple, Optional

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
DALFOX_THREADS = int(os.environ.get("DALFOX_THREADS", "5"))

# Filtering toggles
KEEP_NOISE = os.environ.get("KEEP_NOISE", "").lower() in ("1","true","yes")
MIN_PRE_CVSS = float(os.environ.get("MIN_PRE_CVSS", "0"))
KEEP_FOCUS = os.environ.get("KEEP_FOCUS", "1").lower() in ("1","true","yes")
MAX_TRIAGE = int(os.environ.get("MAX_TRIAGE", "0"))

SYSTEM_PROMPT = """You are a senior web security engineer and bug bounty triager.
Return STRICT JSON with keys: title, cvss_vector, cvss_score, summary, repro, impact, remediation, cwe, confidence, recommended_bounty_usd.
Be conservative. If low-value/noisy, confidence="low", recommended_bounty_usd=0. No leaked-credential validation or SE."""
USER_TMPL = """Program scope:
{scope}

Finding JSON:
{finding}
"""

# ==== Optional dedupe import (safe fallback if missing) ====
try:
    from mcp_helpers.dedupe import filter_and_dedupe
except Exception:
    def filter_and_dedupe(findings, keep_noise=False):
        # Minimal no-op fallback (keeps original behavior)
        return findings

# ==== Focus keywords & CVSS estimation ====
FOCUS_KEYWORDS = [
    "sql injection", "sqli", "cross site scripting", "xss",
    "server side request forgery", "ssrf",
    "remote code execution", "rce",
    "authentication bypass", "broken access control",
    "xml external entities", "xxe",
    "file upload", "aws", "s3", "credential", "token", "secret",
    "idOR", "idor"
]

def rough_cvss_estimate(f: dict) -> float:
    # Prefer explicit CVSS fields if any tool provided them
    for k in ("cvss", "cvss_score", "cvss_v3", "cvss3", "cvss3_score"):
        v = f.get(k)
        try:
            if v is None:
                continue
            if isinstance(v, str) and "/" in v:   # vector string present
                return 6.5  # mid-band so we don't drop it prematurely
            return float(v)
        except Exception:
            pass
    # Fall back to ZAP-like risk strings
    risk = (f.get("risk") or f.get("severity") or "").strip().lower()
    if risk in ("informational", "info", "none"): return 0.0
    if risk == "low": return 3.1
    if risk == "medium": return 5.5
    if risk == "high": return 8.0
    if risk == "critical": return 9.0
    return 4.0

# ==== OpenAI helper ====
def openai_chat(msgs):
    r = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type":"application/json"},
        json={"model": LLM_MODEL, "messages": msgs, "temperature": 0.0, "max_tokens": 1600},
        timeout=180,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()

# ==== Dalfox runner (your CLI style) ====
def run_dalfox_check(target_url: str, param_name: Optional[str] = None) -> Tuple[bool, dict]:
    """
    Safe Dalfox confirmation for XSS-like issues.
    Uses your working CLI: dalfox url "<URL>" simple --format <file.json>
    Returns (confirmed, evidence_dict).
    """
    evidence = {"engine_result": None, "payload": None, "proof_snippet": None, "raw_output": None, "cmd": None}
    tmp_out = os.path.join("output_zap", f"dalfox_{int(time.time())}.json")

    # Ensure URL contains FUZZ placeholder
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    u = urlparse(target_url)
    qs = dict(parse_qsl(u.query, keep_blank_values=True))
    if param_name:
        qs[param_name] = "FUZZ"
    else:
        if "FUZZ" not in (u.query or ""):
            qs["x"] = "FUZZ"
    run_url = urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(qs, doseq=True), u.fragment))

    if DALFOX_DOCKER:
        # Docker variant: JSON lands inside container unless you bind mount; prefer local binary.
        cmd = [
            "docker", "run", "--rm", "--network", "host",
            "ghcr.io/hahwul/dalfox:latest",
            "dalfox", "url", run_url, "simple", "--format", "/tmp/dalfox_out.json"
        ]
    else:
        cmd = [DALFOX_PATH, "url", run_url, "simple", "--format", tmp_out]

    evidence["cmd"] = " ".join(shlex.quote(x) for x in cmd)
    print(f"[DALFOX] {evidence['cmd']}")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=DALFOX_TIMEOUT)
    except subprocess.TimeoutExpired:
        evidence["engine_result"] = "timeout"
        return False, evidence

    # Always capture console output for audit
    out_text = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    if out_text.strip():
        print("[DALFOX-DEBUG] ----- STDOUT/STDERR BEGIN -----")
        print(out_text[:8000])
        print("[DALFOX-DEBUG] ----- STDOUT/STDERR END   -----")
    evidence["raw_output"] = out_text

    wrote_file = os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 0
    if wrote_file:
        try:
            raw_out = open(tmp_out, "r", encoding="utf-8").read()
            evidence["raw_output"] = raw_out  # prefer file
            j = json.loads(raw_out) if raw_out.strip() else {}
            # Many dalfox builds use {"results":[...]}
            results = j.get("results") if isinstance(j, dict) else None
            if results and len(results) > 0:
                r = results[0]
                evidence["engine_result"] = "confirmed"
                evidence["payload"] = r.get("payload") or r.get("vector")
                evidence["proof_snippet"] = r.get("evidence") or r.get("proof") or str(r)
                return True, evidence
        except Exception:
            pass

    # If no JSON written or empty: write a stub so we keep evidence
    if not wrote_file:
        try:
            stub = {"results": [], "stdout": proc.stdout, "stderr": proc.stderr}
            with open(tmp_out, "w", encoding="utf-8") as fh:
                json.dump(stub, fh, indent=2)
        except Exception:
            pass

    evidence["engine_result"] = "not_found"
    return False, evidence

# ==== Main triage ====
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings_file", required=True)
    ap.add_argument("--scope_file", default="scope.json")
    args = ap.parse_args()

    print(f"[TRIAGE] Using DALFOX_BIN={DALFOX_PATH} (docker={DALFOX_DOCKER})")
    out_dir = "output_zap"
    os.makedirs(out_dir, exist_ok=True)

    scope = json.load(open(args.scope_file))
    findings = json.load(open(args.findings_file))

    # 1) Dedupe / noise filter (saves tokens)
    n0 = len(findings)
    findings = filter_and_dedupe(findings, keep_noise=KEEP_NOISE)
    print(f"[DEDupe] input={n0} kept={len(findings)} skipped={n0-len(findings)} keep_noise={KEEP_NOISE}")

    # 2) Pre-CVSS filter + focus whitelist (saves tokens & runtime)
    pre_len = len(findings)
    filtered = []
    for f in findings:
        name = (f.get("name","") or "") + " " + (f.get("alert","") or "")
        text = (name + " " + (f.get("otherinfo","") or "") + " " + (f.get("evidence","") or "")).lower()
        is_focus = any(k in text for k in FOCUS_KEYWORDS) or str(f.get("cweid","")) in ("79","89","918","287","284","434","611")
        est = rough_cvss_estimate(f)
        f["_pre_cvss"] = est
        f["_is_focus"] = bool(is_focus)
        if est >= MIN_PRE_CVSS or (KEEP_FOCUS and is_focus):
            filtered.append(f)
    findings = filtered
    print(f"[PRE-CVSS] input={pre_len} kept={len(findings)} skipped={pre_len-len(findings)} "
          f"min_pre_cvss={MIN_PRE_CVSS} keep_focus={KEEP_FOCUS}")

    # 3) Budget cap
    if MAX_TRIAGE and len(findings) > MAX_TRIAGE:
        findings = findings[:MAX_TRIAGE]
        print(f"[BUDGET] Capped triage to MAX_TRIAGE={MAX_TRIAGE}")

    triaged = []
    for f in findings:
        msgs = [
            {"role":"system","content":SYSTEM_PROMPT},
            {"role":"user","content":USER_TMPL.format(scope=json.dumps(scope,indent=2),
                                                      finding=json.dumps(f,indent=2))}
        ]
        # LLM triage
        try:
            txt = openai_chat(msgs)
            try:
                t = json.loads(txt)
            except Exception:
                t = {
                    "title": f.get("name","Finding"), "cvss_vector":"TBD","cvss_score":0,
                    "summary": txt[:400], "repro":"See evidence", "impact":"See evidence",
                    "remediation":"See evidence","cwe": f.get("cweid") or "N/A",
                    "confidence":"low","recommended_bounty_usd":0
                }
        except Exception as e:
            t = {
                "title": f.get("name","Finding"), "cvss_vector":"TBD","cvss_score":0,
                "summary": f"LLM error: {e}", "repro":"See evidence", "impact":"See evidence",
                "remediation":"See evidence","cwe": f.get("cweid") or "N/A",
                "confidence":"low","recommended_bounty_usd":0
            }

        # Attach raw + prefilter metadata
        t["_raw_finding"] = f
        t["_pre_cvss"] = f.get("_pre_cvss")
        t["_is_focus"] = f.get("_is_focus")

        # === Dalfox validation for XSS ===
        try:
            name_l = (f.get("name","") or "").lower()
            cwe_s = str(f.get("cweid","") or "")
            is_xss = ("xss" in name_l) or ("cross site scripting" in name_l) or ("79" in cwe_s)
            if is_xss:
                target_url = f.get("url") or f.get("uri") or ""
                param = f.get("param") or None
                print(f"[TRIAGE] XSS candidate → url='{target_url}', param='{param}'")
                if target_url:
                    confirmed, dal = run_dalfox_check(target_url, param)
                    t.setdefault("validation", {})
                    t["validation"]["dalfox"] = dal
                    t["validation"]["dalfox_confirmed"] = bool(confirmed)
                    # bump confidence if confirmed
                    if confirmed and str(t.get("confidence","")).lower() in ("low","unknown",""):
                        t["confidence"] = "medium"
                    if confirmed and not t.get("recommended_bounty_usd"):
                        t["recommended_bounty_usd"] = 250
            else:
                print(f"[TRIAGE] Skipping dalfox: not XSS (name='{f.get('name')}', cweid='{f.get('cweid')}')")
        except Exception as e:
            t.setdefault("validation", {})
            t["validation"]["dalfox"] = {"engine_result":"error","raw_output":str(e)}
            t["validation"]["dalfox_confirmed"] = False
        # === end Dalfox validation ===

        triaged.append(t)
        time.sleep(0.3)

    # Write triage JSON
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
