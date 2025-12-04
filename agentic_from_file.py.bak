#!/usr/bin/env python3
import os, json, time, argparse, requests

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")
H1_ALIAS = os.environ.get("H1_ALIAS","h1yourusername@wearehackerone.com")
if not OPENAI_API_KEY:
    raise SystemExit("Set OPENAI_API_KEY env var.")

SYSTEM_PROMPT = """You are a senior web security engineer and bug bounty triager.
Return STRICT JSON with keys: title, cvss_vector, cvss_score, summary, repro, impact, remediation, cwe, confidence, recommended_bounty_usd.
Be conservative. If low-value/noisy, confidence="low", recommended_bounty_usd=0. No leaked-credential validation or SE."""
USER_TMPL = """Program scope:
{scope}

Finding JSON:
{finding}
"""

def openai_chat(msgs):
    r = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type":"application/json"},
        json={"model": LLM_MODEL, "messages": msgs, "temperature": 0.0, "max_tokens": 1600},
        timeout=180,
    ); r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings_file", required=True)
    ap.add_argument("--scope_file", default="scope.json")
    args = ap.parse_args()
    scope = json.load(open(args.scope_file))
    findings = json.load(open(args.findings_file))
    out_dir = "output_zap"
    os.makedirs(out_dir, exist_ok=True)
    triaged = []
    for f in findings:
        msgs=[{"role":"system","content":SYSTEM_PROMPT},
              {"role":"user","content":USER_TMPL.format(scope=json.dumps(scope,indent=2),
                                                        finding=json.dumps(f,indent=2))}]
        try:
            txt = openai_chat(msgs)
            try:
                t = json.loads(txt)
            except Exception:
                t = {"title": f.get("name","Finding"), "cvss_vector":"TBD","cvss_score":0,
                     "summary": txt[:400], "repro":"See evidence", "impact":"See evidence",
                     "remediation":"See evidence","cwe": f.get("cweid") or "N/A",
                     "confidence":"low","recommended_bounty_usd":0}
        except Exception as e:
            t = {"title": f.get("name","Finding"), "cvss_vector":"TBD","cvss_score":0,
                 "summary": f"LLM error: {e}", "repro":"See evidence", "impact":"See evidence",
                 "remediation":"See evidence","cwe": f.get("cweid") or "N/A",
                 "confidence":"low","recommended_bounty_usd":0}
        t["_raw_finding"] = f
        triaged.append(t)
        time.sleep(1.0)
    scan_id = os.path.basename(args.findings_file).replace("zap_findings_","").replace(".json","")
    triage_path = os.path.join(out_dir, f"triage_{scan_id}.json")
    json.dump(triaged, open(triage_path,"w"), indent=2)
    print("Wrote", triage_path)
    # write per-finding markdown
    def md(t, scope):
        return f"""# {t.get('title','Finding')}

**Severity (CVSS v3):** {t.get('cvss_score','TBD')} ({t.get('cvss_vector','TBD')})
**CWE:** {t.get('cwe','N/A')}

## Summary
{t.get('summary','')}

## Steps to reproduce
{t.get('repro','')}

## Impact
{t.get('impact','')}

## Recommended remediation
{t.get('remediation','')}

**Scope compliance:** Tested only within configured scope. Research header used: {H1_ALIAS}. Rate ≤ program rules.
"""
    for t in triaged:
        name = t.get("title","finding").replace(" ","_")[:80]
        path = os.path.join(out_dir, f"{scan_id}__{name}.md")
        open(path,"w").write(md(t, scope))
        print("Wrote", path)

if __name__ == "__main__":
    main()
