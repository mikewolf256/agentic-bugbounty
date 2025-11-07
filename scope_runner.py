#!/usr/bin/env python3
import os, time, json, requests, argparse, subprocess, shlex

MCP_BASE = os.environ.get("MCP_BASE", "http://localhost:8100")
H1_ALIAS = os.environ.get("H1_ALIAS", "h1yourusername@wearehackerone.com")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")
POLL_INTERVAL = int(os.environ.get("AGENT_POLL_INTERVAL", "8"))

OUTDIR = "output_zap"
os.makedirs(OUTDIR, exist_ok=True)

def call_mcp(path, method="GET", data=None):
    url = MCP_BASE.rstrip("/") + path
    if method == "GET":
        r = requests.get(url, timeout=180)
    else:
        r = requests.post(url, json=data, timeout=180)
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        return r.text

def zap_ready():
    try:
        v = requests.get("http://localhost:8080/JSON/core/view/version/", timeout=10).json()
        return bool(v.get("version"))
    except Exception:
        return False

def start_scan(host):
    print(f"==> start_zap_scan: {host}")
    resp = call_mcp("/mcp/start_zap_scan", "POST", {"targets":[host]})
    return resp["our_scan_id"]

def poll_scan(scan_id):
    print(f"   polling: {scan_id}")
    while True:
        try:
            out = call_mcp(f"/mcp/poll_zap/{scan_id}")
            if isinstance(out, dict) and out.get("findings_file"):
                return out["findings_file"], out.get("count", 0)
        except requests.HTTPError as e:
            # If server restarted and forgot the job but file exists, try to locate it
            pass
        time.sleep(POLL_INTERVAL)

def export_reports(scan_id):
    try:
        resp = call_mcp(f"/mcp/export_report/{scan_id}", "POST")
        return resp.get("reports", [])
    except Exception as e:
        print(f"   export_report warning: {e}")
        return []

def triage_with_ai(findings_file, scope_file):
    if not OPENAI_API_KEY:
        print("   [skip AI triage] OPENAI_API_KEY not set.")
        return
    cmd = f'python agentic_from_file.py --findings_file {shlex.quote(findings_file)} --scope_file {shlex.quote(scope_file)}'
    print("   triage:", cmd)
    subprocess.run(cmd, shell=True, check=False)

def ffuf_discovery(host, wordlist=None):
    # Optional quick discovery; keep gentle and in scope.
    if not wordlist:
        return
    target = f"https://{host}/FUZZ"
    body = {
        "target": target,
        "wordlist": wordlist,
        "rate": 3
    }
    try:
        print(f"   ffuf discovery on {host} with {wordlist}")
        out = call_mcp("/mcp/run_ffuf", "POST", body)
        # Save ffuf raw output alongside host
        with open(os.path.join(OUTDIR, f"ffuf_{host}.json"), "w") as fh:
            json.dump(out, fh, indent=2)
    except Exception as e:
        print(f"   ffuf error: {e}")

def run_scope(scope_path, include_secondary=True, ffuf_wordlist=None):
    scope = json.load(open(scope_path))
    primary = scope.get("primary_targets", [])
    secondary = scope.get("secondary_targets", []) if include_secondary else []

    if not zap_ready():
        print("ZAP API not reachable at http://localhost:8080 — start the ZAP container first.")
        return

    hosts = list(primary) + list(secondary)
    print(f"Targets: {hosts}")
    for host in hosts:
        print(f"\n=== Host: {host} ===")
        # Optional lightweight ffuf discovery before/after ZAP
        if ffuf_wordlist:
            ffuf_discovery(host, ffuf_wordlist)

        scan_id = start_scan(host)
        findings_file, count = poll_scan(scan_id)
        print(f"   findings: {count} -> {findings_file}")

        # Export HackerOne-style markdown from MCP
        reports = export_reports(scan_id)
        print(f"   reports: {len(reports)} files")

        # AI triage → writes triage_<scan>.json and per-finding md
        triage_with_ai(findings_file, scope_path)

    print("\nAll done. Check output_zap/ for findings, triage, and reports.")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", default="scope.json", help="path to scope.json")
    ap.add_argument("--no-secondary", action="store_true", help="scan only primary targets")
    ap.add_argument("--ffuf-wordlist", help="optional path to a (reasonable) wordlist")
    args = ap.parse_args()
    run_scope(args.scope, include_secondary=not args.no_secondary, ffuf_wordlist=args.ffuf_wordlist)

