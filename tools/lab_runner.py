#!/usr/bin/env python3
"""Lab Runner - Orchestrate vulnerable lab environments for testing.

This script manages dockerized vulnerable labs for testing the agentic
bug bounty pipeline. It can:
- Start/stop labs via docker-compose
- Run the full scan pipeline against a lab
- Compare findings against expected_findings in lab_metadata.json
- Output lab_results_<lab>_<ts>.json with detection scores
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
LABS_DIR = REPO_ROOT / "labs"
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", str(REPO_ROOT / "output_scans")))
MCP_URL = os.environ.get("MCP_URL", "http://127.0.0.1:8000")


def load_lab_metadata(lab_name: str) -> Dict[str, Any]:
    """Load lab metadata from lab_metadata.json."""
    lab_dir = LABS_DIR / lab_name
    meta_path = lab_dir / "lab_metadata.json"
    if not meta_path.exists():
        raise SystemExit(f"lab_metadata.json not found for lab {lab_name} at {meta_path}")
    return json.loads(meta_path.read_text(encoding="utf-8"))


def list_labs() -> List[str]:
    """List available labs."""
    if not LABS_DIR.exists():
        return []
    return [
        d.name for d in LABS_DIR.iterdir()
        if d.is_dir() and (d / "lab_metadata.json").exists()
    ]


def run_cmd(cmd: List[str], cwd: Optional[Path] = None, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and optionally check return code."""
    print(f"[lab_runner] $ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd or REPO_ROOT, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"[lab_runner] STDERR: {result.stderr}")
        raise SystemExit(f"Command failed with {result.returncode}: {' '.join(cmd)}")
    return result


def start_lab(lab_name: str) -> None:
    """Start a lab using docker-compose."""
    lab_dir = LABS_DIR / lab_name
    compose_file = lab_dir / "docker-compose.yml"
    
    if not compose_file.exists():
        raise SystemExit(f"docker-compose.yml not found for lab {lab_name}")
    
    print(f"[lab_runner] Starting lab: {lab_name}")
    run_cmd(["docker-compose", "-f", str(compose_file), "up", "-d", "--build"], cwd=lab_dir)
    
    # Wait for lab to be ready
    meta = load_lab_metadata(lab_name)
    base_url = meta.get("base_url", "http://localhost:8080")
    print(f"[lab_runner] Waiting for lab to be ready at {base_url}...")
    
    for i in range(30):  # 30 second timeout
        try:
            import requests
            resp = requests.get(base_url, timeout=2)
            if resp.status_code < 500:
                print(f"[lab_runner] Lab is ready (status {resp.status_code})")
                return
        except Exception:
            pass
        time.sleep(1)
    
    print("[lab_runner] Warning: Lab may not be fully ready")


def stop_lab(lab_name: str) -> None:
    """Stop a lab using docker-compose."""
    lab_dir = LABS_DIR / lab_name
    compose_file = lab_dir / "docker-compose.yml"
    
    if not compose_file.exists():
        print(f"[lab_runner] No docker-compose.yml found for {lab_name}, skipping")
        return
    
    print(f"[lab_runner] Stopping lab: {lab_name}")
    run_cmd(["docker-compose", "-f", str(compose_file), "down"], cwd=lab_dir, check=False)


def run_scan(lab_name: str, profile: Optional[str] = None) -> Dict[str, Any]:
    """Run the full scan pipeline against a lab."""
    meta = load_lab_metadata(lab_name)
    base_url = meta.get("base_url", "http://localhost:8080")
    
    # Configure scope via MCP (Phase 1: Scope Configuration Helper)
    try:
        from tools.lab_scope_helper import configure_lab_scope
        scope = configure_lab_scope(lab_name, mcp_url=MCP_URL)
        print(f"[lab_runner] Scope configured via MCP for {lab_name}")
    except Exception as e:
        print(f"[lab_runner] Warning: Failed to configure scope via MCP: {e}")
        # Fallback to creating scope file only
        scope = {
            "program_name": f"lab-{meta.get('name', lab_name)}",
            "primary_targets": [base_url],
            "secondary_targets": [],
            "rules": {},
            "in_scope": [{"url": base_url}],
        }
    
    # Create scope file for this lab (for agentic_runner.py)
    scope_path = REPO_ROOT / f"scope.lab.{lab_name}.json"
    scope_path.write_text(json.dumps(scope, indent=2), encoding="utf-8")
    print(f"[lab_runner] Wrote scope file: {scope_path}")
    
    # Build command
    cmd = [
        sys.executable, str(REPO_ROOT / "agentic_runner.py"),
        "--mode", "full-scan",
        "--scope_file", str(scope_path),
        "--mcp-url", MCP_URL,
    ]
    
    if profile:
        cmd.extend(["--profile", profile])
    
    # Run the scan
    print(f"[lab_runner] Running scan against {base_url}...")
    result = run_cmd(cmd, check=False)
    
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def load_findings(lab_name: str) -> List[Dict[str, Any]]:
    """Load findings from the latest scan output."""
    findings: List[Dict[str, Any]] = []
    
    # Look for triage JSON files
    if not OUTPUT_DIR.exists():
        return findings
    
    for fpath in OUTPUT_DIR.glob("*_triage_*.json"):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                findings.extend(data)
            elif isinstance(data, dict):
                findings.append(data)
        except Exception:
            continue
    
    # Also check for targeted nuclei findings
    for fpath in OUTPUT_DIR.glob("targeted_nuclei_*.json"):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        findings.append(json.loads(line))
        except Exception:
            continue
    
    return findings


def validate_findings(lab_name: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compare findings against expected findings from lab metadata."""
    meta = load_lab_metadata(lab_name)
    expected = meta.get("expected_findings", [])
    
    results = {
        "lab_name": lab_name,
        "timestamp": int(time.time()),
        "total_expected": len(expected),
        "total_found": len(findings),
        "matched": [],
        "missed": [],
        "extra": [],
        "detection_rate": 0.0,
    }
    
    # Index expected findings by type/pattern
    expected_patterns = {}
    for exp in expected:
        key = (exp.get("type", ""), exp.get("cwe", ""))
        expected_patterns[key] = exp
    
    # Match findings against expected
    matched_keys = set()
    for finding in findings:
        title = (finding.get("title") or finding.get("template-id") or "").lower()
        cwe = finding.get("cwe", "")
        
        # Try to match
        matched = False
        for key, exp in expected_patterns.items():
            exp_type = exp.get("type", "").lower()
            exp_cwe = exp.get("cwe", "")
            exp_pattern = exp.get("pattern", "").lower()
            
            if (
                (exp_type and exp_type in title) or
                (exp_cwe and exp_cwe.lower() in cwe.lower()) or
                (exp_pattern and exp_pattern in title)
            ):
                if key not in matched_keys:
                    results["matched"].append({
                        "expected": exp,
                        "found": {"title": title, "cwe": cwe},
                    })
                    matched_keys.add(key)
                matched = True
                break
        
        if not matched:
            results["extra"].append({"title": title, "cwe": cwe})
    
    # Find missed expected findings
    for key, exp in expected_patterns.items():
        if key not in matched_keys:
            results["missed"].append(exp)
    
    # Calculate detection rate
    if results["total_expected"] > 0:
        results["detection_rate"] = len(results["matched"]) / results["total_expected"]
    
    return results


def main(argv: Optional[List[str]] = None) -> None:
    ap = argparse.ArgumentParser(
        description="Lab Runner - Orchestrate vulnerable labs for testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --list                    # List available labs
  %(prog)s --lab xss-basic --start   # Start a lab
  %(prog)s --lab xss-basic --scan    # Run scan against a lab
  %(prog)s --lab xss-basic --validate # Compare findings to expected
  %(prog)s --lab xss-basic --full    # Start, scan, validate, stop
  %(prog)s --lab xss-basic --stop    # Stop a lab
        """
    )
    ap.add_argument("--lab", help="Lab name (directory under labs/)")
    ap.add_argument("--list", action="store_true", help="List available labs")
    ap.add_argument("--start", action="store_true", help="Start the lab")
    ap.add_argument("--stop", action="store_true", help="Stop the lab")
    ap.add_argument("--scan", action="store_true", help="Run scan against the lab")
    ap.add_argument("--validate", action="store_true", help="Validate findings against expected")
    ap.add_argument("--full", action="store_true", help="Full cycle: start, scan, validate, stop")
    ap.add_argument("--profile", help="Scan profile to use (e.g., xss-heavy)")
    mcp_url_default = os.environ.get("MCP_URL", "http://127.0.0.1:8000")
    ap.add_argument("--mcp-url", default=mcp_url_default, help=f"MCP server URL (default: {mcp_url_default})")
    ap.add_argument("--test-all", action="store_true", help="Test all labs")
    ap.add_argument("--test-new", action="store_true", help="Test only new labs (15 new ones)")
    
    args = ap.parse_args(argv)
    
    global MCP_URL
    MCP_URL = args.mcp_url
    
    # Handle --list
    if args.list:
        labs = list_labs()
        if not labs:
            print("No labs found. Create labs under labs/ directory.")
        else:
            print("Available labs:")
            for lab in sorted(labs):
                try:
                    meta = load_lab_metadata(lab)
                    desc = meta.get("description", "No description")
                    print(f"  {lab:20} - {desc}")
                except Exception:
                    print(f"  {lab:20} - (error loading metadata)")
        return
    
    # Require lab name for other operations
    if not args.lab and (args.start or args.stop or args.scan or args.validate or args.full):
        ap.error("--lab is required for this operation")
    
    # Validate lab exists
    if args.lab:
        lab_dir = LABS_DIR / args.lab
        if not lab_dir.exists():
            available = list_labs()
            raise SystemExit(f"Lab '{args.lab}' not found. Available: {', '.join(available)}")
    
    # Handle --full (complete cycle)
    if args.full:
        args.start = True
        args.scan = True
        args.validate = True
        # Note: stop at the end, handled below
    
    # Execute operations
    if args.start:
        start_lab(args.lab)
    
    if args.scan:
        scan_result = run_scan(args.lab, profile=args.profile)
        print(f"[lab_runner] Scan completed with return code: {scan_result['returncode']}")
    
    if args.validate:
        findings = load_findings(args.lab)
        print(f"[lab_runner] Loaded {len(findings)} findings for validation")
        
        validation = validate_findings(args.lab, findings)
        
        # Print summary
        print("\n" + "=" * 60)
        print(f"Lab Validation Results: {args.lab}")
        print("=" * 60)
        print(f"Expected findings: {validation['total_expected']}")
        print(f"Matched findings:  {len(validation['matched'])}")
        print(f"Missed findings:   {len(validation['missed'])}")
        print(f"Extra findings:    {len(validation['extra'])}")
        print(f"Detection rate:    {validation['detection_rate']:.1%}")
        
        if validation['missed']:
            print("\nMissed expected findings:")
            for m in validation['missed']:
                print(f"  - {m.get('type', 'unknown')}: {m.get('description', 'N/A')}")
        
        # Save results
        OUTPUT_DIR.mkdir(exist_ok=True)
        results_path = OUTPUT_DIR / f"lab_results_{args.lab}_{int(time.time())}.json"
        results_path.write_text(json.dumps(validation, indent=2), encoding="utf-8")
        print(f"\n[lab_runner] Wrote results to: {results_path}")
    
    if args.full or args.stop:
        if args.full:
            # Small delay before stopping
            time.sleep(2)
        stop_lab(args.lab)
    
    # Handle --test-all and --test-new
    if args.test_all or args.test_new:
        from tools.lab_test_suite import test_all_labs, list_new_labs, list_all_labs
        if args.test_new:
            lab_names = list_new_labs()
            print(f"[lab_runner] Testing {len(lab_names)} new labs")
        else:
            lab_names = list_all_labs()
            print(f"[lab_runner] Testing all {len(lab_names)} labs")
        
        results = test_all_labs(
            lab_names=lab_names,
            mcp_url=MCP_URL,
            profile=args.profile
        )
        return
    
    if not any([args.list, args.start, args.stop, args.scan, args.validate, args.full, args.test_all, args.test_new]):
        ap.print_help()


if __name__ == "__main__":
    main()
