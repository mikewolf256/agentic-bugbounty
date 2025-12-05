#!/usr/bin/env python3
"""
Multi-Scope Runner - Orchestrate scanning across multiple scopes using Kubernetes workers.

This script enables parallel scanning of multiple bug bounty scopes, leveraging
the local Kubernetes infrastructure for distributed execution.

Usage:
    python tools/multi_scope_runner.py --scopes scope1.json scope2.json
    python tools/multi_scope_runner.py --scopes-dir scopes/
    python tools/multi_scope_runner.py --scopes scope1.json --max-concurrent 2
"""

import os
import sys
import json
import time
import argparse
import subprocess
import shlex
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from tools.local_executor import LocalExecutor, is_local_k8s_mode
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    LocalExecutor = None
    is_local_k8s_mode = lambda: False
    print("[WARN] LocalExecutor not available. K8s mode disabled.", file=sys.stderr)

MCP_BASE = os.environ.get("MCP_BASE", "http://localhost:8000")
OUTPUT_DIR = Path("output_zap")
OUTPUT_DIR.mkdir(exist_ok=True)


class MultiScopeRunner:
    """Orchestrate scanning across multiple scopes."""
    
    def __init__(
        self,
        k8s_mode: bool = True,
        max_concurrent: int = 3,
        output_dir: Optional[Path] = None,
    ):
        self.k8s_mode = k8s_mode and K8S_AVAILABLE and is_local_k8s_mode()
        self.max_concurrent = max_concurrent
        self.output_dir = output_dir or OUTPUT_DIR
        
        if self.k8s_mode:
            try:
                self.executor = LocalExecutor()
                print("[MULTI-SCOPE] K8s mode enabled")
            except Exception as e:
                print(f"[MULTI-SCOPE] K8s mode failed: {e}, falling back to local mode", file=sys.stderr)
                self.k8s_mode = False
                self.executor = None
        else:
            self.executor = None
            print("[MULTI-SCOPE] Local mode (no K8s)")
    
    def call_mcp(self, path: str, method: str = "GET", data: Optional[Dict] = None) -> Any:
        """Call MCP server endpoint."""
        import requests
        url = MCP_BASE.rstrip("/") + path
        try:
            if method == "GET":
                r = requests.get(url, timeout=180)
            else:
                r = requests.post(url, json=data, timeout=180)
            r.raise_for_status()
            try:
                return r.json()
            except Exception:
                return r.text
        except Exception as e:
            print(f"[MCP] Error calling {path}: {e}", file=sys.stderr)
            return None
    
    def zap_ready(self) -> bool:
        """Check if ZAP is ready."""
        try:
            import requests
            v = requests.get("http://localhost:8080/JSON/core/view/version/", timeout=10).json()
            return bool(v.get("version"))
        except Exception:
            return False
    
    def start_zap_scan(self, host: str) -> Optional[str]:
        """Start a ZAP scan for a host."""
        resp = self.call_mcp("/mcp/start_zap_scan", "POST", {"targets": [host]})
        if resp and isinstance(resp, dict):
            return resp.get("our_scan_id") or resp.get("scan_id")
        return None
    
    def poll_zap_scan(self, scan_id: str, poll_interval: int = 8) -> tuple:
        """Poll ZAP scan until complete."""
        while True:
            try:
                out = self.call_mcp(f"/mcp/poll_zap/{scan_id}")
                if isinstance(out, dict) and out.get("findings_file"):
                    return out["findings_file"], out.get("count", 0)
                if isinstance(out, dict) and out.get("status") == "error":
                    return None, 0
            except Exception:
                pass
            time.sleep(poll_interval)
    
    def run_tool_via_k8s(self, tool: str, target: str) -> Optional[Dict[str, Any]]:
        """Run a tool via K8s worker."""
        if not self.executor:
            return None
        try:
            return self.executor.submit_and_wait(tool, target)
        except Exception as e:
            print(f"[K8S] Error running {tool} for {target}: {e}", file=sys.stderr)
            return None
    
    def run_recon_for_host(self, host: str) -> Dict[str, Any]:
        """Run reconnaissance tools for a host."""
        results = {
            "host": host,
            "whatweb": None,
            "katana": None,
            "nuclei": None,
        }
        
        # WhatWeb fingerprinting
        if self.k8s_mode:
            print(f"  [RECON] Running WhatWeb for {host}...")
            results["whatweb"] = self.run_tool_via_k8s("whatweb", host)
        
        # Katana crawling (if available)
        if self.k8s_mode:
            print(f"  [RECON] Running Katana for {host}...")
            results["katana"] = self.run_tool_via_k8s("katana", host)
        
        # Nuclei scanning (if available)
        if self.k8s_mode:
            print(f"  [RECON] Running Nuclei for {host}...")
            results["nuclei"] = self.run_tool_via_k8s("nuclei", host)
        
        return results
    
    def run_scope(self, scope_path: str) -> Dict[str, Any]:
        """Run scanning for a single scope."""
        scope_file = Path(scope_path)
        if not scope_file.exists():
            return {
                "scope": scope_path,
                "status": "error",
                "error": f"Scope file not found: {scope_path}",
            }
        
        scope_name = scope_file.stem
        with open(scope_file) as f:
            scope_data = json.load(f)
        
        print(f"\n{'='*60}")
        print(f"Processing scope: {scope_name}")
        print(f"{'='*60}")
        
        # Extract targets
        primary = scope_data.get("primary_targets", [])
        secondary = scope_data.get("secondary_targets", [])
        in_scope = scope_data.get("in_scope", [])
        
        # Extract URLs from in_scope if present
        hosts = list(primary) + list(secondary)
        if in_scope:
            for entry in in_scope:
                url = entry.get("url") or entry.get("target") or ""
                if url and url not in hosts:
                    hosts.append(url)
        
        if not hosts:
            return {
                "scope": scope_name,
                "status": "error",
                "error": "No targets found in scope",
            }
        
        print(f"Targets: {len(hosts)} hosts")
        
        # Create scope-specific output directory
        scope_output_dir = self.output_dir / f"scope_{scope_name}"
        scope_output_dir.mkdir(exist_ok=True)
        
        scope_results = {
            "scope": scope_name,
            "scope_file": str(scope_path),
            "targets": hosts,
            "started_at": datetime.utcnow().isoformat(),
            "zap_scans": {},
            "recon_results": {},
            "findings_files": [],
            "triage_files": [],
            "reports": [],
            "status": "running",
        }
        
        # Check ZAP availability
        if not self.zap_ready():
            print("  [WARN] ZAP not available, skipping ZAP scans")
        else:
            # Start ZAP scans for each host
            for host in hosts:
                print(f"\n  [ZAP] Starting scan for {host}...")
                scan_id = self.start_zap_scan(host)
                if scan_id:
                    scope_results["zap_scans"][host] = scan_id
                    print(f"    Scan ID: {scan_id}")
        
        # Run recon tools in parallel (if k8s mode)
        if self.k8s_mode:
            print(f"\n  [RECON] Running reconnaissance tools...")
            for host in hosts:
                recon_result = self.run_recon_for_host(host)
                scope_results["recon_results"][host] = recon_result
                # Save recon results
                recon_file = scope_output_dir / f"recon_{host.replace('://', '_').replace('/', '_')}.json"
                with open(recon_file, "w") as f:
                    json.dump(recon_result, f, indent=2)
        
        # Poll ZAP scans
        print(f"\n  [ZAP] Polling scans...")
        for host, scan_id in scope_results["zap_scans"].items():
            print(f"    Polling {host} (scan_id: {scan_id})...")
            findings_file, count = self.poll_zap_scan(scan_id)
            if findings_file:
                scope_results["findings_files"].append(findings_file)
                print(f"      Found {count} findings -> {findings_file}")
        
        # Run triage for each findings file
        if scope_results["findings_files"]:
            print(f"\n  [TRIAGE] Running AI triage...")
            for findings_file in scope_results["findings_files"]:
                if not os.path.exists(findings_file):
                    continue
                print(f"    Triage for {findings_file}...")
                try:
                    cmd = [
                        sys.executable,
                        "agentic_from_file.py",
                        "--findings_file", findings_file,
                        "--scope_file", scope_path,
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                    if result.returncode == 0:
                        # Find generated triage file
                        scan_id = Path(findings_file).stem.replace("zap_findings_", "")
                        triage_file = self.output_dir / f"triage_{scan_id}.json"
                        if triage_file.exists():
                            scope_results["triage_files"].append(str(triage_file))
                            print(f"      Triage complete -> {triage_file}")
                except Exception as e:
                    print(f"      Triage error: {e}", file=sys.stderr)
        
        # Export reports
        print(f"\n  [REPORTS] Exporting reports...")
        for host, scan_id in scope_results["zap_scans"].items():
            try:
                resp = self.call_mcp(f"/mcp/export_report/{scan_id}", "POST")
                if resp and isinstance(resp, dict):
                    reports = resp.get("reports", [])
                    scope_results["reports"].extend(reports)
                    print(f"    Exported {len(reports)} reports for {host}")
            except Exception as e:
                print(f"    Report export error for {host}: {e}", file=sys.stderr)
        
        scope_results["status"] = "completed"
        scope_results["completed_at"] = datetime.utcnow().isoformat()
        
        # Save scope results
        results_file = scope_output_dir / "scope_results.json"
        with open(results_file, "w") as f:
            json.dump(scope_results, f, indent=2)
        
        print(f"\n  [DONE] Scope {scope_name} completed")
        return scope_results
    
    def run_scopes(self, scope_files: List[str]) -> Dict[str, Any]:
        """Run scanning for multiple scopes."""
        print(f"\n{'='*80}")
        print(f"Multi-Scope Runner")
        print(f"  Scopes: {len(scope_files)}")
        print(f"  Max concurrent: {self.max_concurrent}")
        print(f"  K8s mode: {self.k8s_mode}")
        print(f"{'='*80}\n")
        
        all_results = {
            "started_at": datetime.utcnow().isoformat(),
            "scopes": [],
            "summary": {},
        }
        
        # Run scopes with thread pool for parallel execution
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            future_to_scope = {
                executor.submit(self.run_scope, scope_file): scope_file
                for scope_file in scope_files
            }
            
            for future in as_completed(future_to_scope):
                scope_file = future_to_scope[future]
                try:
                    result = future.result()
                    all_results["scopes"].append(result)
                except Exception as e:
                    print(f"[ERROR] Scope {scope_file} failed: {e}", file=sys.stderr)
                    all_results["scopes"].append({
                        "scope": scope_file,
                        "status": "error",
                        "error": str(e),
                    })
        
        # Generate summary
        completed = sum(1 for s in all_results["scopes"] if s.get("status") == "completed")
        failed = len(all_results["scopes"]) - completed
        total_findings = sum(len(s.get("findings_files", [])) for s in all_results["scopes"])
        total_reports = sum(len(s.get("reports", [])) for s in all_results["scopes"])
        
        all_results["summary"] = {
            "total_scopes": len(scope_files),
            "completed": completed,
            "failed": failed,
            "total_findings_files": total_findings,
            "total_reports": total_reports,
        }
        all_results["completed_at"] = datetime.utcnow().isoformat()
        
        # Save aggregated results
        summary_file = self.output_dir / "multi_scope_summary.json"
        with open(summary_file, "w") as f:
            json.dump(all_results, f, indent=2)
        
        print(f"\n{'='*80}")
        print(f"Multi-Scope Scan Complete")
        print(f"  Completed: {completed}/{len(scope_files)}")
        print(f"  Failed: {failed}")
        print(f"  Total findings files: {total_findings}")
        print(f"  Total reports: {total_reports}")
        print(f"  Summary: {summary_file}")
        print(f"{'='*80}\n")
        
        return all_results


def main():
    parser = argparse.ArgumentParser(
        description="Run scans across multiple scopes using Kubernetes workers"
    )
    parser.add_argument(
        "--scopes",
        nargs="+",
        help="List of scope JSON files to scan",
    )
    parser.add_argument(
        "--scopes-dir",
        help="Directory containing scope JSON files",
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=3,
        help="Maximum concurrent scopes (default: 3)",
    )
    parser.add_argument(
        "--no-k8s",
        action="store_true",
        help="Disable K8s mode (use local execution)",
    )
    parser.add_argument(
        "--output-dir",
        default="output_zap",
        help="Output directory (default: output_zap)",
    )
    
    args = parser.parse_args()
    
    # Collect scope files
    scope_files = []
    if args.scopes:
        scope_files.extend(args.scopes)
    if args.scopes_dir:
        scope_dir = Path(args.scopes_dir)
        if scope_dir.exists():
            scope_files.extend(scope_dir.glob("*.json"))
    
    if not scope_files:
        print("Error: No scope files specified. Use --scopes or --scopes-dir", file=sys.stderr)
        sys.exit(1)
    
    # Create runner
    runner = MultiScopeRunner(
        k8s_mode=not args.no_k8s,
        max_concurrent=args.max_concurrent,
        output_dir=Path(args.output_dir),
    )
    
    # Run scopes
    results = runner.run_scopes(scope_files)
    
    # Exit with error if any scopes failed
    if results["summary"]["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

