#!/usr/bin/env python3
"""Test Discord Alerts with Full Lab Scan

This script runs a complete full scan against a lab, which will:
1. Discover vulnerabilities
2. Run AI triage (assigns CVSS scores and bounty estimates)
3. Queue high-value findings for validation
4. Send Discord alerts for queued findings

Prerequisites:
- Set OPENAI_API_KEY environment variable
- Set DISCORD_WEBHOOK_URL environment variable (optional, for testing alerts)
- Lab must be running (command_injection_lab on port 5013)
- MCP server must be running on port 8000
"""

import os
import sys
import json
import time
import requests
from pathlib import Path

# Add tools to path
REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

MCP_URL = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8000")
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", str(REPO_ROOT / "output_scans")))
OUTPUT_DIR.mkdir(exist_ok=True, parents=True)

# Test lab - using command_injection_lab which we know works
TEST_LAB = "command_injection_lab"
TEST_LAB_PORT = 5013
TEST_LAB_URL = f"http://localhost:{TEST_LAB_PORT}"


def check_prerequisites():
    """Check if all prerequisites are met."""
    print("=" * 70)
    print("Checking Prerequisites")
    print("=" * 70)
    
    issues = []
    
    # Check OpenAI API key
    if not os.environ.get("OPENAI_API_KEY"):
        issues.append("OPENAI_API_KEY not set (required for AI triage)")
    else:
        print("✓ OPENAI_API_KEY is set")
    
    # Check Discord webhook (optional but recommended)
    if not os.environ.get("DISCORD_WEBHOOK_URL"):
        print("⚠️  DISCORD_WEBHOOK_URL not set - alerts will not be sent")
        print("   Set it with: export DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...'")
    else:
        print("✓ DISCORD_WEBHOOK_URL is set")
    
    # Check MCP server
    try:
        resp = requests.get(f"{MCP_URL}/mcp/health", timeout=5)
        if resp.status_code == 200:
            print(f"✓ MCP server is running at {MCP_URL}")
        else:
            issues.append(f"MCP server returned status {resp.status_code}")
    except Exception as e:
        issues.append(f"MCP server not reachable: {e}")
    
    # Check lab
    try:
        resp = requests.get(TEST_LAB_URL, timeout=5)
        if resp.status_code < 500:
            print(f"✓ Lab is reachable at {TEST_LAB_URL}")
        else:
            issues.append(f"Lab returned status {resp.status_code}")
    except Exception as e:
        issues.append(f"Lab not reachable: {e}")
        print(f"   Start it with: docker-compose up {TEST_LAB}")
    
    if issues:
        print("\n❌ Prerequisites not met:")
        for issue in issues:
            print(f"   - {issue}")
        return False
    
    print("\n✓ All prerequisites met!")
    return True


def configure_scope():
    """Configure scope for all running labs (not just the test lab)."""
    from pathlib import Path
    import json
    
    scope = {
        "program_name": f"test-{TEST_LAB}",
        # primary_targets: Only the test lab - this is what gets scanned/recon
        "primary_targets": [TEST_LAB_URL],
        "secondary_targets": [],
        "rules": {
            "rate_limit": 100,
            "excluded_vuln_types": [],
            "requires_poc": False,
        },
        # in_scope: All labs (for scope enforcement - allows testers to access all labs)
        # But recon only runs on primary_targets, not all of in_scope
        "in_scope": [
            {"url": TEST_LAB_URL},
            {"url": f"localhost:{TEST_LAB_PORT}"},
        ],
    }
    
    # Add all lab endpoints to scope (both localhost and Docker service names)
    # This ensures all testers can run against their respective labs
    labs_dir = REPO_ROOT / "labs"
    if labs_dir.exists():
        # Port mapping for labs (from docker-compose.yml)
        lab_port_map = {
            "command_injection_lab": 5013,
            "path_traversal_lab": 5014,
            "file_upload_lab": 5015,
            "csrf_lab": 5016,
            "nosql_injection_lab": 5017,
            "ldap_injection_lab": 5018,
            "mass_assignment_lab": 5019,
            "websocket_lab": 5020,
            "ssi_injection_lab": 5022,
            "crypto_weakness_lab": 5023,
            "parameter_pollution_lab": 5024,
            "dns_rebinding_lab": 5025,
            "cache_poisoning_lab": 5026,
            "random_generation_lab": 5027,
        }
        
        # Add ALL labs to in_scope for scope enforcement (so testers can access them)
        # But recon will only run on primary_targets (just the test lab)
        all_labs_added = 0
        for lab_dir in labs_dir.iterdir():
            if lab_dir.is_dir():
                meta_path = lab_dir / "lab_metadata.json"
                if meta_path.exists():
                    try:
                        meta = json.loads(meta_path.read_text(encoding="utf-8"))
                        base_url = meta.get("base_url", "")
                        lab_name = lab_dir.name
                        
                        if base_url:
                            # Add base URL (could be localhost or Docker service name)
                            if {"url": base_url} not in scope["in_scope"]:
                                scope["in_scope"].append({"url": base_url})
                                all_labs_added += 1
                            
                            # Also add localhost version if we have a port mapping
                            if lab_name in lab_port_map:
                                port = lab_port_map[lab_name]
                                localhost_url = f"http://localhost:{port}"
                                localhost_host = f"localhost:{port}"
                                
                                # Add localhost URLs
                                if {"url": localhost_url} not in scope["in_scope"]:
                                    scope["in_scope"].append({"url": localhost_url})
                                if {"url": localhost_host} not in scope["in_scope"]:
                                    scope["in_scope"].append({"url": localhost_host})
                                
                                # Also add Docker service name format (for tester access)
                                docker_url = f"http://{lab_name}:5000"
                                docker_host = f"{lab_name}:5000"
                                if {"url": docker_url} not in scope["in_scope"]:
                                    scope["in_scope"].append({"url": docker_url})
                                if {"url": docker_host} not in scope["in_scope"]:
                                    scope["in_scope"].append({"url": docker_host})
                    except Exception:
                        pass  # Skip if lab metadata can't be loaded
        
        if all_labs_added > 0:
            print(f"   Added {all_labs_added} labs to in_scope (for scope enforcement)")
            print(f"   Note: Recon will only run on primary_targets ({TEST_LAB_URL})")
    
    try:
        resp = requests.post(f"{MCP_URL}/mcp/set_scope", json=scope, timeout=10)
        resp.raise_for_status()
        print(f"\n✓ Scope configured with {len(scope['in_scope'])} targets")
        print(f"   Primary: {TEST_LAB_URL}")
        print(f"   Total in-scope URLs: {len(scope['in_scope'])}")
        print(f"   Includes: localhost ports, Docker service names, and lab base URLs")
        return scope
    except Exception as e:
        print(f"\n✗ Failed to configure scope: {e}")
        import traceback
        traceback.print_exc()
        return None


def run_full_scan(scope):
    """Run a full scan via agentic_runner."""
    print("\n" + "=" * 70)
    print("Running Full Scan")
    print("=" * 70)
    print(f"Target: {TEST_LAB_URL}")
    print("This will:")
    print("  1. Run Katana + Nuclei discovery")
    print("  2. Run targeted vulnerability tests")
    print("  3. Run AI triage (assigns CVSS scores)")
    print("  4. Queue high-value findings (CVSS >= 7.0 or bounty >= $500)")
    print("  5. Send Discord alerts for queued findings")
    print("\nThis may take 2-5 minutes...\n")
    
    try:
        from agentic_runner import run_full_scan_via_mcp
        
        start_time = time.time()
        summary = run_full_scan_via_mcp(scope, program_id=f"test-{TEST_LAB}")
        elapsed = time.time() - start_time
        
        print(f"\n✓ Scan completed in {elapsed:.1f} seconds")
        
        # Print summary
        hosts = summary.get("hosts", [])
        print(f"\nScan Summary:")
        print(f"  Hosts scanned: {len(hosts)}")
        
        modules = summary.get("modules", {})
        for host, host_modules in modules.items():
            print(f"\n  Host: {host}")
            for module_name, module_data in host_modules.items():
                if isinstance(module_data, dict):
                    findings_file = module_data.get("findings_file")
                    if findings_file:
                        print(f"    {module_name}: {findings_file}")
        
        return summary
    except Exception as e:
        print(f"\n✗ Scan failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def check_validation_queue():
    """Check validation queue and show queued findings."""
    print("\n" + "=" * 70)
    print("Checking Validation Queue")
    print("=" * 70)
    
    try:
        from tools.human_validation_workflow import HumanValidationWorkflow
        
        workflow = HumanValidationWorkflow()
        pending = workflow.get_pending_validations(program_name=f"test-{TEST_LAB}")
        stats = workflow.get_stats()
        
        print(f"\nValidation Queue Status:")
        print(f"  Pending:  {stats['pending']}")
        print(f"  Approved: {stats['approved']}")
        print(f"  Rejected: {stats['rejected']}")
        print(f"  Total:    {stats['total']}")
        
        if pending:
            print(f"\n✓ Found {len(pending)} findings queued for validation:")
            print("\nQueued Findings:")
            for i, v in enumerate(pending, 1):
                finding = v.get("finding", {})
                title = finding.get("title", "Unknown")
                cvss = finding.get("cvss_score", 0.0)
                bounty = finding.get("estimated_bounty", 0)
                url = finding.get("url") or finding.get("_raw_finding", {}).get("url", "N/A")
                
                print(f"\n  [{i}] {v['validation_id']}")
                print(f"      Title: {title}")
                print(f"      CVSS: {cvss:.1f} | Estimated Bounty: ${bounty}")
                print(f"      URL: {url}")
                print(f"      Queued: {v.get('queued_at', 'N/A')}")
            
            print(f"\n✓ Discord alerts should have been sent for these findings")
            print(f"  Check your Discord channel to verify")
        else:
            print("\n⚠️  No findings in validation queue")
            print("  This could mean:")
            print("    - Findings didn't meet threshold (CVSS >= 7.0 or bounty >= $500)")
            print("    - Triage didn't assign high enough scores")
            print("    - Human validation is disabled in profile")
        
        return {
            "pending_count": len(pending),
            "validations": pending,
            "stats": stats,
        }
    except Exception as e:
        print(f"\n✗ Failed to check validation queue: {e}")
        import traceback
        traceback.print_exc()
        return {"pending_count": 0, "error": str(e)}


def main():
    """Main test function."""
    print("\n" + "=" * 70)
    print("Discord Alert Test - Full Scan")
    print("=" * 70)
    
    # Step 1: Check prerequisites
    if not check_prerequisites():
        print("\n❌ Prerequisites not met. Please fix the issues above and try again.")
        return 1
    
    # Step 2: Configure scope
    scope = configure_scope()
    if not scope:
        print("\n❌ Failed to configure scope")
        return 1
    
    # Step 3: Run full scan
    summary = run_full_scan(scope)
    if not summary:
        print("\n❌ Scan failed")
        return 1
    
    # Step 4: Wait a moment for triage to complete
    print("\n⏳ Waiting for triage and validation workflow to complete...")
    time.sleep(3)
    
    # Step 5: Check validation queue
    queue_info = check_validation_queue()
    
    # Final summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Lab: {TEST_LAB}")
    print(f"Lab URL: {TEST_LAB_URL}")
    print(f"Scan completed: ✓")
    print(f"Findings queued: {queue_info.get('pending_count', 0)}")
    
    if queue_info.get("pending_count", 0) > 0:
        print(f"\n✅ SUCCESS: {queue_info['pending_count']} findings queued for validation")
        print("✅ Discord alerts should have been sent")
        print("\nNext steps:")
        print("  1. Check your Discord channel for validation alerts")
        print("  2. Review findings: python tools/validation_cli.py list")
        print("  3. Approve/reject: python tools/validation_cli.py approve <validation_id>")
    else:
        print("\n⚠️  No findings were queued")
        print("This could be normal if findings didn't meet the threshold.")
        print("You can still test Discord alerts directly:")
        print("  python -c \"from tools.alerting import get_alert_manager; get_alert_manager().send_discord_validation_alert('test-123', {'title': 'Test', 'cvss_score': 9.0, 'estimated_bounty': 1000, 'url': 'http://test.com'}, 'test-program')\"")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

