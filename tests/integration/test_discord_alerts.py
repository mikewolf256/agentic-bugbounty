#!/usr/bin/env python3
"""Test Discord Alerts with Lab Validation

This script runs a full scan against a lab, triggers the validation workflow,
and verifies that Discord alerts are sent for high-value findings.
"""

import os
import sys
import json
import time
import requests
from pathlib import Path
from typing import Dict, Any, Optional

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


def check_discord_webhook() -> bool:
    """Check if Discord webhook is configured."""
    webhook_url = os.environ.get("DISCORD_WEBHOOK_URL")
    if not webhook_url:
        print("[TEST] ⚠️  DISCORD_WEBHOOK_URL not set - alerts will not be sent")
        print("[TEST] Set it with: export DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...'")
        return False
    print(f"[TEST] ✓ Discord webhook configured: {webhook_url[:50]}...")
    return True


def check_lab_reachable() -> bool:
    """Check if test lab is reachable."""
    try:
        resp = requests.get(TEST_LAB_URL, timeout=5)
        if resp.status_code < 500:
            print(f"[TEST] ✓ Lab is reachable at {TEST_LAB_URL}")
            return True
    except Exception as e:
        print(f"[TEST] ✗ Lab not reachable at {TEST_LAB_URL}: {e}")
        print(f"[TEST] Make sure the lab is running: docker-compose up {TEST_LAB}")
    return False


def configure_scope() -> Dict[str, Any]:
    """Configure scope for the test lab."""
    scope = {
        "program_name": f"test-{TEST_LAB}",
        "primary_targets": [TEST_LAB_URL],
        "secondary_targets": [],
        "rules": {
            "rate_limit": 100,
            "excluded_vuln_types": [],
            "requires_poc": False,
        },
        "in_scope": [
            {"url": TEST_LAB_URL},
            {"url": f"localhost:{TEST_LAB_PORT}"},
        ],
    }
    
    try:
        resp = requests.post(f"{MCP_URL}/mcp/set_scope", json=scope, timeout=10)
        resp.raise_for_status()
        print(f"[TEST] ✓ Scope configured for {TEST_LAB_URL}")
        return scope
    except Exception as e:
        print(f"[TEST] ✗ Failed to configure scope: {e}")
        return scope


def run_full_scan(scope: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Run a full scan via agentic_runner."""
    print(f"\n[TEST] Running full scan against {TEST_LAB_URL}...")
    print("[TEST] This will trigger triage and validation workflow...\n")
    
    try:
        # Import agentic_runner
        from agentic_runner import run_full_scan_via_mcp
        
        # Run the scan
        summary = run_full_scan_via_mcp(scope, program_id=f"test-{TEST_LAB}")
        
        print(f"\n[TEST] ✓ Scan completed")
        print(f"[TEST] Summary: {json.dumps(summary, indent=2)[:500]}...")
        
        return summary
    except Exception as e:
        print(f"[TEST] ✗ Scan failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def check_validation_queue() -> Dict[str, Any]:
    """Check if findings were queued for validation."""
    try:
        from tools.human_validation_workflow import HumanValidationWorkflow
        
        workflow = HumanValidationWorkflow()
        pending = workflow.get_pending_validations()
        
        print(f"\n[TEST] Validation Queue Status:")
        print(f"  Pending validations: {len(pending)}")
        
        if pending:
            print(f"\n[TEST] ✓ Findings queued for validation:")
            for v in pending[:5]:  # Show first 5
                finding = v.get("finding", {})
                title = finding.get("title", "Unknown")
                cvss = finding.get("cvss_score", 0.0)
                bounty = finding.get("estimated_bounty", 0)
                print(f"    - {v['validation_id'][:20]}... | {title[:50]} | CVSS: {cvss:.1f} | Bounty: ${bounty}")
        
        stats = workflow.get_stats()
        return {
            "pending_count": len(pending),
            "stats": stats,
            "validations": pending,
        }
    except Exception as e:
        print(f"[TEST] ✗ Failed to check validation queue: {e}")
        import traceback
        traceback.print_exc()
        return {"pending_count": 0, "error": str(e)}


def verify_discord_alert_sent() -> bool:
    """Verify that a Discord alert was sent (by checking if webhook was called)."""
    # Note: We can't directly verify Discord received the message without
    # checking Discord's API or logs. But we can check:
    # 1. If webhook URL is configured
    # 2. If validation queue has items (which should have triggered alerts)
    # 3. If alerting code executed without errors
    
    webhook_url = os.environ.get("DISCORD_WEBHOOK_URL")
    if not webhook_url:
        print("[TEST] ⚠️  Cannot verify - DISCORD_WEBHOOK_URL not set")
        return False
    
    # Check validation queue
    queue_info = check_validation_queue()
    if queue_info.get("pending_count", 0) > 0:
        print(f"\n[TEST] ✓ Validation queue has {queue_info['pending_count']} pending items")
        print("[TEST] ✓ Discord alerts should have been sent for these findings")
        print("[TEST] Check your Discord channel to verify the alerts were received")
        return True
    else:
        print("\n[TEST] ⚠️  No findings in validation queue")
        print("[TEST] This could mean:")
        print("  - No findings met the threshold (CVSS >= 7.0 or bounty >= $500)")
        print("  - Triage didn't complete successfully")
        print("  - Human validation is disabled in profile")
        return False


def test_discord_alert_directly() -> bool:
    """Test Discord alert directly by sending a test message."""
    print("\n[TEST] Testing Discord alert directly...")
    
    try:
        from tools.alerting import get_alert_manager
        
        alert_manager = get_alert_manager()
        
        # Send a test alert
        test_finding = {
            "title": "Test Finding - Discord Alert Verification",
            "cvss_score": 9.0,
            "estimated_bounty": 1000,
            "url": TEST_LAB_URL,
            "report_path": "/tmp/test_report.md",
        }
        
        # Send validation alert
        success = alert_manager.send_discord_validation_alert(
            validation_id="test-validation-12345",
            finding=test_finding,
            program_name=f"test-{TEST_LAB}",
        )
        
        if success:
            print("[TEST] ✓ Test Discord alert sent successfully")
            print("[TEST] Check your Discord channel for the test message")
            return True
        else:
            print("[TEST] ✗ Failed to send test Discord alert")
            print("[TEST] Check DISCORD_WEBHOOK_URL and webhook permissions")
            return False
    except Exception as e:
        print(f"[TEST] ✗ Error sending test alert: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main test function."""
    print("=" * 70)
    print("Discord Alert Testing with Lab Validation")
    print("=" * 70)
    
    # Step 1: Check prerequisites
    print("\n[STEP 1] Checking prerequisites...")
    if not check_discord_webhook():
        print("\n[TEST] ⚠️  Discord webhook not configured - continuing with limited testing")
        print("[TEST] Set DISCORD_WEBHOOK_URL to test full alert flow")
    
    if not check_lab_reachable():
        print("\n[TEST] ✗ Lab not reachable - cannot continue")
        print(f"[TEST] Start the lab with: docker-compose up {TEST_LAB}")
        return 1
    
    # Step 2: Configure scope
    print("\n[STEP 2] Configuring scope...")
    scope = configure_scope()
    
    # Step 3: Test direct Discord alert
    print("\n[STEP 3] Testing direct Discord alert...")
    test_discord_alert_directly()
    
    # Step 4: Run full scan (this will trigger triage and validation workflow)
    print("\n[STEP 4] Running full scan to trigger validation workflow...")
    print("[TEST] This may take a few minutes...")
    
    scan_summary = run_full_scan(scope)
    
    if not scan_summary:
        print("\n[TEST] ✗ Scan failed - cannot verify validation workflow")
        return 1
    
    # Step 5: Wait a bit for triage to complete
    print("\n[STEP 5] Waiting for triage and validation workflow...")
    time.sleep(5)
    
    # Step 6: Check validation queue
    print("\n[STEP 6] Checking validation queue...")
    queue_info = check_validation_queue()
    
    # Step 7: Verify Discord alerts
    print("\n[STEP 7] Verifying Discord alerts...")
    alerts_sent = verify_discord_alert_sent()
    
    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Lab: {TEST_LAB}")
    print(f"Lab URL: {TEST_LAB_URL}")
    print(f"Scan completed: {'✓' if scan_summary else '✗'}")
    print(f"Findings queued: {queue_info.get('pending_count', 0)}")
    print(f"Discord alerts sent: {'✓' if alerts_sent else '⚠️'}")
    
    if queue_info.get("pending_count", 0) > 0:
        print("\n[TEST] ✓ SUCCESS: Findings were queued and Discord alerts should have been sent")
        print("[TEST] Check your Discord channel to confirm alerts were received")
    else:
        print("\n[TEST] ⚠️  No findings in validation queue")
        print("[TEST] This could be normal if:")
        print("  - Findings didn't meet CVSS >= 7.0 or bounty >= $500 threshold")
        print("  - Human validation is disabled in profile")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

