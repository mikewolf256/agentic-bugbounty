#!/usr/bin/env python3
"""Test Discord Webhook Configuration

This script tests if the Discord webhook is properly configured and can send messages.
"""

import os
import sys

def test_webhook():
    """Test Discord webhook configuration and send a test message."""
    print("=" * 70)
    print("Discord Webhook Test")
    print("=" * 70)
    
    # Check if webhook URL is set
    webhook_url = os.environ.get("DISCORD_WEBHOOK_URL")
    if not webhook_url:
        print("\n❌ DISCORD_WEBHOOK_URL environment variable is not set")
        print("\nTo set it:")
        print("  1. Go to your Discord server")
        print("  2. Server Settings → Integrations → Webhooks")
        print("  3. Create a new webhook or use an existing one")
        print("  4. Copy the webhook URL")
        print("  5. Set it: export DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...'")
        return False
    
    print(f"\n✓ DISCORD_WEBHOOK_URL is set")
    print(f"  URL: {webhook_url[:50]}...")
    
    # Test sending a message
    print("\nTesting webhook by sending a test message...")
    
    try:
        from tools.alerting import get_alert_manager
        
        alert_manager = get_alert_manager()
        
        # Send test validation alert
        test_finding = {
            "title": "Test Finding - Discord Webhook Verification",
            "cvss_score": 9.0,
            "estimated_bounty": 1000,
            "url": "http://test.example.com",
            "report_path": "/tmp/test_report.md",
        }
        
        success = alert_manager.send_discord_validation_alert(
            validation_id="test-validation-12345",
            finding=test_finding,
            program_name="test-program",
        )
        
        if success:
            print("\n✅ SUCCESS: Test message sent to Discord!")
            print("   Check your Discord channel for the test message")
            return True
        else:
            print("\n❌ FAILED: Could not send test message")
            print("   Check the error messages above for details")
            return False
            
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_direct_webhook():
    """Test Discord webhook directly with requests."""
    print("\n" + "=" * 70)
    print("Direct Webhook Test (using requests)")
    print("=" * 70)
    
    webhook_url = os.environ.get("DISCORD_WEBHOOK_URL")
    if not webhook_url:
        print("\n❌ DISCORD_WEBHOOK_URL not set")
        return False
    
    import requests
    
    # Simple test payload
    payload = {
        "content": "🧪 Test message from Agentic Bug Bounty System\n\nIf you see this, your webhook is working!",
        "embeds": [{
            "title": "Webhook Test",
            "description": "This is a test message to verify your Discord webhook configuration.",
            "color": 3447003,  # Blue
            "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        }]
    }
    
    try:
        print(f"\nSending test message to: {webhook_url[:50]}...")
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        
        print(f"\n✅ SUCCESS: HTTP {response.status_code}")
        print("   Check your Discord channel for the test message")
        return True
    except requests.exceptions.RequestException as e:
        print(f"\n❌ FAILED: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"   Response status: {e.response.status_code}")
            print(f"   Response body: {e.response.text[:200]}")
        return False


if __name__ == "__main__":
    print("\nTesting Discord webhook configuration...\n")
    
    # Test 1: Direct webhook test (more detailed error info)
    direct_success = test_direct_webhook()
    
    # Test 2: Using alert manager
    print("\n" + "-" * 70)
    manager_success = test_webhook()
    
    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Direct webhook test: {'✅ PASSED' if direct_success else '❌ FAILED'}")
    print(f"Alert manager test:  {'✅ PASSED' if manager_success else '❌ FAILED'}")
    
    if not direct_success and not manager_success:
        print("\n💡 Troubleshooting:")
        print("  1. Verify DISCORD_WEBHOOK_URL is correct")
        print("  2. Check that the webhook hasn't been deleted")
        print("  3. Ensure the webhook has permission to post in the channel")
        print("  4. Try creating a new webhook URL")
    
    sys.exit(0 if (direct_success or manager_success) else 1)

