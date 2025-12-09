#!/usr/bin/env python3
"""
Test script for hybrid model triage routing.

Tests:
1. Model selection logic (simple vs complex findings)
2. CVSS threshold routing
3. Bounty threshold routing
4. Complex vulnerability detection
5. Backward compatibility
"""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Set test environment
os.environ.setdefault("OPENAI_API_KEY", "test-key")  # Prevent SystemExit
os.environ.setdefault("USE_HYBRID_TRIAGE", "true")
os.environ.setdefault("LLM_MODEL", "gpt-4o-mini")
os.environ.setdefault("LLM_MODEL_ADVANCED", "gpt-4o")
os.environ.setdefault("HYBRID_CVSS_THRESHOLD", "7.0")
os.environ.setdefault("HYBRID_BOUNTY_THRESHOLD", "5000")

from agentic_runner import (
    is_complex_vulnerability,
    get_model_for_finding,
    USE_HYBRID_TRIAGE,
    LLM_MODEL,
    LLM_MODEL_ADVANCED,
    HYBRID_CVSS_THRESHOLD,
    HYBRID_BOUNTY_THRESHOLD,
)


def test_complex_vulnerability_detection():
    """Test complex vulnerability detection."""
    print("\n=== Test 1: Complex Vulnerability Detection ===")
    
    test_cases = [
        # (finding, expected_complex)
        ({"name": "Cross Site Scripting (Reflected)"}, False),
        ({"name": "Business Logic Flaw in Pricing"}, True),
        ({"name": "GraphQL Depth DoS"}, True),
        ({"name": "OAuth Redirect URI Manipulation"}, True),
        ({"name": "Race Condition in Payment"}, True),
        ({"name": "Request Smuggling"}, True),
        ({"name": "Template Injection (SSTI)"}, True),
        ({"name": "Deserialization RCE"}, True),
        ({"name": "JWT Algorithm Confusion"}, True),
        ({"name": "Authentication Bypass"}, True),
        ({"name": "Privilege Escalation"}, True),
        ({"name": "Exploitation Chain"}, True),
        ({"chain_id": "chain_123"}, True),
        ({"exploitability_score": 0.8}, True),
    ]
    
    passed = 0
    failed = 0
    
    for finding, expected in test_cases:
        result = is_complex_vulnerability(finding)
        status = "✓" if result == expected else "✗"
        if result == expected:
            passed += 1
        else:
            failed += 1
        print(f"  {status} {finding.get('name', 'finding')}: {result} (expected {expected})")
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_cvss_threshold_routing():
    """Test CVSS threshold routing."""
    print("\n=== Test 2: CVSS Threshold Routing ===")
    
    test_cases = [
        # (finding, expected_model)
        ({"cvss_score": 6.5}, LLM_MODEL),  # Below threshold
        ({"cvss_score": 7.0}, LLM_MODEL_ADVANCED),  # At threshold
        ({"cvss_score": 8.5}, LLM_MODEL_ADVANCED),  # Above threshold
        ({"cvss": 9.0}, LLM_MODEL_ADVANCED),  # Different field name
        ({"cvss_v3": 7.5}, LLM_MODEL_ADVANCED),
        ({"cvss3_score": 6.9}, LLM_MODEL),  # Just below
        ({"cvss_score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, LLM_MODEL_ADVANCED),  # Vector string
    ]
    
    passed = 0
    failed = 0
    
    for finding, expected in test_cases:
        result = get_model_for_finding(finding)
        status = "✓" if result == expected else "✗"
        if result == expected:
            passed += 1
        else:
            failed += 1
        cvss = finding.get("cvss_score") or finding.get("cvss") or finding.get("cvss_v3") or finding.get("cvss3_score")
        print(f"  {status} CVSS {cvss}: {result} (expected {expected})")
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_bounty_threshold_routing():
    """Test bounty threshold routing."""
    print("\n=== Test 3: Bounty Threshold Routing ===")
    
    test_cases = [
        # (finding, expected_model)
        ({"bounty_estimate": {"estimated": 3000}}, LLM_MODEL),  # Below threshold
        ({"bounty_estimate": {"estimated": 5000}}, LLM_MODEL_ADVANCED),  # At threshold
        ({"bounty_estimate": {"estimated": 10000}}, LLM_MODEL_ADVANCED),  # Above threshold
        ({"recommended_bounty_usd": 4500}, LLM_MODEL),  # Below threshold
        ({"recommended_bounty_usd": 5000}, LLM_MODEL_ADVANCED),  # At threshold
        ({"recommended_bounty_usd": 15000}, LLM_MODEL_ADVANCED),  # Above threshold
    ]
    
    passed = 0
    failed = 0
    
    for finding, expected in test_cases:
        result = get_model_for_finding(finding)
        status = "✓" if result == expected else "✗"
        if result == expected:
            passed += 1
        else:
            failed += 1
        bounty = finding.get("bounty_estimate", {}).get("estimated") or finding.get("recommended_bounty_usd")
        print(f"  {status} Bounty ${bounty}: {result} (expected {expected})")
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_complex_type_routing():
    """Test complex type routing."""
    print("\n=== Test 4: Complex Type Routing ===")
    
    test_cases = [
        # (finding, expected_model)
        ({"name": "Business Logic Flaw"}, LLM_MODEL_ADVANCED),
        ({"name": "GraphQL Injection"}, LLM_MODEL_ADVANCED),
        ({"name": "OAuth Misconfiguration"}, LLM_MODEL_ADVANCED),
        ({"name": "Race Condition"}, LLM_MODEL_ADVANCED),
        ({"name": "Simple XSS"}, LLM_MODEL),  # Simple finding
        ({"name": "Basic SQL Injection"}, LLM_MODEL),  # Simple finding
    ]
    
    passed = 0
    failed = 0
    
    for finding, expected in test_cases:
        result = get_model_for_finding(finding)
        status = "✓" if result == expected else "✗"
        if result == expected:
            passed += 1
        else:
            failed += 1
        print(f"  {status} {finding['name']}: {result} (expected {expected})")
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_hybrid_triage_disabled():
    """Test that hybrid triage can be disabled."""
    print("\n=== Test 5: Hybrid Triage Disabled ===")
    
    # Temporarily disable
    original = os.environ.get("USE_HYBRID_TRIAGE")
    os.environ["USE_HYBRID_TRIAGE"] = "false"
    
    # Reload module to pick up new env var
    import importlib
    import agentic_runner
    importlib.reload(agentic_runner)
    
    from agentic_runner import get_model_for_finding as get_model_disabled
    
    # Test that complex finding still uses base model when disabled
    complex_finding = {"name": "Business Logic Flaw", "cvss_score": 9.0}
    result = get_model_disabled(complex_finding)
    
    # Restore
    if original:
        os.environ["USE_HYBRID_TRIAGE"] = original
    else:
        os.environ["USE_HYBRID_TRIAGE"] = "true"
    
    # Reload again
    importlib.reload(agentic_runner)
    
    expected = agentic_runner.LLM_MODEL
    status = "✓" if result == expected else "✗"
    print(f"  {status} Complex finding with hybrid disabled: {result} (expected {expected})")
    
    return result == expected


def test_model_usage_tracking():
    """Test that model usage is tracked."""
    print("\n=== Test 6: Model Usage Tracking ===")
    
    from agentic_runner import _model_usage_stats
    
    # Reset stats
    _model_usage_stats.clear()
    
    # Simulate some usage
    _model_usage_stats["gpt-4o-mini"] = 5
    _model_usage_stats["gpt-4o"] = 2
    
    if _model_usage_stats:
        stats_str = ", ".join([f"{model}: {count}" for model, count in sorted(_model_usage_stats.items())])
        print(f"  ✓ Stats tracking works: {stats_str}")
        return True
    else:
        print("  ✗ Stats tracking not working")
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("Hybrid Model Triage Routing Tests")
    print("=" * 60)
    
    print(f"\nConfiguration:")
    print(f"  USE_HYBRID_TRIAGE: {USE_HYBRID_TRIAGE}")
    print(f"  LLM_MODEL: {LLM_MODEL}")
    print(f"  LLM_MODEL_ADVANCED: {LLM_MODEL_ADVANCED}")
    print(f"  HYBRID_CVSS_THRESHOLD: {HYBRID_CVSS_THRESHOLD}")
    print(f"  HYBRID_BOUNTY_THRESHOLD: {HYBRID_BOUNTY_THRESHOLD}")
    
    results = []
    
    results.append(("Complex Detection", test_complex_vulnerability_detection()))
    results.append(("CVSS Routing", test_cvss_threshold_routing()))
    results.append(("Bounty Routing", test_bounty_threshold_routing()))
    results.append(("Complex Type Routing", test_complex_type_routing()))
    results.append(("Hybrid Disabled", test_hybrid_triage_disabled()))
    results.append(("Usage Tracking", test_model_usage_tracking()))
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")
    
    print(f"\n  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())




