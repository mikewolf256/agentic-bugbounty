#!/usr/bin/env python3
"""
Integration test for hybrid model triage routing.

Tests the actual triage function with mock findings to verify
model selection works in practice.
"""

import os
import sys
import json
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock OpenAI API to avoid actual API calls
class MockResponse:
    def __init__(self, content):
        self.content = content
        self.json_data = {
            "choices": [{"message": {"content": content}}]
        }
    
    def json(self):
        return self.json_data
    
    def raise_for_status(self):
        pass


def test_triage_with_mock_findings():
    """Test triage with various finding types."""
    print("\n=== Integration Test: Triage with Mock Findings ===")
    
    # Set up test environment
    os.environ.setdefault("OPENAI_API_KEY", "test-key")
    os.environ.setdefault("USE_HYBRID_TRIAGE", "true")
    os.environ.setdefault("LLM_MODEL", "gpt-4o-mini")
    os.environ.setdefault("LLM_MODEL_ADVANCED", "gpt-4o")
    
    # Import after setting env vars
    import agentic_runner
    from agentic_runner import get_model_for_finding, _model_usage_stats
    
    # Reset stats
    _model_usage_stats.clear()
    
    # Create mock findings
    mock_findings = [
        {
            "name": "Cross Site Scripting (Reflected)",
            "risk": "Medium",
            "url": "http://example.com/search?q=test",
            "cvss_score": 6.1,  # Below threshold
        },
        {
            "name": "Business Logic Flaw in Pricing",
            "risk": "High",
            "url": "http://example.com/checkout",
            "cvss_score": 8.5,  # Above threshold
        },
        {
            "name": "GraphQL Depth DoS",
            "risk": "High",
            "url": "http://example.com/graphql",
            # Complex type, should use advanced
        },
        {
            "name": "SQL Injection",
            "risk": "High",
            "url": "http://example.com/search?id=1",
            "cvss_score": 9.0,  # Above threshold
        },
        {
            "name": "OAuth Redirect URI Manipulation",
            "risk": "Critical",
            "url": "http://example.com/oauth",
            "bounty_estimate": {"estimated": 6000},  # Above bounty threshold
        },
        {
            "name": "Simple Information Disclosure",
            "risk": "Low",
            "url": "http://example.com/robots.txt",
            "cvss_score": 3.1,  # Low score
        },
    ]
    
    print("\n  Testing model selection for each finding:")
    model_selections = {}
    
    for finding in mock_findings:
        model = get_model_for_finding(finding)
        finding_name = finding.get("name", "unknown")
        model_selections[finding_name] = model
        
        # Determine expected model
        cvss = finding.get("cvss_score", 0)
        bounty = finding.get("bounty_estimate", {}).get("estimated", 0)
        is_complex = agentic_runner.is_complex_vulnerability(finding)
        
        expected = agentic_runner.LLM_MODEL_ADVANCED if (
            cvss >= 7.0 or 
            bounty >= 5000 or 
            is_complex
        ) else agentic_runner.LLM_MODEL
        
        status = "✓" if model == expected else "✗"
        print(f"    {status} {finding_name[:40]:40s} → {model:15s} (CVSS: {cvss}, Bounty: ${bounty}, Complex: {is_complex})")
    
    # Summary
    base_model_count = sum(1 for m in model_selections.values() if m == agentic_runner.LLM_MODEL)
    advanced_model_count = sum(1 for m in model_selections.values() if m == agentic_runner.LLM_MODEL_ADVANCED)
    
    print(f"\n  Model Selection Summary:")
    print(f"    {agentic_runner.LLM_MODEL}: {base_model_count} findings")
    print(f"    {agentic_runner.LLM_MODEL_ADVANCED}: {advanced_model_count} findings")
    
    # Verify routing logic
    expected_base = 2  # Simple XSS and Info Disclosure
    expected_advanced = 4  # Business Logic, GraphQL, SQLi, OAuth
    
    if base_model_count == expected_base and advanced_model_count == expected_advanced:
        print(f"\n  ✓ Routing logic correct: {base_model_count} base, {advanced_model_count} advanced")
        return True
    else:
        print(f"\n  ✗ Routing logic incorrect: expected {expected_base} base, {expected_advanced} advanced")
        return False


def test_model_selection_edge_cases():
    """Test edge cases in model selection."""
    print("\n=== Edge Cases Test ===")
    
    import agentic_runner
    from agentic_runner import get_model_for_finding
    
    edge_cases = [
        # Empty finding
        ({}, agentic_runner.LLM_MODEL),
        # Finding with only name
        ({"name": "Test"}, agentic_runner.LLM_MODEL),
        # CVSS exactly at threshold
        ({"cvss_score": 7.0}, agentic_runner.LLM_MODEL_ADVANCED),
        # CVSS just below threshold
        ({"cvss_score": 6.99}, agentic_runner.LLM_MODEL),
        # Bounty exactly at threshold
        ({"bounty_estimate": {"estimated": 5000}}, agentic_runner.LLM_MODEL_ADVANCED),
        # Bounty just below threshold
        ({"bounty_estimate": {"estimated": 4999}}, agentic_runner.LLM_MODEL),
        # Multiple triggers (should still use advanced)
        ({"name": "Business Logic", "cvss_score": 8.0, "bounty_estimate": {"estimated": 10000}}, agentic_runner.LLM_MODEL_ADVANCED),
    ]
    
    passed = 0
    failed = 0
    
    for finding, expected in edge_cases:
        result = get_model_for_finding(finding)
        if result == expected:
            passed += 1
            print(f"  ✓ Edge case passed")
        else:
            failed += 1
            print(f"  ✗ Edge case failed: got {result}, expected {expected}")
            print(f"     Finding: {finding}")
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def main():
    """Run integration tests."""
    print("=" * 60)
    print("Hybrid Model Triage Integration Tests")
    print("=" * 60)
    
    results = []
    
    results.append(("Mock Findings Triage", test_triage_with_mock_findings()))
    results.append(("Edge Cases", test_model_selection_edge_cases()))
    
    print("\n" + "=" * 60)
    print("Integration Test Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")
    
    print(f"\n  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ All integration tests passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())




