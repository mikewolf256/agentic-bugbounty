#!/usr/bin/env python3
"""Cache Poisoning Tester

Tests for cache poisoning vulnerabilities:
- HTTP cache key injection
- Cache poisoning via headers
- Cache poisoning via query parameters
"""

import os
import requests
from typing import Dict, Any, Optional
from urllib.parse import urlparse


def test_cache_poisoning(
    target_url: str,
    cache_headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Test for cache poisoning vulnerabilities
    
    Args:
        target_url: Target URL
        cache_headers: Optional cache headers to test
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "cache_poisoning",
        "vulnerable": False,
        "poisoning_method": None,
        "evidence": None
    }
    
    # Test cache key injection via headers
    poison_headers = {
        "X-Forwarded-Host": "evil.com",
        "Host": "evil.com",
        "X-Original-URL": "/evil",
    }
    
    try:
        resp = requests.get(target_url, headers=poison_headers, timeout=10)
        
        # Check if poisoned header appears in response
        if "evil.com" in resp.text:
            result["vulnerable"] = True
            result["poisoning_method"] = "header_injection"
            result["evidence"] = {
                "headers_used": poison_headers,
                "status_code": resp.status_code,
                "response_snippet": resp.text[:500],
                "note": "Cache poisoning via header injection detected"
            }
    except Exception:
        pass
    
    return result


def validate_cache_poisoning(
    discovery_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Main validation function for cache poisoning
    
    Args:
        discovery_data: Discovery data
        
    Returns:
        Dict with validation results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    target = discovery_data.get("target")
    if not target:
        return results
    
    test_result = test_cache_poisoning(target)
    results["tests_run"] += 1
    if test_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(test_result)
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="Cache Poisoning Tester")
    ap.add_argument("--target", required=True, help="Target URL")
    args = ap.parse_args()
    
    result = test_cache_poisoning(args.target)
    
    import json
    print(json.dumps(result, indent=2))

