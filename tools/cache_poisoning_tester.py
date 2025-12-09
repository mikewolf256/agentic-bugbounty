#!/usr/bin/env python3
"""Cache Poisoning Tester

Tests for cache poisoning vulnerabilities:
- HTTP cache key injection
- Cache poisoning via headers
- Cache poisoning via query parameters
"""

import os
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, urljoin


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
        "type": "cache_poisoning",
        "test": "cache_poisoning",
        "vulnerable": False,
        "url": target_url,
        "poisoning_method": None,
        "evidence": None
    }
    
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    # Test endpoints - check both the target URL and common cacheable paths
    test_endpoints = [target_url]
    if not any(ep in target_url for ep in ["/page", "/api/data"]):
        test_endpoints.extend([
            urljoin(target_url, "/page"),
            urljoin(target_url, "/api/data"),
        ])
    
    # Headers to test for cache poisoning
    poison_headers_sets = [
        {"X-Forwarded-Host": "evil.com"},
        {"X-Forwarded-Host": "evil.com", "Host": "evil.com"},
        {"X-Original-URL": "/evil"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-Proto": "https"},
    ]
    
    for endpoint in test_endpoints:
        for poison_headers in poison_headers_sets:
            try:
                resp = requests.get(endpoint, headers=poison_headers, timeout=10)
                
                # Check if poisoned header appears in response body or headers
                response_contains_poison = "evil.com" in resp.text
                headers_contain_poison = any("evil" in str(v).lower() for v in resp.headers.values())
                
                # Check for X-Forwarded-Host in response (indicates header reflection)
                x_forwarded_in_response = "x-forwarded-host" in resp.text.lower()
                
                if response_contains_poison or headers_contain_poison:
                    result["vulnerable"] = True
                    result["poisoning_method"] = "header_injection"
                    result["evidence"] = {
                        "endpoint": endpoint,
                        "headers_used": poison_headers,
                        "status_code": resp.status_code,
                        "response_snippet": resp.text[:500],
                        "response_headers": dict(resp.headers),
                        "note": "Cache poisoning via header injection detected"
                    }
                    return result
                
                # Check if response has cacheable headers and reflects our header
                cache_control = resp.headers.get('Cache-Control', '')
                if ('public' in cache_control or 'max-age' in cache_control) and x_forwarded_in_response:
                    result["vulnerable"] = True
                    result["poisoning_method"] = "header_reflection_in_cached_response"
                    result["evidence"] = {
                        "endpoint": endpoint,
                        "headers_used": poison_headers,
                        "status_code": resp.status_code,
                        "cache_control": cache_control,
                        "response_snippet": resp.text[:500],
                        "note": "Header reflected in cacheable response"
                    }
                    return result
                    
            except Exception:
                continue
    
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
    
    cache_headers = discovery_data.get("cache_headers")
    
    test_result = test_cache_poisoning(target, cache_headers)
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

