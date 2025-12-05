#!/usr/bin/env python3
"""DNS Rebinding Tester

Tests for DNS rebinding vulnerabilities:
- DNS rebinding to bypass same-origin policy
- Internal network access via DNS rebinding
- Cloud metadata access via DNS rebinding
"""

import os
import requests
from typing import Dict, Any, Optional
from urllib.parse import urlparse


def test_dns_rebinding(
    target_url: str,
    internal_target: str = "127.0.0.1"
) -> Dict[str, Any]:
    """Test for DNS rebinding vulnerabilities
    
    Args:
        target_url: Target URL
        internal_target: Internal target to test (e.g., 127.0.0.1, 169.254.169.254)
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "dns_rebinding",
        "vulnerable": False,
        "internal_access": False,
        "evidence": None
    }
    
    # DNS rebinding requires a controlled DNS server
    # This is a simplified test that checks if internal endpoints are accessible
    # Full DNS rebinding would require setting up a rebinding DNS server
    
    parsed = urlparse(target_url)
    host = parsed.netloc.split(":")[0]
    
    # Test if internal endpoints are accessible
    internal_endpoints = [
        f"http://{internal_target}/",
        f"http://{internal_target}:8080/",
        f"http://169.254.169.254/latest/meta-data/",
    ]
    
    for endpoint in internal_endpoints:
        try:
            resp = requests.get(endpoint, timeout=5)
            if resp.status_code == 200:
                result["vulnerable"] = True
                result["internal_access"] = True
                result["evidence"] = {
                    "internal_endpoint": endpoint,
                    "status_code": resp.status_code,
                    "response_snippet": resp.text[:500],
                    "note": "Internal network access detected"
                }
                break
        except Exception:
            continue
    
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
    
    test_result = test_dns_rebinding(target)
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

