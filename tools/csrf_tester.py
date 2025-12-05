#!/usr/bin/env python3
"""CSRF Tester

Tests for Cross-Site Request Forgery (CSRF) vulnerabilities:
- CSRF token presence and validation
- SameSite cookie protection
- Origin/Referer header validation
- PoC HTML form generation
"""

import os
import time
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, urljoin


def test_csrf_token_presence(endpoint: str, method: str = "POST") -> Dict[str, Any]:
    """Test if endpoint requires CSRF token
    
    Args:
        endpoint: Target endpoint URL
        method: HTTP method
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "csrf_token_presence",
        "requires_token": False,
        "token_parameter": None,
        "evidence": None
    }
    
    # Try request without token
    try:
        if method.upper() == "POST":
            resp = requests.post(endpoint, data={}, timeout=10)
        elif method.upper() == "PUT":
            resp = requests.put(endpoint, data={}, timeout=10)
        elif method.upper() == "DELETE":
            resp = requests.delete(endpoint, timeout=10)
        else:
            resp = requests.get(endpoint, timeout=10)
        
        # Check response for CSRF token indicators
        response_text = resp.text.lower()
        csrf_indicators = [
            "csrf", "token", "authenticity", "form_token",
            "csrf_token", "_token", "csrfmiddlewaretoken"
        ]
        
        for indicator in csrf_indicators:
            if indicator in response_text:
                result["requires_token"] = True
                result["token_parameter"] = indicator
                result["evidence"] = {
                    "status_code": resp.status_code,
                    "indicator_found": indicator,
                    "response_snippet": resp.text[:500]
                }
                break
        
        # Check if request was rejected (might indicate token required)
        if resp.status_code in [403, 400] and "csrf" in response_text:
            result["requires_token"] = True
            result["evidence"] = {
                "status_code": resp.status_code,
                "note": "Request rejected, CSRF token may be required"
            }
            
    except Exception as e:
        result["evidence"] = {"error": str(e)}
    
    return result


def test_csrf_protection(
    endpoint: str,
    method: str = "POST",
    auth_context: Optional[Dict] = None
) -> Dict[str, Any]:
    """Test CSRF protection mechanisms
    
    Args:
        endpoint: Target endpoint URL
        method: HTTP method
        auth_context: Optional authentication context (cookies, headers)
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "csrf_protection",
        "vulnerable": False,
        "protection_mechanisms": [],
        "evidence": None
    }
    
    # Build request with auth context
    headers = {}
    cookies = {}
    if auth_context:
        headers.update(auth_context.get("headers", {}))
        cookies.update(auth_context.get("cookies", {}))
    
    # Test 1: Check SameSite cookie attribute
    if cookies:
        # Note: SameSite is a cookie attribute, not easily testable via requests
        # This would require browser-based testing
        result["protection_mechanisms"].append("samesite_cookie_check_requires_browser")
    
    # Test 2: Check Origin header validation
    # Try request without Origin header
    try:
        if method.upper() == "POST":
            resp1 = requests.post(endpoint, data={}, headers=headers, cookies=cookies, timeout=10)
        else:
            resp1 = requests.get(endpoint, headers=headers, cookies=cookies, timeout=10)
        
        # Try request with Origin header
        headers_with_origin = headers.copy()
        headers_with_origin["Origin"] = "https://evil.com"
        
        if method.upper() == "POST":
            resp2 = requests.post(endpoint, data={}, headers=headers_with_origin, cookies=cookies, timeout=10)
        else:
            resp2 = requests.get(endpoint, headers=headers_with_origin, cookies=cookies, timeout=10)
        
        # If both requests succeed, Origin validation may be missing
        if resp1.status_code == resp2.status_code and resp1.status_code < 400:
            result["vulnerable"] = True
            result["evidence"] = {
                "status_code": resp1.status_code,
                "note": "Origin header validation may be missing"
            }
        elif resp2.status_code >= 400:
            result["protection_mechanisms"].append("origin_header_validation")
            
    except Exception as e:
        result["evidence"] = {"error": str(e)}
    
    # Test 3: Check Referer header validation
    try:
        headers_with_referer = headers.copy()
        headers_with_referer["Referer"] = "https://evil.com"
        
        if method.upper() == "POST":
            resp3 = requests.post(endpoint, data={}, headers=headers_with_referer, cookies=cookies, timeout=10)
        else:
            resp3 = requests.get(endpoint, headers=headers_with_referer, cookies=cookies, timeout=10)
        
        if resp3.status_code < 400:
            # Check if original request also succeeds
            if method.upper() == "POST":
                resp_orig = requests.post(endpoint, data={}, headers=headers, cookies=cookies, timeout=10)
            else:
                resp_orig = requests.get(endpoint, headers=headers, cookies=cookies, timeout=10)
            
            if resp_orig.status_code == resp3.status_code:
                result["vulnerable"] = True
                if not result["evidence"]:
                    result["evidence"] = {}
                result["evidence"]["referer_validation"] = "missing"
        else:
            result["protection_mechanisms"].append("referer_header_validation")
            
    except Exception as e:
        pass
    
    return result


def generate_csrf_poc(
    endpoint: str,
    method: str = "POST",
    form_data: Optional[Dict[str, str]] = None
) -> str:
    """Generate CSRF PoC HTML form
    
    Args:
        endpoint: Target endpoint URL
        method: HTTP method
        form_data: Optional form data to include
        
    Returns:
        HTML string with CSRF PoC
    """
    if not form_data:
        form_data = {}
    
    # Build form fields
    form_fields = ""
    for key, value in form_data.items():
        form_fields += f'    <input type="hidden" name="{key}" value="{value}">\n'
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This form will automatically submit to: {endpoint}</p>
    <form id="csrf_form" action="{endpoint}" method="{method.upper()}">
{form_fields}
        <input type="submit" value="Submit">
    </form>
    <script>
        // Auto-submit form
        document.getElementById('csrf_form').submit();
    </script>
</body>
</html>"""
    
    return html


def validate_csrf(
    discovery_data: Dict[str, Any],
    auth_context: Optional[Dict] = None
) -> Dict[str, Any]:
    """Main validation function for CSRF vulnerabilities
    
    Args:
        discovery_data: Discovery data containing endpoints (from csrf_discovery.py)
        auth_context: Optional authentication context
        
    Returns:
        Dict with validation results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": [],
        "poc_html": []
    }
    
    # Get state-changing endpoints from discovery data
    endpoints = discovery_data.get("csrf_prone_endpoints", [])
    if not endpoints:
        endpoints = discovery_data.get("state_changing_endpoints", [])
    
    if not endpoints:
        return results
    
    # Test each endpoint
    for endpoint_info in endpoints:
        endpoint_url = endpoint_info.get("url")
        method = endpoint_info.get("method", "POST")
        
        if not endpoint_url:
            continue
        
        # Test CSRF token presence
        token_test = test_csrf_token_presence(endpoint_url, method)
        results["tests_run"] += 1
        
        # Test CSRF protection
        protection_test = test_csrf_protection(endpoint_url, method, auth_context)
        results["tests_run"] += 1
        
        if protection_test["vulnerable"]:
            results["vulnerable"] = True
            finding = {
                "endpoint": endpoint_url,
                "method": method,
                "vulnerable": True,
                "token_required": token_test.get("requires_token", False),
                "protection_mechanisms": protection_test.get("protection_mechanisms", []),
                "evidence": protection_test.get("evidence"),
            }
            results["findings"].append(finding)
            
            # Generate PoC HTML
            poc_html = generate_csrf_poc(endpoint_url, method)
            results["poc_html"].append({
                "endpoint": endpoint_url,
                "method": method,
                "html": poc_html
            })
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="CSRF Tester")
    ap.add_argument("--target", required=True, help="Target base URL")
    ap.add_argument("--discovery-data", help="Path to CSRF discovery data JSON file")
    ap.add_argument("--output", help="Output JSON file")
    args = ap.parse_args()
    
    # Load discovery data
    discovery_data = {"csrf_prone_endpoints": []}
    if args.discovery_data and os.path.exists(args.discovery_data):
        with open(args.discovery_data, "r", encoding="utf-8") as fh:
            discovery_data = json.load(fh)
    
    result = validate_csrf(discovery_data)
    
    # Save results
    if args.output:
        out_path = args.output
    else:
        parsed = urlparse(args.target)
        host = parsed.netloc.replace(":", "_")
        out_path = f"csrf_validation_{host}.json"
    
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    import json
    print(json.dumps(result, indent=2))

