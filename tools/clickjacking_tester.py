#!/usr/bin/env python3
"""Clickjacking Vulnerability Tester

Tests for clickjacking vulnerabilities:
- Missing X-Frame-Options header
- Missing/misconfigured Content-Security-Policy frame-ancestors
- Frameable sensitive pages
- UI redressing possibilities
"""

from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin

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


# Sensitive pages that should be protected from clickjacking
SENSITIVE_ENDPOINTS = [
    "/", "/login", "/signin", "/auth",
    "/register", "/signup",
    "/account", "/profile", "/settings",
    "/admin", "/dashboard",
    "/payment", "/checkout", "/billing",
    "/password", "/change-password",
    "/transfer", "/send",
    "/delete", "/remove",
    "/api/settings", "/api/profile",
]


def check_xframe_options(headers: Dict[str, str]) -> Dict[str, Any]:
    """Check X-Frame-Options header.
    
    Args:
        headers: Response headers dict
    
    Returns:
        Dict with analysis results
    """
    result = {
        "present": False,
        "value": None,
        "valid": False,
        "issues": [],
    }
    
    # Check for X-Frame-Options (case-insensitive)
    xfo = None
    for key, value in headers.items():
        if key.lower() == "x-frame-options":
            xfo = value
            break
    
    if xfo:
        result["present"] = True
        result["value"] = xfo
        
        xfo_upper = xfo.upper().strip()
        
        if xfo_upper == "DENY":
            result["valid"] = True
        elif xfo_upper == "SAMEORIGIN":
            result["valid"] = True
        elif xfo_upper.startswith("ALLOW-FROM"):
            # ALLOW-FROM is deprecated and not supported by all browsers
            result["issues"].append("ALLOW-FROM is deprecated and not universally supported")
            result["valid"] = False
        else:
            result["issues"].append(f"Invalid X-Frame-Options value: {xfo}")
            result["valid"] = False
    else:
        result["issues"].append("X-Frame-Options header is missing")
    
    return result


def check_csp_frame_ancestors(headers: Dict[str, str]) -> Dict[str, Any]:
    """Check Content-Security-Policy frame-ancestors directive.
    
    Args:
        headers: Response headers dict
    
    Returns:
        Dict with analysis results
    """
    result = {
        "present": False,
        "value": None,
        "valid": False,
        "issues": [],
    }
    
    # Check for CSP header (case-insensitive)
    csp = None
    for key, value in headers.items():
        if key.lower() == "content-security-policy":
            csp = value
            break
    
    if not csp:
        result["issues"].append("Content-Security-Policy header is missing")
        return result
    
    # Parse frame-ancestors directive
    directives = csp.split(";")
    frame_ancestors = None
    
    for directive in directives:
        directive = directive.strip()
        if directive.lower().startswith("frame-ancestors"):
            frame_ancestors = directive
            break
    
    if frame_ancestors:
        result["present"] = True
        result["value"] = frame_ancestors
        
        # Parse the sources
        parts = frame_ancestors.split()
        sources = parts[1:] if len(parts) > 1 else []
        
        if "'none'" in sources or "none" in [s.lower().strip("'") for s in sources]:
            result["valid"] = True
        elif "'self'" in sources and len(sources) == 1:
            result["valid"] = True
        elif "*" in sources:
            result["issues"].append("frame-ancestors allows any origin (*)")
            result["valid"] = False
        elif any(s.startswith("http:") for s in sources):
            result["issues"].append("frame-ancestors allows non-HTTPS origins")
            result["valid"] = False
        elif sources:
            # Has specific origins - may be intentional
            result["valid"] = True
            result["issues"].append(f"frame-ancestors allows specific origins: {', '.join(sources)}")
        else:
            result["issues"].append("frame-ancestors directive has no sources")
            result["valid"] = False
    else:
        result["issues"].append("CSP frame-ancestors directive is missing")
    
    return result


def is_page_frameable(url: str, timeout: int = 10) -> Dict[str, Any]:
    """Test if a page can be framed.
    
    Args:
        url: URL to test
        timeout: Request timeout
    
    Returns:
        Dict with test results
    """
    result = {
        "url": url,
        "frameable": True,
        "xframe_options": None,
        "csp_frame_ancestors": None,
        "issues": [],
    }
    
    try:
        resp = safe_get(url, timeout=timeout, allow_redirects=True)
        
        # Check X-Frame-Options
        xfo_check = check_xframe_options(dict(resp.headers))
        result["xframe_options"] = xfo_check
        
        # Check CSP frame-ancestors
        csp_check = check_csp_frame_ancestors(dict(resp.headers))
        result["csp_frame_ancestors"] = csp_check
        
        # Determine if frameable
        if xfo_check["valid"] or csp_check["valid"]:
            result["frameable"] = False
        else:
            result["issues"].extend(xfo_check["issues"])
            result["issues"].extend(csp_check["issues"])
        
    except Exception as e:
        result["error"] = str(e)
        result["frameable"] = False  # Can't determine if error
    
    return result


def discover_sensitive_pages(base_url: str, timeout: int = 10) -> List[str]:
    """Discover sensitive pages that should be protected.
    
    Args:
        base_url: Base URL to scan
        timeout: Request timeout
    
    Returns:
        List of discovered URLs
    """
    discovered = []
    
    for endpoint in SENSITIVE_ENDPOINTS:
        test_url = urljoin(base_url, endpoint)
        try:
            resp = safe_get(test_url, timeout=timeout, allow_redirects=True)
            # Include pages that exist (not 404)
            if resp.status_code != 404:
                discovered.append(test_url)
        except:
            continue
    
    return discovered


def generate_poc_html(target_url: str) -> str:
    """Generate a proof-of-concept HTML page for clickjacking.
    
    Args:
        target_url: URL of the frameable page
    
    Returns:
        HTML code for PoC
    """
    return f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
        }}
        .container {{
            position: relative;
            width: 100%;
            height: 100vh;
        }}
        iframe {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            border: none;
            opacity: 0.5; /* Make semi-transparent to show overlay */
            z-index: 1;
        }}
        .overlay {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 2;
            pointer-events: none;
        }}
        .overlay button {{
            position: absolute;
            /* Adjust these coordinates to position over the target button */
            top: 200px;
            left: 300px;
            padding: 10px 20px;
            background: #ff0000;
            color: white;
            border: none;
            cursor: pointer;
            pointer-events: auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        <iframe src="{target_url}"></iframe>
        <div class="overlay">
            <button>Click here to win a prize!</button>
        </div>
    </div>
    <script>
        // This script is for testing - in a real attack, the iframe would be invisible
        document.querySelector('.overlay button').addEventListener('click', function() {{
            alert('User clicked on overlay - attack successful!');
        }});
    </script>
</body>
</html>'''


def validate_clickjacking(
    target_url: str,
    endpoints: Optional[List[str]] = None,
    discovery_data: Optional[Dict] = None,
    timeout: int = 10
) -> Dict[str, Any]:
    """Run comprehensive clickjacking vulnerability testing.
    
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
        "frameable_pages": [],
        "protected_pages": [],
        "findings": [],
        "poc_html": None,
    }
    
    # Get endpoints to test
    if endpoints:
        test_endpoints = endpoints
    elif discovery_data and discovery_data.get("endpoints"):
        test_endpoints = [urljoin(target_url, ep) for ep in discovery_data["endpoints"]]
    else:
        test_endpoints = discover_sensitive_pages(target_url, timeout)
    
    if not test_endpoints:
        test_endpoints = [target_url]
    
    # Test each endpoint
    for endpoint in test_endpoints[:15]:  # Limit to 15 endpoints
        frame_test = is_page_frameable(endpoint, timeout)
        
        if frame_test.get("frameable"):
            result["vulnerable"] = True
            result["frameable_pages"].append(endpoint)
            
            # Determine severity based on page type
            severity = "low"
            parsed = urlparse(endpoint)
            path_lower = parsed.path.lower()
            
            # High severity for auth/payment pages
            if any(s in path_lower for s in ["/login", "/signin", "/payment", "/checkout", "/admin", "/transfer"]):
                severity = "high"
            # Medium for account/settings pages
            elif any(s in path_lower for s in ["/account", "/profile", "/settings", "/password", "/delete"]):
                severity = "medium"
            
            result["findings"].append({
                "type": "clickjacking",
                "url": endpoint,
                "evidence": "; ".join(frame_test.get("issues", [])),
                "severity": severity,
                "xframe_options": frame_test.get("xframe_options", {}),
                "csp_frame_ancestors": frame_test.get("csp_frame_ancestors", {}),
            })
        else:
            result["protected_pages"].append(endpoint)
    
    # Generate PoC for first vulnerable page
    if result["frameable_pages"]:
        result["poc_html"] = generate_poc_html(result["frameable_pages"][0])
    
    return result


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python clickjacking_tester.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"[*] Testing clickjacking on: {target}")
    
    results = validate_clickjacking(target)
    
    print(f"\n[*] Results:")
    print(f"  Vulnerable: {results['vulnerable']}")
    print(f"  Frameable Pages: {len(results['frameable_pages'])}")
    print(f"  Protected Pages: {len(results['protected_pages'])}")
    
    for finding in results.get("findings", []):
        print(f"\n  Finding: {finding['type']} ({finding['severity']})")
        print(f"    URL: {finding['url']}")
        print(f"    Issues: {finding.get('evidence', 'N/A')}")

