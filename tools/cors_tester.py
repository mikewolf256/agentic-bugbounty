#!/usr/bin/env python3
"""CORS Misconfiguration Tester

Tests for CORS (Cross-Origin Resource Sharing) vulnerabilities:
- Reflected Origin (Access-Control-Allow-Origin reflects arbitrary origin)
- Null Origin allowed
- Wildcard Origin with credentials
- Subdomain matching bypass (evil.target.com)
- Protocol downgrade (http:// when https:// expected)
- Trust of third-party origins
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


# Endpoints commonly vulnerable to CORS misconfig
CORS_SENSITIVE_ENDPOINTS = [
    "/api/user", "/api/users", "/api/me", "/api/profile",
    "/api/account", "/api/settings", "/api/config",
    "/api/data", "/api/private", "/api/sensitive",
    "/api/v1/user", "/api/v1/me", "/api/v1/account",
    "/api/v2/user", "/api/v2/me",
    "/graphql", "/api/graphql",
    "/user", "/me", "/profile",
    "/api/balance", "/api/wallet", "/api/transactions",
]


def test_reflected_origin(
    url: str,
    timeout: int = 10
) -> Dict[str, Any]:
    """Test if Origin header is reflected in ACAO.
    
    Args:
        url: URL to test
        timeout: Request timeout
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "reflected_origin",
        "url": url,
        "vulnerable": False,
        "evidence": None,
        "allows_credentials": False,
    }
    
    # Test with evil origin
    evil_origins = [
        "https://evil.com",
        "https://attacker.com",
        "http://malicious.site",
    ]
    
    for evil_origin in evil_origins:
        try:
            resp = safe_get(
                url,
                headers={"Origin": evil_origin},
                timeout=timeout
            )
            
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            
            if acao == evil_origin:
                result["vulnerable"] = True
                result["evidence"] = f"Origin '{evil_origin}' is reflected in ACAO header"
                result["allows_credentials"] = acac == "true"
                result["reflected_origin"] = evil_origin
                result["acao_header"] = acao
                result["acac_header"] = acac
                break
            
        except Exception as e:
            continue
    
    return result


def test_null_origin(
    url: str,
    timeout: int = 10
) -> Dict[str, Any]:
    """Test if null Origin is allowed.
    
    Args:
        url: URL to test
        timeout: Request timeout
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "null_origin",
        "url": url,
        "vulnerable": False,
        "evidence": None,
        "allows_credentials": False,
    }
    
    try:
        resp = safe_get(
            url,
            headers={"Origin": "null"},
            timeout=timeout
        )
        
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        
        if acao == "null":
            result["vulnerable"] = True
            result["evidence"] = "Null origin is allowed in ACAO header"
            result["allows_credentials"] = acac == "true"
            result["acao_header"] = acao
            result["acac_header"] = acac
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def test_wildcard_with_credentials(
    url: str,
    timeout: int = 10
) -> Dict[str, Any]:
    """Test for wildcard origin with credentials.
    
    Args:
        url: URL to test
        timeout: Request timeout
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "wildcard_credentials",
        "url": url,
        "vulnerable": False,
        "evidence": None,
    }
    
    try:
        resp = safe_get(
            url,
            headers={"Origin": "https://example.com"},
            timeout=timeout
        )
        
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        
        # Note: Browsers won't actually allow * with credentials,
        # but this is still a server misconfiguration
        if acao == "*":
            if acac == "true":
                result["vulnerable"] = True
                result["evidence"] = "Wildcard (*) ACAO with credentials (browser won't honor, but misconfigured)"
            else:
                result["evidence"] = "Wildcard (*) ACAO without credentials (may be intentional)"
            result["acao_header"] = acao
            result["acac_header"] = acac
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def test_subdomain_bypass(
    url: str,
    timeout: int = 10
) -> Dict[str, Any]:
    """Test for subdomain matching bypass.
    
    Args:
        url: URL to test
        timeout: Request timeout
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "subdomain_bypass",
        "url": url,
        "vulnerable": False,
        "evidence": None,
        "bypass_origins": [],
    }
    
    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0]  # Remove port
    
    # Generate bypass attempts
    bypass_origins = [
        f"https://evil{domain}",  # Prefix
        f"https://{domain}.evil.com",  # Suffix
        f"https://evil.{domain}",  # Subdomain
        f"https://{domain}evil.com",  # Combined
        f"https://not{domain}",  # Different prefix
    ]
    
    for evil_origin in bypass_origins:
        try:
            resp = safe_get(
                url,
                headers={"Origin": evil_origin},
                timeout=timeout
            )
            
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            
            if acao == evil_origin:
                result["vulnerable"] = True
                result["bypass_origins"].append(evil_origin)
                
        except Exception:
            continue
    
    if result["bypass_origins"]:
        result["evidence"] = f"Subdomain bypass worked with: {', '.join(result['bypass_origins'][:2])}"
        result["allows_credentials"] = True  # If origin is reflected, likely allows credentials
    
    return result


def test_protocol_downgrade(
    url: str,
    timeout: int = 10
) -> Dict[str, Any]:
    """Test for HTTP protocol allowed when target uses HTTPS.
    
    Args:
        url: URL to test
        timeout: Request timeout
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "protocol_downgrade",
        "url": url,
        "vulnerable": False,
        "evidence": None,
    }
    
    parsed = urlparse(url)
    
    # Only test if target uses HTTPS
    if parsed.scheme != "https":
        result["evidence"] = "Target doesn't use HTTPS, test not applicable"
        return result
    
    domain = parsed.netloc
    http_origin = f"http://{domain}"
    
    try:
        resp = safe_get(
            url,
            headers={"Origin": http_origin},
            timeout=timeout
        )
        
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        
        if acao == http_origin:
            result["vulnerable"] = True
            result["evidence"] = f"HTTP origin accepted for HTTPS target: {http_origin}"
            result["allows_credentials"] = acac == "true"
            result["acao_header"] = acao
            result["acac_header"] = acac
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def discover_cors_endpoints(base_url: str, timeout: int = 10) -> List[str]:
    """Discover endpoints that may have CORS configuration.
    
    Args:
        base_url: Base URL to scan
        timeout: Request timeout
    
    Returns:
        List of discovered URLs
    """
    discovered = []
    
    for endpoint in CORS_SENSITIVE_ENDPOINTS:
        test_url = urljoin(base_url, endpoint)
        try:
            resp = safe_get(
                test_url,
                headers={"Origin": "https://example.com"},
                timeout=timeout
            )
            
            # Include if endpoint responds with CORS headers
            if resp.status_code != 404:
                acao = resp.headers.get("Access-Control-Allow-Origin")
                if acao:
                    discovered.append(test_url)
                elif resp.status_code == 200:
                    # Include 200 responses even without CORS headers
                    discovered.append(test_url)
        except:
            continue
    
    return discovered


def validate_cors(
    target_url: str,
    endpoints: Optional[List[str]] = None,
    discovery_data: Optional[Dict] = None,
    timeout: int = 10
) -> Dict[str, Any]:
    """Run comprehensive CORS misconfiguration testing.
    
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
        test_endpoints = discover_cors_endpoints(target_url, timeout)
    
    if not test_endpoints:
        test_endpoints = [target_url]
    
    # Test each endpoint
    for endpoint in test_endpoints[:10]:  # Limit to 10 endpoints
        endpoint_vulnerable = False
        
        # Test 1: Reflected Origin
        reflected_test = test_reflected_origin(endpoint, timeout)
        result["tests"].append(reflected_test)
        if reflected_test.get("vulnerable"):
            endpoint_vulnerable = True
            severity = "high" if reflected_test.get("allows_credentials") else "medium"
            result["findings"].append({
                "type": "cors_misconfiguration",
                "subtype": "reflected_origin",
                "url": endpoint,
                "evidence": reflected_test.get("evidence", ""),
                "severity": severity,
                "allows_credentials": reflected_test.get("allows_credentials", False),
            })
        
        # Test 2: Null Origin
        null_test = test_null_origin(endpoint, timeout)
        result["tests"].append(null_test)
        if null_test.get("vulnerable"):
            endpoint_vulnerable = True
            severity = "high" if null_test.get("allows_credentials") else "medium"
            result["findings"].append({
                "type": "cors_misconfiguration",
                "subtype": "null_origin",
                "url": endpoint,
                "evidence": null_test.get("evidence", ""),
                "severity": severity,
                "allows_credentials": null_test.get("allows_credentials", False),
            })
        
        # Test 3: Subdomain Bypass
        subdomain_test = test_subdomain_bypass(endpoint, timeout)
        result["tests"].append(subdomain_test)
        if subdomain_test.get("vulnerable"):
            endpoint_vulnerable = True
            result["findings"].append({
                "type": "cors_misconfiguration",
                "subtype": "subdomain_bypass",
                "url": endpoint,
                "evidence": subdomain_test.get("evidence", ""),
                "severity": "medium",
                "bypass_origins": subdomain_test.get("bypass_origins", []),
            })
        
        # Test 4: Protocol Downgrade
        protocol_test = test_protocol_downgrade(endpoint, timeout)
        result["tests"].append(protocol_test)
        if protocol_test.get("vulnerable"):
            endpoint_vulnerable = True
            result["findings"].append({
                "type": "cors_misconfiguration",
                "subtype": "protocol_downgrade",
                "url": endpoint,
                "evidence": protocol_test.get("evidence", ""),
                "severity": "medium",
                "allows_credentials": protocol_test.get("allows_credentials", False),
            })
        
        if endpoint_vulnerable:
            result["vulnerable"] = True
            result["vulnerable_endpoints"].append(endpoint)
    
    return result


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python cors_tester.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"[*] Testing CORS misconfiguration on: {target}")
    
    results = validate_cors(target)
    
    print(f"\n[*] Results:")
    print(f"  Vulnerable: {results['vulnerable']}")
    print(f"  Vulnerable Endpoints: {len(results['vulnerable_endpoints'])}")
    
    for finding in results.get("findings", []):
        print(f"\n  Finding: {finding['type']} - {finding['subtype']} ({finding['severity']})")
        print(f"    URL: {finding['url']}")
        print(f"    Evidence: {finding.get('evidence', 'N/A')}")
        print(f"    Allows Credentials: {finding.get('allows_credentials', False)}")

