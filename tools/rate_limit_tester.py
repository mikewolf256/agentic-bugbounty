#!/usr/bin/env python3
"""Rate Limit Bypass Tester

Tests for rate limiting vulnerabilities:
- Missing rate limits on sensitive endpoints
- Rate limit bypass via header manipulation (X-Forwarded-For, etc.)
- Rate limit bypass via parameter pollution
- Rate limit bypass via case variation
- Rate limit bypass via HTTP method switching
"""

import time
import random
import string
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

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


# Sensitive endpoints typically requiring rate limiting
RATE_LIMIT_SENSITIVE_ENDPOINTS = [
    "/login", "/signin", "/auth", "/authenticate",
    "/register", "/signup", "/create-account",
    "/api/login", "/api/auth", "/api/register",
    "/forgot-password", "/reset-password", "/password-reset",
    "/api/forgot-password", "/api/reset-password",
    "/otp", "/verify-otp", "/2fa", "/mfa",
    "/api/otp", "/api/verify", "/api/2fa",
    "/contact", "/feedback", "/api/contact",
    "/api/users", "/api/user", "/users",
    "/api/search", "/search",
    "/api/export", "/export", "/download",
]

# Headers to test for bypass
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Forwarded-For": "192.168.1.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Real-IP": "10.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"True-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"X-Azure-ClientIP": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
]


def random_ip() -> str:
    """Generate a random IP address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def detect_rate_limit(response: requests.Response) -> bool:
    """Check if response indicates rate limiting."""
    # Status code checks
    if response.status_code == 429:
        return True
    if response.status_code == 503 and "rate" in response.text.lower():
        return True
    
    # Header checks
    rate_headers = ["x-ratelimit-remaining", "x-rate-limit-remaining", 
                   "ratelimit-remaining", "x-ratelimit-limit",
                   "retry-after", "x-retry-after"]
    for header in rate_headers:
        if header in [h.lower() for h in response.headers.keys()]:
            remaining = response.headers.get(header, response.headers.get(header.title(), ""))
            try:
                if int(remaining) <= 0:
                    return True
            except (ValueError, TypeError):
                pass
    
    # Content checks
    rate_indicators = [
        "rate limit", "rate-limit", "ratelimit",
        "too many requests", "request limit",
        "slow down", "throttle", "blocked"
    ]
    text_lower = response.text.lower()
    for indicator in rate_indicators:
        if indicator in text_lower:
            return True
    
    return False


def extract_rate_limit_info(response: requests.Response) -> Dict[str, Any]:
    """Extract rate limit information from response headers."""
    info = {}
    header_mappings = {
        "limit": ["x-ratelimit-limit", "x-rate-limit-limit", "ratelimit-limit"],
        "remaining": ["x-ratelimit-remaining", "x-rate-limit-remaining", "ratelimit-remaining"],
        "reset": ["x-ratelimit-reset", "x-rate-limit-reset", "ratelimit-reset", "retry-after"],
    }
    
    for key, headers in header_mappings.items():
        for header in headers:
            value = response.headers.get(header) or response.headers.get(header.title())
            if value:
                info[key] = value
                break
    
    return info


def test_rate_limit_presence(
    target_url: str,
    num_requests: int = 20,
    timeout: int = 10
) -> Dict[str, Any]:
    """Test if rate limiting exists on an endpoint.
    
    Args:
        target_url: URL to test
        num_requests: Number of requests to send
        timeout: Request timeout in seconds
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "rate_limit_presence",
        "url": target_url,
        "vulnerable": False,
        "has_rate_limit": False,
        "requests_sent": 0,
        "rate_limit_info": {},
        "evidence": None,
    }
    
    try:
        responses = []
        rate_limited = False
        
        for i in range(num_requests):
            try:
                resp = safe_get(target_url, timeout=timeout, allow_redirects=True)
                responses.append(resp)
                result["requests_sent"] = i + 1
                
                # Check if we got rate limited
                if detect_rate_limit(resp):
                    rate_limited = True
                    result["has_rate_limit"] = True
                    result["rate_limit_info"] = extract_rate_limit_info(resp)
                    result["evidence"] = f"Rate limited after {i + 1} requests"
                    break
                
                # Small delay to avoid being too aggressive
                time.sleep(0.05)
            except requests.exceptions.RequestException:
                continue
        
        # If we sent all requests without being rate limited, endpoint may be vulnerable
        if not rate_limited and result["requests_sent"] >= num_requests * 0.9:
            result["vulnerable"] = True
            result["evidence"] = f"No rate limiting detected after {result['requests_sent']} requests"
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def test_header_bypass(
    target_url: str,
    requests_per_ip: int = 10,
    timeout: int = 10
) -> Dict[str, Any]:
    """Test rate limit bypass using header manipulation.
    
    Args:
        target_url: URL to test
        requests_per_ip: Number of requests per spoofed IP
        timeout: Request timeout in seconds
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "header_bypass",
        "url": target_url,
        "vulnerable": False,
        "bypass_headers": [],
        "evidence": None,
    }
    
    # First, check if rate limiting exists
    baseline_limited = False
    for i in range(15):
        try:
            resp = safe_get(target_url, timeout=timeout)
            if detect_rate_limit(resp):
                baseline_limited = True
                break
        except:
            pass
        time.sleep(0.02)
    
    if not baseline_limited:
        result["evidence"] = "No baseline rate limit detected - cannot test bypass"
        return result
    
    # Test each bypass header
    for bypass_header in BYPASS_HEADERS:
        successful_requests = 0
        
        for i in range(requests_per_ip):
            # Randomize IP for each request
            headers = dict(bypass_header)
            for key in headers:
                if headers[key] in ("127.0.0.1", "10.0.0.1", "192.168.1.1"):
                    headers[key] = random_ip()
            
            try:
                resp = safe_get(target_url, headers=headers, timeout=timeout)
                if not detect_rate_limit(resp) and resp.status_code < 400:
                    successful_requests += 1
            except:
                continue
            
            time.sleep(0.02)
        
        # If we got significantly more requests through with bypass, it works
        if successful_requests >= requests_per_ip * 0.8:
            result["vulnerable"] = True
            result["bypass_headers"].append(list(bypass_header.keys())[0])
    
    if result["bypass_headers"]:
        result["evidence"] = f"Rate limit bypassed using headers: {', '.join(result['bypass_headers'])}"
    
    return result


def test_case_bypass(target_url: str, timeout: int = 10) -> Dict[str, Any]:
    """Test rate limit bypass using URL case variations.
    
    Args:
        target_url: URL to test
        timeout: Request timeout in seconds
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "case_bypass",
        "url": target_url,
        "vulnerable": False,
        "variations": [],
        "evidence": None,
    }
    
    parsed = urlparse(target_url)
    path = parsed.path
    
    # Generate case variations
    variations = [
        path.upper(),
        path.lower(),
        path.capitalize(),
        path.swapcase(),
    ]
    
    # Also add some common variations
    if path.lower() == "/login":
        variations.extend(["/LOGIN", "/Login", "/loGin", "/logIN"])
    
    # Test if rate limiting is case-sensitive
    for variation in set(variations):
        if variation == path:
            continue
        
        test_url = f"{parsed.scheme}://{parsed.netloc}{variation}"
        if parsed.query:
            test_url += f"?{parsed.query}"
        
        successful = 0
        for i in range(10):
            try:
                resp = safe_get(test_url, timeout=timeout)
                if not detect_rate_limit(resp) and resp.status_code < 400:
                    successful += 1
            except:
                continue
            time.sleep(0.05)
        
        if successful >= 8:
            result["variations"].append(variation)
    
    if result["variations"]:
        result["vulnerable"] = True
        result["evidence"] = f"Rate limit bypassed using URL variations: {', '.join(result['variations'][:3])}"
    
    return result


def test_method_bypass(target_url: str, timeout: int = 10) -> Dict[str, Any]:
    """Test rate limit bypass using HTTP method switching.
    
    Args:
        target_url: URL to test
        timeout: Request timeout in seconds
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "method_bypass",
        "url": target_url,
        "vulnerable": False,
        "bypass_methods": [],
        "evidence": None,
    }
    
    methods = ["GET", "POST", "PUT", "PATCH", "OPTIONS", "HEAD"]
    
    for method in methods:
        try:
            successful = 0
            for i in range(10):
                try:
                    resp = requests.request(method, target_url, timeout=timeout)
                    if not detect_rate_limit(resp) and resp.status_code < 400:
                        successful += 1
                except:
                    continue
                time.sleep(0.05)
            
            if successful >= 8:
                result["bypass_methods"].append(method)
        except:
            continue
    
    # If multiple methods work without rate limiting
    if len(result["bypass_methods"]) >= 2:
        result["vulnerable"] = True
        result["evidence"] = f"Multiple HTTP methods not rate limited: {', '.join(result['bypass_methods'])}"
    
    return result


def discover_rate_limit_endpoints(base_url: str, timeout: int = 10) -> List[str]:
    """Discover sensitive endpoints that should have rate limiting.
    
    Args:
        base_url: Base URL to scan
        timeout: Request timeout in seconds
    
    Returns:
        List of discovered endpoint URLs
    """
    discovered = []
    
    for endpoint in RATE_LIMIT_SENSITIVE_ENDPOINTS:
        test_url = urljoin(base_url, endpoint)
        try:
            resp = safe_get(test_url, timeout=timeout, allow_redirects=True)
            # Include any endpoint that responds (not 404)
            if resp.status_code != 404:
                discovered.append(test_url)
        except:
            continue
    
    return discovered


def validate_rate_limiting(
    target_url: str,
    endpoints: Optional[List[str]] = None,
    discovery_data: Optional[Dict] = None,
    run_bypass_tests: bool = True,
    timeout: int = 10
) -> Dict[str, Any]:
    """Run comprehensive rate limit testing.
    
    Args:
        target_url: Base URL to test
        endpoints: Optional list of specific endpoints to test
        discovery_data: Optional discovery data with endpoints
        run_bypass_tests: Whether to run bypass tests
        timeout: Request timeout in seconds
    
    Returns:
        Dict with all test results
    """
    result = {
        "target": target_url,
        "vulnerable": False,
        "vulnerable_endpoints": [],
        "bypass_vulnerable": False,
        "tests": [],
        "findings": [],
    }
    
    # Get endpoints to test
    if endpoints:
        test_endpoints = endpoints
    elif discovery_data and discovery_data.get("endpoints"):
        test_endpoints = [urljoin(target_url, ep) for ep in discovery_data["endpoints"]]
    else:
        test_endpoints = discover_rate_limit_endpoints(target_url, timeout)
    
    if not test_endpoints:
        test_endpoints = [target_url]
    
    # Test each endpoint for rate limiting
    for endpoint in test_endpoints[:10]:  # Limit to 10 endpoints
        presence_test = test_rate_limit_presence(endpoint, timeout=timeout)
        result["tests"].append(presence_test)
        
        if presence_test.get("vulnerable"):
            result["vulnerable"] = True
            result["vulnerable_endpoints"].append(endpoint)
            result["findings"].append({
                "type": "rate_limit_missing",
                "url": endpoint,
                "evidence": presence_test.get("evidence", ""),
                "severity": "medium",
            })
        
        # Run bypass tests if rate limiting exists
        if run_bypass_tests and presence_test.get("has_rate_limit"):
            # Header bypass
            header_test = test_header_bypass(endpoint, timeout=timeout)
            result["tests"].append(header_test)
            if header_test.get("vulnerable"):
                result["bypass_vulnerable"] = True
                result["vulnerable"] = True
                result["findings"].append({
                    "type": "rate_limit_bypass",
                    "subtype": "header_bypass",
                    "url": endpoint,
                    "evidence": header_test.get("evidence", ""),
                    "bypass_headers": header_test.get("bypass_headers", []),
                    "severity": "high",
                })
            
            # Case bypass
            case_test = test_case_bypass(endpoint, timeout=timeout)
            result["tests"].append(case_test)
            if case_test.get("vulnerable"):
                result["bypass_vulnerable"] = True
                result["vulnerable"] = True
                result["findings"].append({
                    "type": "rate_limit_bypass",
                    "subtype": "case_bypass",
                    "url": endpoint,
                    "evidence": case_test.get("evidence", ""),
                    "severity": "medium",
                })
    
    return result


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python rate_limit_tester.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"[*] Testing rate limiting on: {target}")
    
    results = validate_rate_limiting(target)
    
    print(f"\n[*] Results:")
    print(f"  Vulnerable: {results['vulnerable']}")
    print(f"  Vulnerable Endpoints: {len(results['vulnerable_endpoints'])}")
    print(f"  Bypass Vulnerable: {results['bypass_vulnerable']}")
    
    for finding in results.get("findings", []):
        print(f"\n  Finding: {finding['type']}")
        print(f"    URL: {finding['url']}")
        print(f"    Evidence: {finding.get('evidence', 'N/A')}")

