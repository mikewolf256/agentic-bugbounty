#!/usr/bin/env python3
"""Race Condition Validator Module

Tests for race conditions using:
- Parallel request sender (configurable threads, timing)
- Response diffing to detect race success
- Turbo Intruder-style single-packet attack support
- Track balance/count deltas as evidence
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

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




def send_parallel_requests(
    url: str,
    method: str = "POST",
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    num_requests: int = 10,
    delay_ms: int = 0,
    timeout: int = 10,
) -> List[Dict[str, Any]]:
    """Send multiple parallel requests to test for race conditions.
    
    Args:
        url: Target URL
        method: HTTP method
        data: Request data/payload
        headers: Request headers
        num_requests: Number of parallel requests to send
        delay_ms: Delay between requests in milliseconds (0 = simultaneous)
        timeout: Request timeout in seconds
    
    Returns:
        List of response data for each request
    """
    responses = []
    
    def send_request(request_id: int) -> Dict[str, Any]:
        """Send a single request."""
        if delay_ms > 0:
            time.sleep((request_id * delay_ms) / 1000.0)
        
        try:
            if method.upper() == "POST":
                resp = safe_post(url, json=data, headers=headers, timeout=timeout)
            elif method.upper() == "PUT":
                resp = requests.put(url, json=data, headers=headers, timeout=timeout)
            elif method.upper() == "PATCH":
                resp = requests.patch(url, json=data, headers=headers, timeout=timeout)
            elif method.upper() == "DELETE":
                resp = requests.delete(url, headers=headers, timeout=timeout)
            else:
                resp = safe_get(url, headers=headers, timeout=timeout)
            
            return {
                "request_id": request_id,
                "status_code": resp.status_code,
                "response_text": resp.text[:500],  # First 500 chars
                "response_json": None,
                "headers": dict(resp.headers),
                "timestamp": time.time(),
            }
        except Exception as e:
            return {
                "request_id": request_id,
                "error": str(e),
                "timestamp": time.time(),
            }
    
    # Send requests in parallel
    with ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [executor.submit(send_request, i) for i in range(num_requests)]
        
        for future in as_completed(futures):
            try:
                result = future.result()
                responses.append(result)
            except Exception as e:
                responses.append({
                    "error": str(e),
                    "timestamp": time.time(),
                })
    
    return responses


def detect_race_condition(responses: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze responses to detect race condition success.
    
    Args:
        responses: List of response data from parallel requests
    
    Returns:
        Dict with race condition detection results
    """
    result = {
        "race_detected": False,
        "evidence": [],
        "status_codes": {},
        "response_differences": [],
    }
    
    if len(responses) < 2:
        return result
    
    # Count status codes
    for resp in responses:
        if "status_code" in resp:
            code = resp["status_code"]
            result["status_codes"][code] = result["status_codes"].get(code, 0) + 1
    
    # Check for multiple successful responses (indicates race condition)
    success_codes = [200, 201, 202, 204]
    successful_responses = [r for r in responses if r.get("status_code") in success_codes]
    
    if len(successful_responses) > 1:
        result["race_detected"] = True
        result["evidence"].append({
            "type": "multiple_success",
            "count": len(successful_responses),
            "expected": 1,
        })
    
    # Check for response differences (different data returned)
    response_texts = [r.get("response_text", "") for r in successful_responses if "response_text" in r]
    if len(set(response_texts)) > 1:
        result["race_detected"] = True
        result["evidence"].append({
            "type": "response_differences",
            "unique_responses": len(set(response_texts)),
        })
        result["response_differences"] = list(set(response_texts))[:5]  # First 5 unique
    
    # Try to parse JSON and detect balance/count changes
    for resp in successful_responses:
        if "response_text" in resp:
            try:
                data = json.loads(resp["response_text"])
                # Look for balance, count, or similar fields
                for key in ["balance", "count", "quantity", "amount", "credits", "points"]:
                    if key in data:
                        result["evidence"].append({
                            "type": "state_change",
                            "field": key,
                            "value": data[key],
                        })
            except json.JSONDecodeError:
                pass
    
    return result


def test_race_condition(
    url: str,
    method: str = "POST",
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    num_requests: int = 10,
    delay_ms: int = 0,
) -> Dict[str, Any]:
    """Test a single endpoint for race conditions.
    
    Args:
        url: Target URL
        method: HTTP method
        data: Request data
        headers: Request headers
        num_requests: Number of parallel requests
        delay_ms: Delay between requests (0 = simultaneous)
    
    Returns:
        Dict with test results
    """
    result = {
        "url": url,
        "method": method,
        "num_requests": num_requests,
        "delay_ms": delay_ms,
        "vulnerable": False,
    }
    
    # Send parallel requests
    responses = send_parallel_requests(url, method, data, headers, num_requests, delay_ms)
    result["responses"] = responses
    
    # Detect race condition
    detection = detect_race_condition(responses)
    result["detection"] = detection
    result["vulnerable"] = detection["race_detected"]
    
    return result


def validate_race_conditions(discovery_data: Dict[str, Any]) -> Dict[str, Any]:
    """Run race condition validation tests.
    
    Args:
        discovery_data: Race discovery data from race_discovery.py
    
    Returns:
        Dict with validation results
    """
    results = {
        "base_url": discovery_data.get("base_url"),
        "tests": [],
        "vulnerable_count": 0,
    }
    
    # Test each race-prone endpoint
    for ep in discovery_data.get("race_prone_endpoints", []):
        url = ep.get("url")
        method = ep.get("method", "POST")
        ep_type = ep.get("type", [])
        
        if not url:
            continue
        
        # Prepare test data based on endpoint type
        test_data = {}
        if "financial" in ep_type:
            test_data = {"amount": 100, "action": "transfer"}
        elif "account" in ep_type:
            test_data = {"action": "create"}
        elif "resource" in ep_type:
            test_data = {"action": "allocate"}
        
        print(f"[RACE-VALIDATOR] Testing {method} {url}...", file=sys.stderr)
        
        # Run race condition test
        test_result = test_race_condition(
            url=url,
            method=method,
            data=test_data if method in ["POST", "PUT", "PATCH"] else None,
            num_requests=10,
            delay_ms=0,  # Simultaneous requests
        )
        
        results["tests"].append(test_result)
        
        if test_result.get("vulnerable"):
            results["vulnerable_count"] += 1
            print(f"[RACE-VALIDATOR] VULNERABLE: {url}", file=sys.stderr)
    
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="Race Condition Validator")
    ap.add_argument("--discovery-file", required=True, help="Race discovery JSON file from race_discovery.py")
    ap.add_argument("--output", help="Output JSON file (default: race_validation_<host>.json)")
    ap.add_argument("--num-requests", type=int, default=10, help="Number of parallel requests per test")
    ap.add_argument("--delay-ms", type=int, default=0, help="Delay between requests in milliseconds")
    
    args = ap.parse_args()
    
    # Load discovery data
    with open(args.discovery_file, "r", encoding="utf-8") as fh:
        discovery_data = json.load(fh)
    
    # Run validation
    results = validate_race_conditions(discovery_data)
    
    # Override test parameters if provided
    if args.num_requests or args.delay_ms:
        for test in results["tests"]:
            if args.num_requests:
                test["num_requests"] = args.num_requests
            if args.delay_ms:
                test["delay_ms"] = args.delay_ms
    
    # Output file
    if args.output:
        out_path = args.output
    else:
        base_url = discovery_data.get("base_url", "unknown")
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        host = parsed.netloc.replace(":", "_")
        out_path = f"race_validation_{host}.json"
    
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    
    print(f"[RACE-VALIDATOR] Found {results['vulnerable_count']} vulnerable endpoints")
    for test in results["tests"]:
        if test.get("vulnerable"):
            print(f"[RACE-VALIDATOR] VULNERABLE: {test.get('url')}")
    
    print(out_path)


if __name__ == "__main__":
    main()

