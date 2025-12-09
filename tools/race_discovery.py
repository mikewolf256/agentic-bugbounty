#!/usr/bin/env python3
"""Race Condition Discovery Module

Identifies race-prone endpoints:
- Financial transactions, balance updates, coupon redemption
- Account creation, invitation systems
- File operations, resource allocation
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List
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




def identify_race_prone_endpoints(base_url: str, api_endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Identify endpoints that are likely vulnerable to race conditions.
    
    Args:
        base_url: Base URL of the application
        api_endpoints: List of API endpoints from recon
    
    Returns:
        Dict with race-prone endpoints and patterns
    """
    results = {
        "base_url": base_url,
        "race_prone_endpoints": [],
        "patterns_detected": [],
    }
    
    # Keywords that indicate race-prone operations
    financial_keywords = [
        "balance", "payment", "transfer", "withdraw", "deposit", "refund",
        "coupon", "discount", "redeem", "credit", "debit", "transaction",
        "purchase", "order", "checkout", "cart", "billing",
    ]
    
    account_keywords = [
        "create", "register", "signup", "invite", "invitation", "activate",
        "verify", "confirm", "account", "user", "profile",
    ]
    
    resource_keywords = [
        "allocate", "reserve", "book", "claim", "lock", "unlock",
        "file", "upload", "download", "delete", "remove",
    ]
    
    # HTTP methods that modify state (race-prone)
    state_modifying_methods = ["POST", "PUT", "PATCH", "DELETE"]
    
    for ep in api_endpoints:
        url = ep.get("url", "")
        method = (ep.get("method", "GET")).upper()
        
        if method not in state_modifying_methods:
            continue
        
        url_lower = url.lower()
        path_lower = urlparse(url).path.lower()
        
        # Check for financial operations
        financial_match = any(kw in url_lower or kw in path_lower for kw in financial_keywords)
        account_match = any(kw in url_lower or kw in path_lower for kw in account_keywords)
        resource_match = any(kw in url_lower or kw in path_lower for kw in resource_keywords)
        
        if financial_match or account_match or resource_match:
            race_type = []
            if financial_match:
                race_type.append("financial")
            if account_match:
                race_type.append("account")
            if resource_match:
                race_type.append("resource")
            
            results["race_prone_endpoints"].append({
                "url": url,
                "method": method,
                "type": race_type,
                "confidence": "high" if financial_match else "medium",
            })
            
            for rt in race_type:
                if rt not in results["patterns_detected"]:
                    results["patterns_detected"].append(rt)
    
    return results


def detect_non_idempotent_operations(base_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect non-idempotent operations that might be race-prone.
    
    Args:
        base_url: Base URL
        endpoints: List of endpoints to test
    
    Returns:
        List of non-idempotent endpoints
    """
    non_idempotent = []
    
    # Endpoints that should be idempotent but might not be
    idempotent_candidates = [
        ("POST", "/api/orders"),
        ("POST", "/api/payments"),
        ("POST", "/api/coupons/redeem"),
        ("POST", "/api/invitations"),
    ]
    
    for method, path_pattern in idempotent_candidates:
        for ep in endpoints:
            url = ep.get("url", "")
            ep_method = (ep.get("method", "GET")).upper()
            ep_path = urlparse(url).path
            
            if ep_method == method and path_pattern in ep_path:
                # Test if endpoint is idempotent by making same request twice
                try:
                    # First request
                    resp1 = safe_post(url, json={}, timeout=5)
                    
                    # Second identical request
                    resp2 = safe_post(url, json={}, timeout=5)
                    
                    # If responses differ significantly, might be non-idempotent
                    if resp1.status_code != resp2.status_code or resp1.text != resp2.text:
                        non_idempotent.append({
                            "url": url,
                            "method": method,
                            "evidence": {
                                "first_status": resp1.status_code,
                                "second_status": resp2.status_code,
                                "responses_differ": resp1.text != resp2.text,
                            },
                        })
                except Exception:
                    pass
    
    return non_idempotent


def main() -> None:
    ap = argparse.ArgumentParser(description="Race Condition Discovery")
    ap.add_argument("--target", required=True, help="Target base URL")
    ap.add_argument("--api-endpoints-file", help="JSON file with API endpoints from recon")
    ap.add_argument("--output", help="Output JSON file (default: race_discovery_<host>.json)")
    
    args = ap.parse_args()
    
    # Load API endpoints if provided
    api_endpoints = []
    if args.api_endpoints_file and os.path.exists(args.api_endpoints_file):
        with open(args.api_endpoints_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            # Handle different formats
            if isinstance(data, list):
                api_endpoints = data
            elif isinstance(data, dict):
                api_endpoints = data.get("api_endpoints", []) or data.get("endpoints", [])
    
    # Discover race-prone endpoints
    results = identify_race_prone_endpoints(args.target, api_endpoints)
    
    # Detect non-idempotent operations
    non_idempotent = detect_non_idempotent_operations(args.target, api_endpoints)
    results["non_idempotent_endpoints"] = non_idempotent
    
    # Output file
    if args.output:
        out_path = args.output
    else:
        parsed = urlparse(args.target)
        host = parsed.netloc.replace(":", "_")
        out_path = f"race_discovery_{host}.json"
    
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    
    print(f"[RACE-DISCOVERY] Found {len(results['race_prone_endpoints'])} race-prone endpoints")
    print(f"[RACE-DISCOVERY] Patterns: {', '.join(results['patterns_detected'])}")
    if non_idempotent:
        print(f"[RACE-DISCOVERY] Found {len(non_idempotent)} potentially non-idempotent endpoints")
    
    print(out_path)


if __name__ == "__main__":
    main()

