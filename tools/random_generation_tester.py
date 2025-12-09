#!/usr/bin/env python3
"""Random Number Generation Tester

Tests for predictable random number generation:
- Predictable session tokens
- Predictable CSRF tokens
- Predictable user IDs
"""

import os
from typing import Dict, Any, Optional, List
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



def test_random_generation(
    target_url: str,
    tokens: Optional[List[str]] = None,
    auth_context: Optional[Dict] = None
) -> Dict[str, Any]:
    """Test for predictable random number generation
    
    Args:
        target_url: Target URL
        tokens: Optional list of tokens to analyze
        auth_context: Optional authentication context
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "random_generation",
        "test": "random_generation",
        "vulnerable": False,
        "predictable": False,
        "url": target_url,
        "token_type": None,
        "evidence": None
    }
    
    from urllib.parse import urljoin
    
    # If no tokens provided, actively fetch tokens from common endpoints
    if not tokens:
        tokens = []
        token_endpoints = ["/api/token", "/token", "/login"]
        
        for endpoint in token_endpoints:
            try:
                endpoint_url = urljoin(target_url, endpoint)
                # Fetch multiple tokens
                for _ in range(3):
                    resp = safe_get(endpoint_url, timeout=5)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            # Look for token in response
                            token = data.get("token") or data.get("session_token") or data.get("csrf_token")
                            if token:
                                tokens.append(str(token))
                            # Check for counter indication
                            counter = data.get("counter")
                            if counter is not None:
                                tokens.append(str(counter))
                            # Check if response explicitly says predictable
                            if data.get("predictable"):
                                result["vulnerable"] = True
                                result["predictable"] = True
                                result["token_type"] = "predictable_token"
                                result["evidence"] = {
                                    "endpoint": endpoint_url,
                                    "response": data,
                                    "note": "Application indicates predictable tokens"
                                }
                                return result
                        except Exception:
                            pass
            except Exception:
                continue
    
    # Analyze tokens if we have them
    if tokens and len(tokens) >= 2:
        # Check for sequential patterns
        for i in range(len(tokens) - 1):
            token1 = tokens[i]
            token2 = tokens[i + 1]
            
            # Check if tokens are sequential
            try:
                if token1.isdigit() and token2.isdigit():
                    diff = int(token2) - int(token1)
                    if diff == 1:
                        result["vulnerable"] = True
                        result["predictable"] = True
                        result["token_type"] = "sequential_numeric"
                        result["evidence"] = {
                            "token1": token1[:20],
                            "token2": token2[:20],
                            "note": "Sequential numeric tokens detected"
                        }
                        return result
            except Exception:
                pass
            
            # Check for predictable patterns (same prefix with incrementing suffix)
            if len(token1) == len(token2) and len(token1) > 4:
                prefix_len = min(10, len(token1) - 4)
                if token1[:prefix_len] == token2[:prefix_len]:
                    # Check if suffix is incrementing
                    suffix1 = token1[prefix_len:]
                    suffix2 = token2[prefix_len:]
                    if suffix1.isdigit() and suffix2.isdigit():
                        diff = int(suffix2) - int(suffix1)
                        if diff == 1:
                            result["vulnerable"] = True
                            result["predictable"] = True
                            result["token_type"] = "sequential_suffix"
                            result["evidence"] = {
                                "token1": token1,
                                "token2": token2,
                                "note": "Sequential token suffix detected"
                            }
                            return result
    
    # Check session tokens from auth context
    if auth_context and "cookies" in auth_context:
        cookies = auth_context["cookies"]
        for name, value in cookies.items():
            if "session" in name.lower() or "token" in name.lower():
                if len(value) < 32:
                    result["vulnerable"] = True
                    result["predictable"] = True
                    result["token_type"] = "short_session_token"
                    result["evidence"] = {
                        "cookie_name": name,
                        "token_length": len(value),
                        "note": "Short session token detected"
                    }
                    return result
    
    return result


def validate_random_generation(
    discovery_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Main validation function for random generation
    
    Args:
        discovery_data: Discovery data
        
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
    
    tokens = discovery_data.get("tokens", [])
    auth_context = discovery_data.get("auth_context")
    
    test_result = test_random_generation(target, tokens, auth_context)
    results["tests_run"] += 1
    if test_result["predictable"]:
        results["vulnerable"] = True
        results["findings"].append(test_result)
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="Random Generation Tester")
    ap.add_argument("--target", required=True, help="Target URL")
    args = ap.parse_args()
    
    result = test_random_generation(args.target)
    
    import json
    print(json.dumps(result, indent=2))

