#!/usr/bin/env python3
"""Random Number Generation Tester

Tests for predictable random number generation:
- Predictable session tokens
- Predictable CSRF tokens
- Predictable user IDs
"""

import os
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse


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
        "test": "random_generation",
        "predictable": False,
        "token_type": None,
        "evidence": None
    }
    
    # Analyze tokens if provided
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
                        result["predictable"] = True
                        result["token_type"] = "sequential_numeric"
                        result["evidence"] = {
                            "token1": token1[:20],
                            "token2": token2[:20],
                            "note": "Sequential numeric tokens detected"
                        }
                        break
            except Exception:
                pass
            
            # Check for predictable patterns
            if len(token1) == len(token2) and token1[:10] == token2[:10]:
                result["predictable"] = True
                result["token_type"] = "predictable_prefix"
                result["evidence"] = {
                    "token1": token1[:20],
                    "token2": token2[:20],
                    "note": "Predictable token prefix detected"
                }
                break
    
    # Check session tokens from auth context
    if auth_context and "cookies" in auth_context:
        cookies = auth_context["cookies"]
        for name, value in cookies.items():
            if "session" in name.lower() or "token" in name.lower():
                if len(value) < 32:
                    result["predictable"] = True
                    result["token_type"] = "short_session_token"
                    result["evidence"] = {
                        "cookie_name": name,
                        "token_length": len(value),
                        "note": "Short session token detected"
                    }
                    break
    
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

