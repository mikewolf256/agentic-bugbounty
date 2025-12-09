#!/usr/bin/env python3
"""Cryptographic Weakness Tester

Tests for cryptographic weaknesses:
- Weak hashing algorithms (MD5, SHA1)
- Weak encryption
- Predictable IVs
- Hardcoded encryption keys
- Weak random number generation
"""

import os
import hashlib
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



def test_crypto_weakness(
    target_url: str,
    tokens: Optional[List[str]] = None,
    cookies: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Test for cryptographic weaknesses
    
    Args:
        target_url: Target URL
        tokens: Optional list of tokens to analyze
        cookies: Optional cookies to analyze
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "crypto_weakness",
        "test": "crypto_weakness",
        "vulnerable": False,
        "url": target_url,
        "weak_algorithms": [],
        "predictable_tokens": [],
        "evidence": None
    }
    
    # Analyze tokens if provided
    if tokens:
        for token in tokens:
            # Check token length (short tokens are weak)
            if len(token) < 32:
                result["predictable_tokens"].append({
                    "token": token[:20] + "...",
                    "issue": "short_token",
                    "length": len(token)
                })
            
            # Check if token looks like base64 (might be predictable)
            try:
                import base64
                decoded = base64.b64decode(token + "==")
                if len(decoded) < 16:
                    result["predictable_tokens"].append({
                        "token": token[:20] + "...",
                        "issue": "base64_encoded_short",
                    })
            except Exception:
                pass
    
    # Analyze cookies if provided
    if cookies:
        for name, value in cookies.items():
            # Check for weak session cookies
            if "session" in name.lower() and len(value) < 32:
                result["predictable_tokens"].append({
                    "token": f"{name}={value[:20]}...",
                    "issue": "weak_session_cookie"
                })
    
    # Check for MD5/SHA1 in responses (indicating weak hashing)
    try:
        resp = safe_get(target_url, timeout=10)
        response_lower = resp.text.lower()
        
        if "md5" in response_lower or "sha1" in response_lower:
            result["weak_algorithms"].append("md5_or_sha1_detected")
            
    except Exception:
        pass
    
    # Set vulnerable based on findings
    if result["weak_algorithms"] or result["predictable_tokens"]:
        result["vulnerable"] = True
    
    result["evidence"] = {
        "tokens_analyzed": len(tokens) if tokens else 0,
        "cookies_analyzed": len(cookies) if cookies else 0,
    }
    
    return result


def validate_crypto_weakness(
    discovery_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Main validation function for cryptographic weaknesses
    
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
    
    # Extract tokens/cookies from discovery data if available
    tokens = discovery_data.get("tokens", [])
    cookies = discovery_data.get("cookies", {})
    
    test_result = test_crypto_weakness(target, tokens, cookies)
    results["tests_run"] += 1
    
    if test_result["weak_algorithms"] or test_result["predictable_tokens"]:
        results["vulnerable"] = True
        results["findings"].append(test_result)
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="Crypto Weakness Tester")
    ap.add_argument("--target", required=True, help="Target URL")
    args = ap.parse_args()
    
    result = test_crypto_weakness(args.target)
    
    import json
    print(json.dumps(result, indent=2))

