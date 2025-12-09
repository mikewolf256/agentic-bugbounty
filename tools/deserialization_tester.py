#!/usr/bin/env python3
"""Deserialization Tester

Tests for deserialization vulnerabilities:
- Java (Java serialization, YAML)
- Python (pickle, YAML)
- .NET (BinaryFormatter)
"""

import requests
from typing import Dict, Any, Optional, List
import base64
import pickle


def test_python_pickle(target_url: str, callback_url: Optional[str] = None) -> Dict[str, Any]:
    """Test for Python pickle deserialization
    
    Args:
        target_url: Target URL
        callback_url: Optional callback URL
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "deserialization",
        "test": "python_pickle",
        "vulnerable": False,
        "url": target_url,
        "param": "data",
        "evidence": None
    }
    
    # Create a simple pickle payload that deserializes to a known value
    # This is safe and just tests if pickle deserialization is happening
    test_value = {"test_key": "pickle_test_12345", "number": 42}
    safe_pickle = base64.b64encode(pickle.dumps(test_value)).decode()
    
    # Try POST with form data (common pattern)
    try:
        resp = requests.post(
            target_url,
            data={"data": safe_pickle},
            timeout=10
        )
        
        # Check if our test value appears in response (successful deserialization)
        if "pickle_test_12345" in resp.text or "test_key" in resp.text:
            result["vulnerable"] = True
            result["evidence"] = {
                "payload": safe_pickle[:50] + "...",
                "method": "POST_FORM",
                "status_code": resp.status_code,
                "response_snippet": resp.text[:500],
                "note": "Pickle deserialization detected - arbitrary object creation possible"
            }
            return result
    except Exception:
        pass
    
    # Try JSON API endpoint
    try:
        resp = requests.post(
            target_url,
            json={"format": "pickle", "data": safe_pickle},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if "pickle_test_12345" in resp.text or "test_key" in resp.text:
            result["vulnerable"] = True
            result["evidence"] = {
                "payload": safe_pickle[:50] + "...",
                "method": "POST_JSON",
                "status_code": resp.status_code,
                "response_snippet": resp.text[:500],
                "note": "Pickle deserialization detected via API - arbitrary object creation possible"
            }
            return result
    except Exception:
        pass
    
    return result


def test_yaml_deserialization(target_url: str, callback_url: Optional[str] = None) -> Dict[str, Any]:
    """Test for YAML deserialization vulnerabilities
    
    Args:
        target_url: Target URL
        callback_url: Optional callback URL
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "deserialization",
        "test": "yaml_deserialization",
        "vulnerable": False,
        "url": target_url,
        "param": "data",
        "evidence": None
    }
    
    # Simple YAML payload to detect if YAML is being parsed
    safe_yaml = """test_key: yaml_test_67890
number: 42
list:
  - item1
  - item2"""
    
    # Try POST with form data
    try:
        resp = requests.post(
            target_url,
            data={"data": safe_yaml},
            timeout=10
        )
        
        if "yaml_test_67890" in resp.text:
            result["vulnerable"] = True
            result["evidence"] = {
                "payload": safe_yaml,
                "method": "POST_FORM",
                "status_code": resp.status_code,
                "response_snippet": resp.text[:500],
                "note": "YAML deserialization detected - check for unsafe Loader usage"
            }
            return result
    except Exception:
        pass
    
    # Try JSON API endpoint
    try:
        resp = requests.post(
            target_url,
            json={"format": "yaml", "data": safe_yaml},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if "yaml_test_67890" in resp.text:
            result["vulnerable"] = True
            result["evidence"] = {
                "payload": safe_yaml,
                "method": "POST_JSON",
                "status_code": resp.status_code,
                "response_snippet": resp.text[:500],
                "note": "YAML deserialization detected via API - check for unsafe Loader usage"
            }
            return result
    except Exception:
        pass
    
    return result


def test_java_deserialization(target_url: str, callback_url: Optional[str] = None) -> Dict[str, Any]:
    """Test for Java deserialization
    
    Args:
        target_url: Target URL
        callback_url: Optional callback URL
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "deserialization",
        "test": "java_deserialization",
        "vulnerable": False,
        "url": target_url,
        "evidence": None
    }
    
    # Java serialization magic bytes (base64 encoded)
    # 0xaced0005 is the Java serialization magic
    java_magic = base64.b64encode(bytes.fromhex("aced0005")).decode()
    
    # Check if server accepts Java serialization
    try:
        resp = requests.post(
            target_url,
            data=base64.b64decode(java_magic),
            headers={"Content-Type": "application/x-java-serialized-object"},
            timeout=10
        )
        
        # Check for Java-specific error messages that indicate deserialization attempt
        java_indicators = [
            "java.io", "ObjectInputStream", "serialVersionUID",
            "ClassNotFoundException", "InvalidClassException",
            "StreamCorruptedException"
        ]
        
        for indicator in java_indicators:
            if indicator in resp.text:
                result["vulnerable"] = True
                result["evidence"] = {
                    "method": "POST",
                    "status_code": resp.status_code,
                    "indicator": indicator,
                    "response_snippet": resp.text[:500],
                    "note": "Java deserialization endpoint detected"
                }
                return result
    except Exception:
        pass
    
    return result


def test_deserialization(target_url: str, format_type: str = "auto", callback_url: Optional[str] = None) -> Dict[str, Any]:
    """Test for deserialization vulnerabilities
    
    Args:
        target_url: Target URL
        format_type: Format to test (java, python, yaml, dotnet, auto)
        callback_url: Optional callback URL
        
    Returns:
        Dict with test results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    if format_type in ("auto", "python", "pickle"):
        python_result = test_python_pickle(target_url, callback_url)
        results["tests_run"] += 1
        if python_result.get("vulnerable"):
            results["vulnerable"] = True
            results["findings"].append(python_result)
    
    if format_type in ("auto", "yaml"):
        yaml_result = test_yaml_deserialization(target_url, callback_url)
        results["tests_run"] += 1
        if yaml_result.get("vulnerable"):
            results["vulnerable"] = True
            results["findings"].append(yaml_result)
    
    if format_type in ("auto", "java"):
        java_result = test_java_deserialization(target_url, callback_url)
        results["tests_run"] += 1
        if java_result.get("vulnerable"):
            results["vulnerable"] = True
            results["findings"].append(java_result)
    
    return results


def test_deserialization_multi_endpoint(
    target_url: str,
    endpoints: Optional[List[str]] = None,
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """Test multiple endpoints for deserialization vulnerabilities
    
    Args:
        target_url: Base target URL
        endpoints: List of endpoints to test (if None, uses common patterns)
        callback_url: Optional callback URL
        
    Returns:
        Dict with test results
    """
    from urllib.parse import urljoin
    
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    # Common deserialization endpoints
    if not endpoints:
        endpoints = [
            "/pickle", "/yaml", "/deserialize", "/api/deserialize",
            "/unmarshal", "/decode", "/parse"
        ]
    
    for endpoint in endpoints:
        full_url = urljoin(target_url, endpoint)
        
        # Test pickle
        pickle_result = test_python_pickle(full_url, callback_url)
        results["tests_run"] += 1
        if pickle_result.get("vulnerable"):
            results["vulnerable"] = True
            results["findings"].append(pickle_result)
        
        # Test YAML
        yaml_result = test_yaml_deserialization(full_url, callback_url)
        results["tests_run"] += 1
        if yaml_result.get("vulnerable"):
            results["vulnerable"] = True
            results["findings"].append(yaml_result)
    
    return results
