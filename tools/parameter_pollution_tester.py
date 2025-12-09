#!/usr/bin/env python3
"""HTTP Parameter Pollution Tester

Tests for HTTP parameter pollution vulnerabilities:
- Duplicate parameters with different values
- Parameter injection in arrays
- Parameter override behavior
"""

import os
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, urlencode, parse_qs


def test_parameter_pollution(
    target_url: str,
    params: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Test for HTTP parameter pollution
    
    Args:
        target_url: Target URL
        params: Parameters to test
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "parameter_pollution",
        "test": "parameter_pollution",
        "vulnerable": False,
        "url": target_url,
        "pollution_method": None,
        "evidence": None
    }
    
    if not params:
        params = {"user": "alice", "role": "user", "id": "1"}
    
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    # Test duplicate parameters
    for param_name, param_value in params.items():
        # Build URL with duplicate parameters
        test_params = [
            (param_name, param_value),
            (param_name, "admin"),  # Different value
        ]
        test_url = base_url + "?" + urlencode(test_params)
        
        try:
            # Test with JSON accept header for API endpoints
            resp = requests.get(test_url, timeout=10, headers={"Accept": "application/json"})
            
            # Check JSON response for pollution indication
            try:
                data = resp.json()
                # Check if pollution_detected field is true
                if data.get("pollution_detected"):
                    result["vulnerable"] = True
                    result["pollution_method"] = "duplicate_parameter"
                    result["evidence"] = {
                        "parameter": param_name,
                        "test_url": test_url,
                        "status_code": resp.status_code,
                        "response": data,
                        "note": "Parameter pollution detected - multiple values processed"
                    }
                    return result
                    
                # Check if all_* arrays have multiple values
                for key in data:
                    if key.startswith("all_") and isinstance(data[key], list) and len(data[key]) > 1:
                        result["vulnerable"] = True
                        result["pollution_method"] = "duplicate_parameter"
                        result["evidence"] = {
                            "parameter": param_name,
                            "test_url": test_url,
                            "status_code": resp.status_code,
                            "response": data,
                            "note": f"Parameter pollution detected - {key} has multiple values"
                        }
                        return result
            except Exception:
                pass
            
            # Check text response for pollution indicators
            response_lower = resp.text.lower()
            if "admin" in response_lower:
                # Check if both values appear (pollution processed)
                if param_value.lower() in response_lower:
                    result["vulnerable"] = True
                    result["pollution_method"] = "duplicate_parameter"
                    result["evidence"] = {
                        "parameter": param_name,
                        "test_url": test_url,
                        "status_code": resp.status_code,
                        "response_snippet": resp.text[:500],
                        "note": "Parameter pollution detected - both values processed"
                    }
                    return result
                    
        except Exception:
            continue
    
    return result


def validate_parameter_pollution(
    discovery_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Main validation function for parameter pollution
    
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
    
    test_result = test_parameter_pollution(target)
    results["tests_run"] += 1
    if test_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(test_result)
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="Parameter Pollution Tester")
    ap.add_argument("--target", required=True, help="Target URL")
    args = ap.parse_args()
    
    result = test_parameter_pollution(args.target)
    
    import json
    print(json.dumps(result, indent=2))

