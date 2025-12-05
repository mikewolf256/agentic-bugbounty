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
        "test": "parameter_pollution",
        "vulnerable": False,
        "pollution_method": None,
        "evidence": None
    }
    
    if not params:
        params = {"id": "1", "user": "test"}
    
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
            resp = requests.get(test_url, timeout=10)
            
            # Check if admin value was used (parameter pollution)
            response_lower = resp.text.lower()
            if "admin" in response_lower and param_value not in response_lower:
                result["vulnerable"] = True
                result["pollution_method"] = "duplicate_parameter"
                result["evidence"] = {
                    "parameter": param_name,
                    "test_url": test_url,
                    "status_code": resp.status_code,
                    "response_snippet": resp.text[:500],
                    "note": "Parameter pollution detected - second value used"
                }
                break
                
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

