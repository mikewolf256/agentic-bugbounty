#!/usr/bin/env python3
"""Multi-Role BAC (Broken Access Control) Tester

Compares API responses across different user roles to detect:
- Horizontal privilege escalation (user A accessing user B's data)
- Vertical privilege escalation (user accessing admin functions)
- Missing authorization checks
- Inconsistent access control enforcement

Usage:
    python tools/multi_role_bac_tester.py --config roles.yaml --target https://api.example.com
"""

import json
import re
import time
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

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


@dataclass
class Role:
    """Represents a user role with authentication details"""
    name: str
    level: int  # Higher = more privileged (e.g., guest=0, user=1, admin=2)
    auth_type: str = "bearer"  # bearer, cookie, header, basic
    token: Optional[str] = None
    cookies: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    login_url: Optional[str] = None
    login_payload: Optional[Dict[str, str]] = None
    user_id: Optional[str] = None  # For IDOR testing


@dataclass
class EndpointTest:
    """Result of testing an endpoint across roles"""
    endpoint: str
    method: str
    expected_min_role: int  # Minimum role level expected to access
    results: Dict[str, Dict] = field(default_factory=dict)  # role_name -> response info
    vulnerabilities: List[Dict] = field(default_factory=list)


@dataclass
class BACTestResult:
    """Complete BAC test results"""
    target: str
    roles_tested: List[str]
    endpoints_tested: int
    vulnerabilities_found: int
    findings: List[Dict]
    endpoint_matrix: List[Dict]  # Role x Endpoint access matrix


def authenticate_role(role: Role, base_url: str) -> Role:
    """Authenticate a role and obtain tokens
    
    Args:
        role: Role configuration
        base_url: Base URL of the API
        
    Returns:
        Role with authentication tokens populated
    """
    if role.token:
        # Already has token
        return role
    
    if role.login_url and role.login_payload:
        # Perform login
        login_url = urljoin(base_url, role.login_url)
        
        try:
            resp = safe_post(login_url, json=role.login_payload, timeout=10)
            
            if resp.status_code in [200, 201]:
                data = resp.json()
                
                # Try common token field names
                token = (
                    data.get("token") or
                    data.get("access_token") or
                    data.get("jwt") or
                    data.get("auth_token") or
                    data.get("data", {}).get("token")
                )
                
                if token:
                    role.token = token
                
                # Also capture user ID if present
                user_id = (
                    data.get("user_id") or
                    data.get("id") or
                    data.get("user", {}).get("id") or
                    data.get("data", {}).get("id")
                )
                
                if user_id:
                    role.user_id = str(user_id)
                
                # Capture cookies
                if resp.cookies:
                    role.cookies = dict(resp.cookies)
                    
        except Exception as e:
            print(f"[!] Failed to authenticate {role.name}: {e}")
    
    return role


def build_request_kwargs(role: Role) -> Dict[str, Any]:
    """Build request kwargs for a role's authentication"""
    kwargs = {"timeout": 10}
    headers = {}
    
    if role.headers:
        headers.update(role.headers)
    
    if role.auth_type == "bearer" and role.token:
        headers["Authorization"] = f"Bearer {role.token}"
    elif role.auth_type == "header" and role.token:
        headers["X-Auth-Token"] = role.token
    
    if headers:
        kwargs["headers"] = headers
    
    if role.cookies:
        kwargs["cookies"] = role.cookies
    
    return kwargs


def normalize_response(resp) -> Dict[str, Any]:
    """Normalize response for comparison"""
    try:
        body = resp.json()
    except Exception:
        body = resp.text[:500]
    
    return {
        "status_code": resp.status_code,
        "body_type": type(body).__name__,
        "body_hash": hashlib.md5(str(body).encode()).hexdigest()[:16],
        "body_preview": str(body)[:200] if isinstance(body, (str, dict, list)) else str(body),
        "has_data": bool(body) and body != {} and body != [],
        "content_length": len(resp.text),
    }


def extract_data_identifiers(response_body: Any) -> List[str]:
    """Extract potential user/object identifiers from response"""
    identifiers = []
    
    if isinstance(response_body, dict):
        for key in ["id", "user_id", "account_id", "owner_id", "created_by"]:
            if key in response_body:
                identifiers.append(str(response_body[key]))
        
        # Recurse into nested objects
        for value in response_body.values():
            identifiers.extend(extract_data_identifiers(value))
    
    elif isinstance(response_body, list):
        for item in response_body[:10]:  # Limit to first 10 items
            identifiers.extend(extract_data_identifiers(item))
    
    return identifiers


def test_endpoint_across_roles(
    endpoint: str,
    method: str,
    roles: List[Role],
    base_url: str,
    expected_min_role: int = 1,
    rate_limit: float = 0.3
) -> EndpointTest:
    """Test a single endpoint across all roles
    
    Args:
        endpoint: API endpoint path
        method: HTTP method
        roles: List of roles to test
        base_url: Base URL
        expected_min_role: Minimum role level expected to access
        rate_limit: Delay between requests
        
    Returns:
        EndpointTest with results and vulnerabilities
    """
    test = EndpointTest(
        endpoint=endpoint,
        method=method,
        expected_min_role=expected_min_role
    )
    
    url = urljoin(base_url, endpoint)
    
    for role in roles:
        time.sleep(rate_limit)
        
        kwargs = build_request_kwargs(role)
        
        try:
            resp = safe_request(method, url, **kwargs)
            normalized = normalize_response(resp)
            
            # Try to extract identifiers
            try:
                body = resp.json()
                identifiers = extract_data_identifiers(body)
                normalized["identifiers"] = identifiers
            except Exception:
                normalized["identifiers"] = []
            
            test.results[role.name] = {
                "role_level": role.level,
                "user_id": role.user_id,
                **normalized
            }
            
        except Exception as e:
            test.results[role.name] = {
                "role_level": role.level,
                "error": str(e)
            }
    
    # Analyze for vulnerabilities
    test.vulnerabilities = _analyze_role_results(test, roles)
    
    return test


def _analyze_role_results(test: EndpointTest, roles: List[Role]) -> List[Dict]:
    """Analyze test results for access control vulnerabilities"""
    vulnerabilities = []
    
    # Sort roles by level
    sorted_roles = sorted(roles, key=lambda r: r.level)
    
    # Find the highest-privilege role that succeeded
    successful_roles = [
        r for r in sorted_roles
        if test.results.get(r.name, {}).get("status_code") == 200
        and test.results.get(r.name, {}).get("has_data")
    ]
    
    # Check for vertical privilege escalation
    # (lower-privilege role accessing endpoint meant for higher privilege)
    for role in sorted_roles:
        result = test.results.get(role.name, {})
        
        if result.get("status_code") == 200 and result.get("has_data"):
            if role.level < test.expected_min_role:
                vulnerabilities.append({
                    "type": "vertical_privilege_escalation",
                    "severity": "high",
                    "endpoint": test.endpoint,
                    "method": test.method,
                    "role": role.name,
                    "role_level": role.level,
                    "expected_min_level": test.expected_min_role,
                    "confidence": "high",
                    "description": f"Role '{role.name}' (level {role.level}) can access endpoint requiring level {test.expected_min_role}+",
                })
    
    # Check for horizontal privilege escalation (IDOR)
    # Compare data identifiers across same-level roles
    same_level_groups = {}
    for role in sorted_roles:
        level = role.level
        if level not in same_level_groups:
            same_level_groups[level] = []
        same_level_groups[level].append(role)
    
    for level, level_roles in same_level_groups.items():
        if len(level_roles) < 2:
            continue
        
        for i, role_a in enumerate(level_roles):
            for role_b in level_roles[i+1:]:
                result_a = test.results.get(role_a.name, {})
                result_b = test.results.get(role_b.name, {})
                
                ids_a = set(result_a.get("identifiers", []))
                ids_b = set(result_b.get("identifiers", []))
                
                # Check if role_a is seeing role_b's data
                if role_b.user_id and role_b.user_id in ids_a:
                    vulnerabilities.append({
                        "type": "horizontal_privilege_escalation",
                        "severity": "high",
                        "endpoint": test.endpoint,
                        "method": test.method,
                        "accessing_role": role_a.name,
                        "victim_role": role_b.name,
                        "exposed_id": role_b.user_id,
                        "confidence": "high",
                        "description": f"User '{role_a.name}' can see data belonging to '{role_b.name}' (ID: {role_b.user_id})",
                    })
                
                # Check if role_b is seeing role_a's data
                if role_a.user_id and role_a.user_id in ids_b:
                    vulnerabilities.append({
                        "type": "horizontal_privilege_escalation",
                        "severity": "high",
                        "endpoint": test.endpoint,
                        "method": test.method,
                        "accessing_role": role_b.name,
                        "victim_role": role_a.name,
                        "exposed_id": role_a.user_id,
                        "confidence": "high",
                        "description": f"User '{role_b.name}' can see data belonging to '{role_a.name}' (ID: {role_a.user_id})",
                    })
    
    # Check for missing authentication
    unauthenticated_role = next((r for r in sorted_roles if r.level == 0), None)
    if unauthenticated_role:
        unauth_result = test.results.get(unauthenticated_role.name, {})
        if unauth_result.get("status_code") == 200 and unauth_result.get("has_data"):
            # Check if this endpoint should require auth
            if test.expected_min_role > 0:
                vulnerabilities.append({
                    "type": "missing_authentication",
                    "severity": "critical",
                    "endpoint": test.endpoint,
                    "method": test.method,
                    "confidence": "high",
                    "description": f"Endpoint accessible without authentication (expected level {test.expected_min_role}+)",
                })
    
    # Check for inconsistent access control
    # (same data returned regardless of role)
    if len(successful_roles) >= 2:
        body_hashes = set()
        for role in successful_roles:
            result = test.results.get(role.name, {})
            if result.get("body_hash"):
                body_hashes.add(result["body_hash"])
        
        if len(body_hashes) == 1:
            # Same response for all roles
            vulnerabilities.append({
                "type": "inconsistent_access_control",
                "severity": "medium",
                "endpoint": test.endpoint,
                "method": test.method,
                "roles_affected": [r.name for r in successful_roles],
                "confidence": "medium",
                "description": "Same data returned regardless of user role - may indicate missing data filtering",
            })
    
    return vulnerabilities


def discover_endpoints(base_url: str, auth_headers: Optional[Dict] = None) -> List[Tuple[str, str, int]]:
    """Discover API endpoints to test
    
    Returns:
        List of (endpoint, method, expected_min_role) tuples
    """
    endpoints = []
    
    # Common API endpoints with expected access levels
    common_endpoints = [
        # User endpoints (level 1 - authenticated user)
        ("/api/users/me", "GET", 1),
        ("/api/profile", "GET", 1),
        ("/api/account", "GET", 1),
        ("/api/user/profile", "GET", 1),
        ("/api/v1/user", "GET", 1),
        ("/api/me", "GET", 1),
        
        # Data endpoints (level 1 - authenticated user)
        ("/api/users", "GET", 1),
        ("/api/orders", "GET", 1),
        ("/api/documents", "GET", 1),
        ("/api/files", "GET", 1),
        ("/api/messages", "GET", 1),
        ("/api/data", "GET", 1),
        
        # Admin endpoints (level 2 - admin)
        ("/api/admin/users", "GET", 2),
        ("/api/admin/config", "GET", 2),
        ("/api/admin/settings", "GET", 2),
        ("/admin/api/users", "GET", 2),
        ("/api/internal/users", "GET", 2),
        ("/api/management/users", "GET", 2),
        ("/api/v1/admin/users", "GET", 2),
        
        # Super admin endpoints (level 3)
        ("/api/admin/system", "GET", 3),
        ("/api/admin/debug", "GET", 3),
        ("/api/internal/debug", "GET", 3),
    ]
    
    # Try to discover which endpoints exist
    for endpoint, method, level in common_endpoints:
        url = urljoin(base_url, endpoint)
        try:
            resp = safe_get(url, headers=auth_headers or {}, timeout=5)
            # If not 404, endpoint likely exists
            if resp.status_code != 404:
                endpoints.append((endpoint, method, level))
        except Exception:
            pass
    
    return endpoints


def run_multi_role_test(
    target_url: str,
    roles: List[Role],
    endpoints: Optional[List[Tuple[str, str, int]]] = None,
    rate_limit: float = 0.3
) -> BACTestResult:
    """Run complete multi-role BAC test
    
    Args:
        target_url: Target API base URL
        roles: List of roles to test
        endpoints: Optional list of (endpoint, method, expected_level) tuples
        rate_limit: Delay between requests
        
    Returns:
        Complete test results
    """
    result = BACTestResult(
        target=target_url,
        roles_tested=[r.name for r in roles],
        endpoints_tested=0,
        vulnerabilities_found=0,
        findings=[],
        endpoint_matrix=[]
    )
    
    # Authenticate all roles
    print(f"[*] Authenticating {len(roles)} roles...")
    authenticated_roles = []
    for role in roles:
        auth_role = authenticate_role(role, target_url)
        authenticated_roles.append(auth_role)
        status = "✓" if auth_role.token or auth_role.cookies or role.level == 0 else "✗"
        print(f"  {status} {role.name} (level {role.level})")
    
    # Discover or use provided endpoints
    if not endpoints:
        print("[*] Discovering endpoints...")
        # Use highest privilege role for discovery
        highest_role = max(authenticated_roles, key=lambda r: r.level)
        kwargs = build_request_kwargs(highest_role)
        endpoints = discover_endpoints(target_url, kwargs.get("headers"))
        print(f"  Found {len(endpoints)} endpoints")
    
    # Test each endpoint
    print(f"\n[*] Testing {len(endpoints)} endpoints across {len(authenticated_roles)} roles...")
    
    for endpoint, method, expected_level in endpoints:
        print(f"  Testing: {method} {endpoint}")
        
        test = test_endpoint_across_roles(
            endpoint, method, authenticated_roles,
            target_url, expected_level, rate_limit
        )
        
        result.endpoints_tested += 1
        
        # Build matrix row
        matrix_row = {
            "endpoint": endpoint,
            "method": method,
            "expected_level": expected_level,
            "access": {}
        }
        
        for role_name, role_result in test.results.items():
            status_code = role_result.get("status_code", 0)
            has_data = role_result.get("has_data", False)
            
            if status_code == 200 and has_data:
                matrix_row["access"][role_name] = "✓"
            elif status_code == 200:
                matrix_row["access"][role_name] = "○"  # 200 but no data
            elif status_code in [401, 403]:
                matrix_row["access"][role_name] = "✗"
            elif status_code == 404:
                matrix_row["access"][role_name] = "-"
            else:
                matrix_row["access"][role_name] = str(status_code)
        
        result.endpoint_matrix.append(matrix_row)
        
        # Add vulnerabilities
        if test.vulnerabilities:
            result.vulnerabilities_found += len(test.vulnerabilities)
            result.findings.extend(test.vulnerabilities)
            for vuln in test.vulnerabilities:
                print(f"    [!] {vuln['type']}: {vuln['description']}")
    
    return result


def validate_multi_role_bac(discovery_data: Dict[str, Any]) -> Dict[str, Any]:
    """MCP-compatible validation function
    
    Args:
        discovery_data: Discovery data from MCP containing:
            - target: Base URL
            - roles: List of role configurations
            - endpoints: Optional list of endpoints
            
    Returns:
        Validation results
    """
    target_url = discovery_data.get("target") or discovery_data.get("url")
    
    if not target_url:
        return {"error": "No target URL provided", "vulnerable": False}
    
    # Parse roles from discovery data
    roles_config = discovery_data.get("roles", [])
    
    if not roles_config:
        # Use default roles
        roles = [
            Role(name="unauthenticated", level=0),
            Role(name="user", level=1, token=discovery_data.get("user_token")),
            Role(name="admin", level=2, token=discovery_data.get("admin_token")),
        ]
    else:
        roles = []
        for rc in roles_config:
            role = Role(
                name=rc.get("name", "unknown"),
                level=rc.get("level", 1),
                auth_type=rc.get("auth_type", "bearer"),
                token=rc.get("token"),
                cookies=rc.get("cookies"),
                headers=rc.get("headers"),
                login_url=rc.get("login_url"),
                login_payload=rc.get("login_payload"),
                user_id=rc.get("user_id"),
            )
            roles.append(role)
    
    # Parse endpoints
    endpoints = None
    if "endpoints" in discovery_data:
        endpoints = [
            (ep.get("path"), ep.get("method", "GET"), ep.get("expected_level", 1))
            for ep in discovery_data["endpoints"]
        ]
    
    # Run test
    result = run_multi_role_test(target_url, roles, endpoints)
    
    return {
        "vulnerable": result.vulnerabilities_found > 0,
        "vulnerabilities_found": result.vulnerabilities_found,
        "findings": result.findings,
        "endpoint_matrix": result.endpoint_matrix,
        "roles_tested": result.roles_tested,
        "endpoints_tested": result.endpoints_tested,
    }


def print_access_matrix(result: BACTestResult):
    """Print a nice access matrix"""
    if not result.endpoint_matrix:
        return
    
    print("\n" + "=" * 80)
    print("ACCESS MATRIX")
    print("=" * 80)
    print("\nLegend: ✓ = Access with data, ○ = 200 OK no data, ✗ = Denied, - = Not found\n")
    
    # Get role names
    roles = result.roles_tested
    
    # Header
    header = f"{'Endpoint':<40}"
    for role in roles:
        header += f"{role:<12}"
    print(header)
    print("-" * 80)
    
    # Rows
    for row in result.endpoint_matrix:
        line = f"{row['method']} {row['endpoint']:<36}"
        for role in roles:
            access = row["access"].get(role, "?")
            line += f"{access:<12}"
        print(line)
    
    print("=" * 80)


if __name__ == "__main__":
    import argparse
    import yaml
    
    parser = argparse.ArgumentParser(description="Multi-Role BAC Tester")
    parser.add_argument("--target", required=True, help="Target API URL")
    parser.add_argument("--config", help="YAML config file with role definitions")
    parser.add_argument("--user-token", help="User role Bearer token")
    parser.add_argument("--admin-token", help="Admin role Bearer token")
    parser.add_argument("--rate-limit", type=float, default=0.3, help="Delay between requests")
    
    args = parser.parse_args()
    
    # Load roles from config or command line
    roles = []
    
    if args.config:
        with open(args.config) as f:
            config = yaml.safe_load(f)
            for rc in config.get("roles", []):
                roles.append(Role(**rc))
    else:
        # Default roles from command line
        roles = [
            Role(name="unauthenticated", level=0),
        ]
        if args.user_token:
            roles.append(Role(name="user", level=1, token=args.user_token))
        if args.admin_token:
            roles.append(Role(name="admin", level=2, token=args.admin_token))
    
    if len(roles) < 2:
        print("[!] Warning: Need at least 2 roles for comparison testing")
        print("    Provide --user-token and/or --admin-token, or use --config")
    
    print(f"[*] Target: {args.target}")
    print(f"[*] Roles: {[r.name for r in roles]}")
    
    result = run_multi_role_test(args.target, roles, rate_limit=args.rate_limit)
    
    print_access_matrix(result)
    
    print(f"\n[*] Summary:")
    print(f"    Endpoints tested: {result.endpoints_tested}")
    print(f"    Vulnerabilities found: {result.vulnerabilities_found}")
    
    if result.findings:
        print(f"\n[!] Vulnerabilities:")
        for finding in result.findings:
            print(f"\n  Type: {finding['type']}")
            print(f"  Severity: {finding['severity']}")
            print(f"  Description: {finding['description']}")

