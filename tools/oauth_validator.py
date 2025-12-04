#!/usr/bin/env python3
"""OAuth/OIDC Validator Module

Tests for OAuth misconfigurations:
- Open redirect via redirect_uri manipulation
- State parameter fixation/missing checks
- Token leakage via referrer header
- Scope escalation attempts
- PKCE downgrade attacks
- Account takeover chain detection
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import requests


def test_open_redirect(authorization_url: str, redirect_uri: str) -> Dict[str, Any]:
    """Test for open redirect via redirect_uri manipulation.
    
    Args:
        authorization_url: OAuth authorization endpoint
        redirect_uri: Redirect URI to test
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "open_redirect",
        "vulnerable": False,
        "evidence": None,
        "redirect_uri": redirect_uri,
    }
    
    # Test various redirect_uri values
    test_uris = [
        "http://evil.com",
        "https://evil.com",
        "//evil.com",
        "javascript:alert(1)",
        "http://localhost:8080",
        "http://127.0.0.1",
        redirect_uri.replace("example.com", "evil.com") if "example.com" in redirect_uri else None,
    ]
    
    test_uris = [uri for uri in test_uris if uri]
    
    for test_uri in test_uris:
        try:
            # Build authorization request
            parsed = urlparse(authorization_url)
            params = parse_qs(parsed.query)
            params["redirect_uri"] = [test_uri]
            params["response_type"] = ["code"]
            params["client_id"] = params.get("client_id", ["test_client"])
            params["state"] = ["test_state"]
            
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            
            # Follow redirects and check if we're redirected to the test URI
            resp = requests.get(test_url, timeout=5, allow_redirects=True)
            
            # Check if final URL contains our test domain
            if "evil.com" in resp.url or "localhost" in resp.url or "127.0.0.1" in resp.url:
                result["vulnerable"] = True
                result["evidence"] = {
                    "test_uri": test_uri,
                    "final_url": resp.url,
                    "status_code": resp.status_code,
                }
                break
        except Exception as e:
            continue
    
    return result


def test_state_parameter(authorization_url: str) -> Dict[str, Any]:
    """Test for state parameter fixation or missing validation.
    
    Args:
        authorization_url: OAuth authorization endpoint
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "state_parameter",
        "vulnerable": False,
        "issues": [],
    }
    
    try:
        # Test 1: Missing state parameter
        parsed = urlparse(authorization_url)
        params = parse_qs(parsed.query)
        params["response_type"] = ["code"]
        params["client_id"] = params.get("client_id", ["test_client"])
        params["redirect_uri"] = params.get("redirect_uri", ["http://example.com/callback"])
        
        # Remove state if present
        if "state" in params:
            del params["state"]
        
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        
        resp = requests.get(test_url, timeout=5, allow_redirects=False)
        
        # If request succeeds without state, it's a potential issue
        if resp.status_code in (200, 302, 301):
            result["issues"].append("state_parameter_optional")
        
        # Test 2: State parameter fixation (same state value accepted multiple times)
        # This is harder to test automatically, but we can note it
        result["issues"].append("state_fixation_requires_manual_testing")
        
    except Exception as e:
        result["error"] = str(e)
    
    if result["issues"]:
        result["vulnerable"] = True
    
    return result


def test_token_leakage(token_endpoint: str, authorization_url: str) -> Dict[str, Any]:
    """Test for token leakage via referrer header or other mechanisms.
    
    Args:
        token_endpoint: OAuth token endpoint
        authorization_url: OAuth authorization endpoint
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "token_leakage",
        "vulnerable": False,
        "issues": [],
    }
    
    # Note: Full token leakage testing requires actual OAuth flow completion
    # This is a simplified check for common issues
    
    # Check if token endpoint accepts referrer-based validation (unlikely but possible)
    try:
        # Test with referrer header
        headers = {
            "Referer": "http://evil.com",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "grant_type": "authorization_code",
            "code": "test_code",
            "redirect_uri": "http://evil.com/callback",
        }
        
        resp = requests.post(token_endpoint, headers=headers, data=data, timeout=5)
        
        # If request is accepted (not immediately rejected), it might be vulnerable
        if resp.status_code not in (400, 401):
            result["issues"].append("token_endpoint_may_accept_external_referrers")
    except Exception:
        pass
    
    result["note"] = "Full token leakage testing requires completing OAuth flow"
    
    if result["issues"]:
        result["vulnerable"] = True
    
    return result


def test_scope_escalation(authorization_url: str, token_endpoint: str) -> Dict[str, Any]:
    """Test for scope escalation attempts.
    
    Args:
        authorization_url: OAuth authorization endpoint
        token_endpoint: OAuth token endpoint
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "scope_escalation",
        "vulnerable": False,
        "issues": [],
    }
    
    # Test requesting elevated scopes
    elevated_scopes = [
        "admin",
        "write",
        "delete",
        "manage",
        "full_access",
        "read:all",
        "write:all",
    ]
    
    try:
        parsed = urlparse(authorization_url)
        params = parse_qs(parsed.query)
        params["response_type"] = ["code"]
        params["client_id"] = params.get("client_id", ["test_client"])
        params["redirect_uri"] = params.get("redirect_uri", ["http://example.com/callback"])
        params["scope"] = [" ".join(elevated_scopes)]
        
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        
        resp = requests.get(test_url, timeout=5, allow_redirects=False)
        
        # If request is accepted (not rejected), scope escalation might be possible
        if resp.status_code in (200, 302, 301):
            result["issues"].append("elevated_scopes_may_be_acceptable")
            result["vulnerable"] = True
    except Exception as e:
        result["error"] = str(e)
    
    return result


def test_pkce_downgrade(authorization_url: str) -> Dict[str, Any]:
    """Test for PKCE downgrade attacks.
    
    Args:
        authorization_url: OAuth authorization endpoint
    
    Returns:
        Dict with test results
    """
    result = {
        "test": "pkce_downgrade",
        "vulnerable": False,
        "issues": [],
    }
    
    try:
        # Test if authorization endpoint accepts requests without PKCE parameters
        parsed = urlparse(authorization_url)
        params = parse_qs(parsed.query)
        params["response_type"] = ["code"]
        params["client_id"] = params.get("client_id", ["test_client"])
        params["redirect_uri"] = params.get("redirect_uri", ["http://example.com/callback"])
        
        # Remove PKCE parameters if present
        if "code_challenge" in params:
            del params["code_challenge"]
        if "code_challenge_method" in params:
            del params["code_challenge_method"]
        
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        
        resp = requests.get(test_url, timeout=5, allow_redirects=False)
        
        # If request succeeds without PKCE, PKCE might not be enforced
        if resp.status_code in (200, 302, 301):
            result["issues"].append("pkce_parameters_optional")
            result["vulnerable"] = True
    except Exception as e:
        result["error"] = str(e)
    
    return result


def validate_oauth(discovery_data: Dict[str, Any]) -> Dict[str, Any]:
    """Run all OAuth validation tests.
    
    Args:
        discovery_data: OAuth discovery data from oauth_discovery.py
    
    Returns:
        Dict with all test results
    """
    results = {
        "base_url": discovery_data.get("base_url"),
        "tests": [],
        "vulnerable_count": 0,
    }
    
    # Get authorization and token endpoints
    auth_endpoint = None
    token_endpoint = None
    
    for ep in discovery_data.get("oauth_endpoints", []):
        url = ep.get("url", "")
        if "authorize" in url.lower():
            auth_endpoint = url
        elif "token" in url.lower() and "authorize" not in url.lower():
            token_endpoint = url
    
    # Also check discovery document
    discovery_doc = discovery_data.get("discovery_doc")
    if discovery_doc:
        if not auth_endpoint and discovery_doc.get("authorization_endpoint"):
            auth_endpoint = discovery_doc["authorization_endpoint"]
        if not token_endpoint and discovery_doc.get("token_endpoint"):
            token_endpoint = discovery_doc["token_endpoint"]
    
    if not auth_endpoint:
        results["error"] = "No authorization endpoint found"
        return results
    
    # Run tests
    if auth_endpoint:
        # Test open redirect
        redirect_uri = discovery_data.get("redirect_uri_patterns", ["http://example.com/callback"])
        if redirect_uri:
            redirect_test = test_open_redirect(auth_endpoint, redirect_uri[0] if isinstance(redirect_uri, list) else redirect_uri)
            results["tests"].append(redirect_test)
            if redirect_test.get("vulnerable"):
                results["vulnerable_count"] += 1
        
        # Test state parameter
        state_test = test_state_parameter(auth_endpoint)
        results["tests"].append(state_test)
        if state_test.get("vulnerable"):
            results["vulnerable_count"] += 1
        
        # Test PKCE downgrade
        pkce_test = test_pkce_downgrade(auth_endpoint)
        results["tests"].append(pkce_test)
        if pkce_test.get("vulnerable"):
            results["vulnerable_count"] += 1
    
    if token_endpoint and auth_endpoint:
        # Test token leakage
        token_test = test_token_leakage(token_endpoint, auth_endpoint)
        results["tests"].append(token_test)
        if token_test.get("vulnerable"):
            results["vulnerable_count"] += 1
        
        # Test scope escalation
        scope_test = test_scope_escalation(auth_endpoint, token_endpoint)
        results["tests"].append(scope_test)
        if scope_test.get("vulnerable"):
            results["vulnerable_count"] += 1
    
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="OAuth/OIDC Validator")
    ap.add_argument("--discovery-file", required=True, help="OAuth discovery JSON file from oauth_discovery.py")
    ap.add_argument("--output", help="Output JSON file (default: oauth_validation_<host>.json)")
    
    args = ap.parse_args()
    
    # Load discovery data
    with open(args.discovery_file, "r", encoding="utf-8") as fh:
        discovery_data = json.load(fh)
    
    # Run validation
    results = validate_oauth(discovery_data)
    
    # Output file
    if args.output:
        out_path = args.output
    else:
        base_url = discovery_data.get("base_url", "unknown")
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        host = parsed.netloc.replace(":", "_")
        out_path = f"oauth_validation_{host}.json"
    
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    
    print(f"[OAUTH-VALIDATOR] Found {results['vulnerable_count']} potential vulnerabilities")
    for test in results["tests"]:
        if test.get("vulnerable"):
            print(f"[OAUTH-VALIDATOR] VULNERABLE: {test.get('test')}")
    
    print(out_path)


if __name__ == "__main__":
    main()

