#!/usr/bin/env python3
"""OAuth/OIDC Discovery Module

Detects OAuth/OIDC endpoints and parses OpenID Connect discovery documents.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests


def discover_oauth_endpoints(base_url: str) -> Dict[str, Any]:
    """Discover OAuth/OIDC endpoints from a base URL.
    
    Args:
        base_url: Base URL to scan (e.g., https://example.com)
    
    Returns:
        Dict with discovered endpoints and metadata
    """
    results = {
        "base_url": base_url,
        "oauth_endpoints": [],
        "oidc_endpoints": [],
        "discovery_doc": None,
        "flows_detected": [],
        "redirect_uri_patterns": [],
    }
    
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    # Common OAuth/OIDC endpoint paths
    oauth_paths = [
        "/oauth/authorize",
        "/oauth/token",
        "/oauth/revoke",
        "/oauth/introspect",
        "/oauth/userinfo",
        "/oauth/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server",
    ]
    
    oidc_paths = [
        "/.well-known/openid-configuration",
        "/.well-known/openid-connect",
        "/oauth/.well-known/openid-configuration",
    ]
    
    # Test OAuth endpoints
    for path in oauth_paths:
        url = urljoin(base, path)
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code in (200, 400, 401):  # 400/401 indicate endpoint exists
                results["oauth_endpoints"].append({
                    "url": url,
                    "status_code": resp.status_code,
                    "content_type": resp.headers.get("Content-Type", ""),
                })
        except Exception:
            pass
    
    # Test OIDC discovery endpoint
    for path in oidc_paths:
        url = urljoin(base, path)
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                try:
                    discovery = resp.json()
                    results["discovery_doc"] = discovery
                    results["oidc_endpoints"].append({
                        "url": url,
                        "status_code": resp.status_code,
                    })
                    
                    # Extract endpoints from discovery document
                    if "authorization_endpoint" in discovery:
                        results["oauth_endpoints"].append({
                            "url": discovery["authorization_endpoint"],
                            "source": "discovery_doc",
                            "status_code": None,
                        })
                    if "token_endpoint" in discovery:
                        results["oauth_endpoints"].append({
                            "url": discovery["token_endpoint"],
                            "source": "discovery_doc",
                            "status_code": None,
                        })
                    if "userinfo_endpoint" in discovery:
                        results["oauth_endpoints"].append({
                            "url": discovery["userinfo_endpoint"],
                            "source": "discovery_doc",
                            "status_code": None,
                        })
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
    
    # Extract OAuth flows from discovery document
    if results["discovery_doc"]:
        doc = results["discovery_doc"]
        response_types = doc.get("response_types_supported", [])
        grant_types = doc.get("grant_types_supported", [])
        
        if "code" in response_types:
            results["flows_detected"].append("authorization_code")
        if "token" in response_types or "id_token token" in response_types:
            results["flows_detected"].append("implicit")
        if "client_credentials" in grant_types:
            results["flows_detected"].append("client_credentials")
        if "password" in grant_types:
            results["flows_detected"].append("resource_owner_password")
        
        # Check for PKCE support
        if doc.get("code_challenge_methods_supported"):
            results["flows_detected"].append("pkce")
    
    # Extract redirect_uri validation patterns (if available in discovery doc)
    if results["discovery_doc"]:
        doc = results["discovery_doc"]
        # Some discovery docs include redirect_uri validation hints
        if "redirect_uris" in doc:
            results["redirect_uri_patterns"] = doc["redirect_uris"]
    
    return results


def extract_oauth_from_js(js_content: str, base_url: str) -> List[Dict[str, Any]]:
    """Extract OAuth configuration from JavaScript code.
    
    Args:
        js_content: JavaScript source code
        base_url: Base URL for resolving relative URLs
    
    Returns:
        List of discovered OAuth endpoints and configurations
    """
    findings = []
    
    # Patterns to detect OAuth flows
    patterns = [
        (r'["\']([^"\']*oauth[^"\']*authorize[^"\']*)["\']', "authorization_endpoint"),
        (r'["\']([^"\']*oauth[^"\']*token[^"\']*)["\']', "token_endpoint"),
        (r'["\']([^"\']*\.well-known/openid-configuration[^"\']*)["\']', "discovery_endpoint"),
        (r'redirect_uri["\']?\s*[:=]\s*["\']([^"\']+)["\']', "redirect_uri"),
        (r'client_id["\']?\s*[:=]\s*["\']([^"\']+)["\']', "client_id"),
        (r'response_type["\']?\s*[:=]\s*["\']([^"\']+)["\']', "response_type"),
    ]
    
    for pattern, label in patterns:
        matches = re.finditer(pattern, js_content, re.IGNORECASE)
        for match in matches:
            value = match.group(1)
            # Resolve relative URLs
            if value.startswith("/") or value.startswith("http"):
                url = urljoin(base_url, value)
            else:
                url = value
            
            findings.append({
                "type": label,
                "value": value,
                "url": url if url.startswith("http") else None,
                "context": match.group(0)[:100],  # First 100 chars of match
            })
    
    return findings


def main() -> None:
    ap = argparse.ArgumentParser(description="OAuth/OIDC Discovery")
    ap.add_argument("--target", required=True, help="Target base URL")
    ap.add_argument("--output", help="Output JSON file (default: oauth_discovery_<host>.json)")
    
    args = ap.parse_args()
    
    # Discover OAuth endpoints
    results = discover_oauth_endpoints(args.target)
    
    # Output file
    if args.output:
        out_path = args.output
    else:
        parsed = urlparse(args.target)
        host = parsed.netloc.replace(":", "_")
        out_path = f"oauth_discovery_{host}.json"
    
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    
    print(f"[OAUTH-DISCOVERY] Found {len(results['oauth_endpoints'])} OAuth endpoints")
    print(f"[OAUTH-DISCOVERY] Found {len(results['oidc_endpoints'])} OIDC endpoints")
    if results["discovery_doc"]:
        print(f"[OAUTH-DISCOVERY] Discovery document found")
        print(f"[OAUTH-DISCOVERY] Flows detected: {', '.join(results['flows_detected'])}")
    
    print(out_path)


if __name__ == "__main__":
    main()

