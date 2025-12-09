#!/usr/bin/env python3
"""CSRF Discovery Module

Discovers state-changing endpoints that may be vulnerable to CSRF:
- POST, PUT, DELETE endpoints
- Endpoints that modify user data or application state
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional
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




def discover_state_changing_endpoints(
    base_url: str,
    discovery_data: Optional[Dict[str, Any]] = None,
    endpoints: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Discover state-changing endpoints from discovery data or base URL.
    
    Args:
        base_url: Base URL to scan
        discovery_data: Optional discovery data containing endpoints
        endpoints: Optional explicit list of endpoints to test
        
    Returns:
        Dict with discovered endpoints and metadata
    """
    from urllib.parse import urljoin
    import re
    
    results = {
        "base_url": base_url,
        "state_changing_endpoints": [],
        "csrf_prone_endpoints": [],
    }
    
    # Use explicit endpoints if provided
    endpoint_list = endpoints or []
    
    # Extract endpoints from discovery data if no explicit list
    if not endpoint_list and discovery_data:
        if "api_endpoints" in discovery_data:
            endpoint_list = discovery_data["api_endpoints"]
        elif "endpoints" in discovery_data:
            endpoint_list = discovery_data["endpoints"]
        elif "web" in discovery_data and "api_endpoints" in discovery_data["web"]:
            endpoint_list = discovery_data["web"]["api_endpoints"]
    
    # If still no endpoints, crawl the site to discover them
    if not endpoint_list:
        discovered_urls = _crawl_for_endpoints(base_url)
        for url in discovered_urls:
            endpoint_list.append({"url": url, "method": "POST"})
        
        # Also add common CSRF-prone endpoints
        common_csrf_endpoints = [
            "/api/user/update",
            "/api/profile",
            "/api/account",
            "/api/transfer",
            "/api/settings",
            "/user/update",
            "/profile",
            "/account",
            "/transfer",
            "/settings",
            "/api/change-password",
            "/api/change-email",
        ]
        for ep in common_csrf_endpoints:
            full_url = urljoin(base_url, ep)
            if full_url not in [e.get("url") for e in endpoint_list]:
                endpoint_list.append({"url": full_url, "method": "POST"})
    
    # Keywords that suggest state-changing operations
    state_changing_keywords = [
        "create", "update", "delete", "remove", "add", "edit",
        "modify", "change", "set", "post", "put", "patch",
        "transfer", "purchase", "order", "checkout", "payment",
        "register", "signup", "subscribe", "unsubscribe",
        "activate", "deactivate", "enable", "disable",
        "api", "user", "account", "profile", "login",
    ]
    
    # State-changing HTTP methods
    state_changing_methods = ["POST", "PUT", "DELETE", "PATCH"]
    
    for endpoint in endpoint_list:
        url = endpoint.get("url") or endpoint.get("path", "")
        method = endpoint.get("method", "POST").upper()
        
        # Make sure URL is absolute
        if not url.startswith("http"):
            url = urljoin(base_url, url)
        
        # Check if endpoint suggests state-changing operation
        url_lower = url.lower()
        is_state_changing = (
            method in state_changing_methods or
            any(keyword in url_lower for keyword in state_changing_keywords)
        )
        
        if is_state_changing:
            endpoint_info = {
                "url": url,
                "method": method,
                "path": endpoint.get("path", ""),
                "csrf_prone": True,  # Assume prone until validated
            }
            results["state_changing_endpoints"].append(endpoint_info)
            results["csrf_prone_endpoints"].append(endpoint_info)
    
    return results


def _crawl_for_endpoints(base_url: str, max_pages: int = 10) -> List[str]:
    """Crawl a site to discover endpoints.
    
    Args:
        base_url: Base URL to crawl
        max_pages: Maximum number of pages to crawl
        
    Returns:
        List of discovered endpoint URLs
    """
    import re
    from urllib.parse import urljoin, urlparse
    
    discovered = set()
    visited = set()
    to_visit = [base_url]
    
    # Common API endpoint patterns
    api_patterns = [
        r'/api/[a-zA-Z0-9_/]+',
        r'/v\d+/[a-zA-Z0-9_/]+',
        r'/[a-zA-Z0-9_]+(?:\.php|\.asp|\.aspx)?',
    ]
    
    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)
        if current_url in visited:
            continue
        
        visited.add(current_url)
        
        try:
            resp = safe_get(current_url, timeout=10)
            html = resp.text
            
            # Find forms with action attributes
            form_actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for action in form_actions:
                full_url = urljoin(current_url, action)
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    discovered.add(full_url)
            
            # Find href links
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for href in hrefs:
                full_url = urljoin(current_url, href)
                parsed = urlparse(full_url)
                if parsed.netloc == urlparse(base_url).netloc:
                    # Add to discovered if it looks like an API endpoint
                    if '/api/' in full_url or any(kw in full_url.lower() for kw in ['update', 'delete', 'create', 'transfer', 'purchase']):
                        discovered.add(full_url)
                    # Add to crawl queue
                    if full_url not in visited:
                        to_visit.append(full_url)
            
            # Look for API endpoints mentioned in JavaScript
            for pattern in api_patterns:
                matches = re.findall(pattern, html)
                for match in matches:
                    full_url = urljoin(current_url, match)
                    if urlparse(full_url).netloc == urlparse(base_url).netloc:
                        discovered.add(full_url)
                        
        except Exception:
            continue
    
    return list(discovered)


def main() -> None:
    ap = argparse.ArgumentParser(description="CSRF Endpoint Discovery")
    ap.add_argument("--target", required=True, help="Target base URL")
    ap.add_argument("--discovery-data", help="Path to discovery data JSON file")
    ap.add_argument("--output", help="Output JSON file")
    
    args = ap.parse_args()
    
    # Load discovery data if provided
    discovery_data = None
    if args.discovery_data and os.path.exists(args.discovery_data):
        with open(args.discovery_data, "r", encoding="utf-8") as fh:
            discovery_data = json.load(fh)
    
    # Discover state-changing endpoints
    results = discover_state_changing_endpoints(args.target, discovery_data)
    
    # Output file
    if args.output:
        out_path = args.output
    else:
        parsed = urlparse(args.target)
        host = parsed.netloc.replace(":", "_")
        out_path = f"csrf_discovery_{host}.json"
    
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    
    print(f"[CSRF-DISCOVERY] Found {len(results['state_changing_endpoints'])} state-changing endpoints")
    print(f"[CSRF-DISCOVERY] Found {len(results['csrf_prone_endpoints'])} CSRF-prone endpoints")
    
    print(out_path)


if __name__ == "__main__":
    main()

