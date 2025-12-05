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

import requests


def discover_state_changing_endpoints(
    base_url: str,
    discovery_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Discover state-changing endpoints from discovery data or base URL.
    
    Args:
        base_url: Base URL to scan
        discovery_data: Optional discovery data containing endpoints
        
    Returns:
        Dict with discovered endpoints and metadata
    """
    results = {
        "base_url": base_url,
        "state_changing_endpoints": [],
        "csrf_prone_endpoints": [],
    }
    
    # Extract endpoints from discovery data
    endpoints = []
    if discovery_data:
        if "api_endpoints" in discovery_data:
            endpoints = discovery_data["api_endpoints"]
        elif "endpoints" in discovery_data:
            endpoints = discovery_data["endpoints"]
        elif "web" in discovery_data and "api_endpoints" in discovery_data["web"]:
            endpoints = discovery_data["web"]["api_endpoints"]
    
    # Keywords that suggest state-changing operations
    state_changing_keywords = [
        "create", "update", "delete", "remove", "add", "edit",
        "modify", "change", "set", "post", "put", "patch",
        "transfer", "purchase", "order", "checkout", "payment",
        "register", "signup", "subscribe", "unsubscribe",
        "activate", "deactivate", "enable", "disable",
    ]
    
    # State-changing HTTP methods
    state_changing_methods = ["POST", "PUT", "DELETE", "PATCH"]
    
    for endpoint in endpoints:
        url = endpoint.get("url") or endpoint.get("path", "")
        method = endpoint.get("method", "GET").upper()
        
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

