#!/usr/bin/env python3
"""Lab Scope Helper - Automated scope configuration for lab testing.

This module provides functions to automatically configure scope for testing
vulnerable labs, ensuring MCP endpoints accept requests from lab URLs.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import requests  # Always import for Session/exceptions support

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


REPO_ROOT = Path(__file__).resolve().parents[1]
LABS_DIR = REPO_ROOT / "labs"


def load_lab_metadata(lab_name: str) -> Dict[str, Any]:
    """Load lab metadata from lab_metadata.json."""
    lab_dir = LABS_DIR / lab_name
    meta_path = lab_dir / "lab_metadata.json"
    if not meta_path.exists():
        raise FileNotFoundError(f"lab_metadata.json not found for lab {lab_name} at {meta_path}")
    return json.loads(meta_path.read_text(encoding="utf-8"))


def get_lab_scope(lab_name: str) -> Dict[str, Any]:
    """Get scope configuration for a lab without setting it.
    
    Args:
        lab_name: Name of the lab (directory under labs/)
        
    Returns:
        Scope configuration dictionary
    """
    meta = load_lab_metadata(lab_name)
    base_url = meta.get("base_url", "http://localhost:8080")
    
    # Parse URL to extract host
    parsed = urlparse(base_url)
    host = parsed.netloc or parsed.path.split("/")[0]
    
    # Create scope configuration
    scope = {
        "program_name": f"lab-{meta.get('name', lab_name)}",
        "primary_targets": [host],
        "secondary_targets": [],
        "rules": {
            "rate_limit": 100,  # Higher rate limit for lab testing
            "excluded_vuln_types": [],
            "requires_poc": False,
        },
        "in_scope": [{"url": base_url}],
    }
    
    return scope


def configure_lab_scope(lab_name: str, mcp_url: str = "http://127.0.0.1:8000") -> Dict[str, Any]:
    """Configure scope for a lab and set it via MCP.
    
    This function:
    1. Loads lab metadata
    2. Extracts base_url
    3. Creates scope configuration
    4. Calls /mcp/set_scope to set active scope
    5. Returns scope configuration
    
    Args:
        lab_name: Name of the lab (directory under labs/)
        mcp_url: MCP server URL (default: http://127.0.0.1:8000)
        
    Returns:
        Scope configuration dictionary
        
    Raises:
        FileNotFoundError: If lab metadata not found
        requests.RequestException: If MCP call fails
    """
    scope = get_lab_scope(lab_name)
    
    # Set scope via MCP
    try:
        set_scope_url = f"{mcp_url}/mcp/set_scope"
        response = safe_post(
            set_scope_url,
            json=scope,
            timeout=10
        )
        response.raise_for_status()
        result = response.json()
        print(f"[LAB-SCOPE] Scope configured for {lab_name}: {result.get('status', 'ok')}")
        print(f"[LAB-SCOPE] Program: {result.get('program_name', scope['program_name'])}")
        print(f"[LAB-SCOPE] Rate limit: {result.get('rate_limit', 'N/A')} req/sec")
    except requests.RequestException as e:
        print(f"[LAB-SCOPE] Warning: Failed to set scope via MCP: {e}")
        print(f"[LAB-SCOPE] Scope configuration created but not set. MCP endpoints may reject requests.")
        raise
    
    return scope


def configure_scope_from_url(base_url: str, program_name: Optional[str] = None, mcp_url: str = "http://127.0.0.1:8000") -> Dict[str, Any]:
    """Configure scope from a base URL (useful for testing arbitrary URLs).
    
    Args:
        base_url: Base URL to test (e.g., "http://localhost:5013")
        program_name: Optional program name (default: "lab-test")
        mcp_url: MCP server URL
        
    Returns:
        Scope configuration dictionary
    """
    parsed = urlparse(base_url)
    host = parsed.netloc or parsed.path.split("/")[0]
    
    scope = {
        "program_name": program_name or "lab-test",
        "primary_targets": [host],
        "secondary_targets": [],
        "rules": {
            "rate_limit": 100,
            "excluded_vuln_types": [],
            "requires_poc": False,
        },
        "in_scope": [{"url": base_url}],
    }
    
    # Set scope via MCP
    try:
        set_scope_url = f"{mcp_url}/mcp/set_scope"
        response = safe_post(
            set_scope_url,
            json=scope,
            timeout=10
        )
        response.raise_for_status()
        result = response.json()
        print(f"[LAB-SCOPE] Scope configured for {base_url}: {result.get('status', 'ok')}")
    except requests.RequestException as e:
        print(f"[LAB-SCOPE] Warning: Failed to set scope via MCP: {e}")
        raise
    
    return scope

