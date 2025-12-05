#!/usr/bin/env python3
"""Enhanced scope validation with wildcard and path matching.

This module provides robust scope matching that handles:
- Wildcard domains (*.example.com)
- Path-based scope validation
- Subdomain matching
- URL normalization
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse


def normalize_host(host_or_url: str) -> str:
    """Normalize hostname by removing scheme, path, and port.
    
    Args:
        host_or_url: Hostname or full URL
        
    Returns:
        Normalized hostname (lowercase, no trailing dot)
    """
    if "://" in host_or_url:
        u = urlparse(host_or_url)
        host = (u.netloc or u.path).split("/")[0]
    else:
        host = host_or_url.split("/")[0]
    
    # Remove port
    if ":" in host:
        host = host.split(":")[0]
    
    return host.lower().strip().rstrip(".")


def match_wildcard_domain(host: str, pattern: str) -> bool:
    """Check if host matches a wildcard domain pattern.
    
    Args:
        host: Hostname to check (e.g., "api.example.com")
        pattern: Wildcard pattern (e.g., "*.example.com" or "example.com")
        
    Returns:
        True if host matches pattern
    """
    host = normalize_host(host)
    pattern = pattern.lower().strip()
    
    # Remove wildcard prefix
    if pattern.startswith("*."):
        base_domain = pattern[2:]  # Remove "*."
        # Match any subdomain of base_domain
        return host == base_domain or host.endswith("." + base_domain)
    elif pattern.startswith("*"):
        # Just "*" matches everything
        return True
    else:
        # Exact match
        return host == pattern


def extract_path_scope(scope_entry: Dict[str, Any]) -> Optional[str]:
    """Extract path restriction from scope entry.
    
    Args:
        scope_entry: Scope entry dict with optional "path" or "instruction" field
        
    Returns:
        Path pattern or None if no path restriction
    """
    # Check for explicit path field
    if "path" in scope_entry:
        return scope_entry["path"]
    
    # Check instruction for path hints (e.g., "Only /api/* paths")
    instruction = scope_entry.get("instruction", "")
    if instruction:
        # Look for path patterns in instruction
        path_match = re.search(r'(?:path|only|restricted to)\s*[:=]?\s*([/\w\*\-]+)', instruction, re.IGNORECASE)
        if path_match:
            return path_match.group(1)
    
    return None


def is_url_in_scope(url: str, scope_config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Check if a URL is within scope.
    
    Args:
        url: Full URL to check (or bare hostname)
        scope_config: Scope configuration dict with primary_targets, secondary_targets, in_scope
        
    Returns:
        Tuple of (is_in_scope, reason)
        - is_in_scope: True if URL matches scope
        - reason: Explanation of why it's in/out of scope, or None
    """
    # Handle bare hostnames (no scheme)
    if "://" not in url:
        # Treat as hostname, add http:// for parsing
        url = f"http://{url}"
    
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else ""
    path = parsed.path or "/"
    
    # If still no host, check if the original URL was just a path
    if not host and parsed.path:
        # Original URL was likely just a path, not a valid target
        return False, "No hostname in URL"
    
    if not host:
        return False, "No hostname in URL"
    
    host_normalized = normalize_host(host)
    
    # Check primary_targets and secondary_targets (simple hostname matching)
    primary_targets = scope_config.get("primary_targets", [])
    secondary_targets = scope_config.get("secondary_targets", [])
    
    for target in primary_targets + secondary_targets:
        target_normalized = normalize_host(target)
        if host_normalized == target_normalized:
            return True, f"Matches target: {target}"
    
    # Check in_scope entries (supports wildcards and paths)
    in_scope = scope_config.get("in_scope", [])
    
    for entry in in_scope:
        entry_url = entry.get("url") or entry.get("target") or ""
        if not entry_url:
            continue
        
        entry_host = normalize_host(entry_url)
        
        # Check if host matches (supports wildcards)
        host_matches = False
        if entry_host.startswith("*"):
            host_matches = match_wildcard_domain(host, entry_host)
        else:
            host_matches = host_normalized == entry_host
        
        if not host_matches:
            continue
        
        # Check path restriction if present
        path_scope = extract_path_scope(entry)
        if path_scope:
            # Simple path matching - supports wildcards
            if path_scope.endswith("*"):
                # Prefix match
                path_prefix = path_scope.rstrip("*")
                if not path.startswith(path_prefix):
                    continue
            elif path_scope.endswith("/*"):
                # Directory match
                path_dir = path_scope.rstrip("/*")
                if not path.startswith(path_dir + "/") and path != path_dir:
                    continue
            else:
                # Exact path match
                if path != path_scope:
                    continue
        
        return True, f"Matches in-scope entry: {entry_url}"
    
    return False, f"Host {host} not found in scope"


def validate_scope_entry(entry: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Validate a single scope entry format.
    
    Args:
        entry: Scope entry dict
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(entry, dict):
        return False, "Scope entry must be a dictionary"
    
    url = entry.get("url") or entry.get("target")
    if not url:
        return False, "Scope entry missing 'url' or 'target' field"
    
    # Validate URL format
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if not parsed.netloc and not parsed.path:
        return False, f"Invalid URL format: {url}"
    
    return True, None


def filter_findings_by_scope(findings: List[Dict[str, Any]], scope_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Filter findings to only include in-scope URLs.
    
    Args:
        findings: List of finding dicts (each should have 'url' or 'uri' field)
        scope_config: Scope configuration
        
    Returns:
        Filtered list of findings that are in-scope
    """
    in_scope_findings = []
    
    for finding in findings:
        url = finding.get("url") or finding.get("uri") or ""
        if not url:
            # Finding without URL - skip or include based on policy
            continue
        
        is_in_scope, reason = is_url_in_scope(url, scope_config)
        if is_in_scope:
            # Add scope validation metadata
            finding["_scope_validated"] = True
            finding["_scope_reason"] = reason
            in_scope_findings.append(finding)
        else:
            # Log out-of-scope finding (for debugging)
            finding["_scope_validated"] = False
            finding["_scope_reason"] = reason
    
    return in_scope_findings


def get_scope_summary(scope_config: Dict[str, Any]) -> Dict[str, Any]:
    """Get a summary of scope configuration.
    
    Args:
        scope_config: Scope configuration dict
        
    Returns:
        Summary dict with counts and types
    """
    primary = scope_config.get("primary_targets", [])
    secondary = scope_config.get("secondary_targets", [])
    in_scope = scope_config.get("in_scope", [])
    
    wildcard_count = sum(1 for entry in in_scope if entry.get("url", "").startswith("*"))
    path_restricted_count = sum(1 for entry in in_scope if extract_path_scope(entry) is not None)
    
    return {
        "primary_targets_count": len(primary),
        "secondary_targets_count": len(secondary),
        "in_scope_entries_count": len(in_scope),
        "wildcard_domains_count": wildcard_count,
        "path_restricted_count": path_restricted_count,
        "total_targets": len(primary) + len(secondary) + len(in_scope),
    }

