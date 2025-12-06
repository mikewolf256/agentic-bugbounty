#!/usr/bin/env python3
"""API Key/Secret Exposure Tester

Tests for exposed API keys and secrets:
- Scans JavaScript files for hardcoded secrets
- Scans HTTP responses for exposed secrets
- Scans error messages for sensitive data
- Validates exposed secrets (tests if still active)
- Classifies secret types and severity
"""

import os
import re
import time
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse


# Secret patterns for common services
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret_key": re.compile(r'aws_secret_access_key["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']'),
    "github_token": re.compile(r'ghp_[A-Za-z0-9]{36}'),
    "github_oauth": re.compile(r'github.*["\']([0-9a-f]{40})["\']'),
    "stripe_key": re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    "stripe_publishable": re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),
    "slack_token": re.compile(r'xox[baprs]-[0-9a-zA-Z-]{10,}'),
    "google_api_key": re.compile(r'AIza[0-9A-Za-z-_]{35}'),
    "firebase_key": re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),
    "private_key": re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    "jwt_secret": re.compile(r'["\']([A-Za-z0-9_-]{32,})["\'].*jwt|jwt.*["\']([A-Za-z0-9_-]{32,})["\']'),
    "api_key_generic": re.compile(r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})["\']'),
    "secret_generic": re.compile(r'["\']?secret["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{20,})["\']'),
}


def scan_for_secrets(content: str, source: str = "unknown") -> List[Dict[str, Any]]:
    """Scan content for exposed secrets
    
    Args:
        content: Content to scan (JS, HTML, response text, etc.)
        source: Source identifier (URL, file path, etc.)
        
    Returns:
        List of found secrets
    """
    secrets = []
    
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = pattern.finditer(content)
        for match in matches:
            secret_value = match.group(0) if match.lastindex is None else match.group(1)
            if secret_value:
                # Extract context around the secret
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end]
                
                secrets.append({
                    "type": secret_type,
                    "value": secret_value[:100],  # Truncate for safety
                    "source": source,
                    "context": context,
                    "severity": _classify_severity(secret_type, secret_value)
                })
    
    return secrets


def _classify_severity(secret_type: str, secret_value: str) -> str:
    """Classify secret severity
    
    Args:
        secret_type: Type of secret found
        secret_value: Secret value
        
    Returns:
        Severity level (high, medium, low)
    """
    high_severity_types = [
        "aws_secret_key", "private_key", "stripe_key",
        "github_token", "slack_token"
    ]
    
    if secret_type in high_severity_types:
        return "high"
    elif "live" in secret_value.lower() or "production" in secret_value.lower():
        return "high"
    elif secret_type in ["aws_access_key", "google_api_key", "firebase_key"]:
        return "medium"
    else:
        return "low"


def validate_secret(secret_type: str, secret_value: str) -> Dict[str, Any]:
    """Validate if an exposed secret is still active
    
    Args:
        secret_type: Type of secret
        secret_value: Secret value
        
    Returns:
        Dict with validation results
    """
    result = {
        "secret_type": secret_type,
        "active": False,
        "validation_method": None,
        "evidence": None
    }
    
    # AWS Access Key validation (limited - can't fully validate without AWS SDK)
    if secret_type == "aws_access_key":
        # Basic format check
        if secret_value.startswith("AKIA") and len(secret_value) == 20:
            result["validation_method"] = "format_check"
            result["active"] = True  # Assume active if format is correct
            result["evidence"] = {"note": "AWS access key format valid"}
    
    # GitHub token validation
    elif secret_type == "github_token":
        try:
            headers = {"Authorization": f"token {secret_value}"}
            resp = requests.get("https://api.github.com/user", headers=headers, timeout=5)
            if resp.status_code == 200:
                result["active"] = True
                result["validation_method"] = "api_check"
                result["evidence"] = {
                    "status_code": resp.status_code,
                    "note": "GitHub token is active"
                }
        except Exception:
            pass
    
    # Stripe key validation (limited - can't fully validate without Stripe SDK)
    elif secret_type in ["stripe_key", "stripe_publishable"]:
        if "live" in secret_value.lower():
            result["validation_method"] = "format_check"
            result["active"] = True
            result["evidence"] = {"note": "Stripe live key detected"}
    
    return result


def scan_js_files(base_url: str, discovery_data: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Scan JavaScript files for secrets (extends js_miner.py functionality)
    
    Args:
        base_url: Base URL
        discovery_data: Optional discovery data with JS file URLs
        
    Returns:
        List of found secrets
    """
    all_secrets = []
    
    # Use js_miner to discover JS files
    try:
        from tools.js_miner import run as js_miner_run
        import tempfile
        
        with tempfile.TemporaryDirectory() as tmpdir:
            js_miner_run(base_url, tmpdir)
            
            # Scan discovered JS files
            js_dir = os.path.join(tmpdir, "js")
            if os.path.exists(js_dir):
                for js_file in os.listdir(js_dir):
                    js_path = os.path.join(js_dir, js_file)
                    with open(js_path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                        secrets = scan_for_secrets(content, source=f"js:{js_file}")
                        all_secrets.extend(secrets)
    except Exception as e:
        print(f"[SECRET-EXPOSURE] JS mining failed: {e}")
    
    return all_secrets


def scan_http_responses(target_url: str, endpoints: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Scan HTTP responses for exposed secrets
    
    Args:
        target_url: Target URL
        endpoints: Optional list of endpoints to scan
        
    Returns:
        List of found secrets
    """
    all_secrets = []
    
    # If no endpoints provided, try common endpoints
    if not endpoints:
        endpoints = [
            target_url,
            f"{target_url}/api",
            f"{target_url}/config",
            f"{target_url}/.env",
            f"{target_url}/config.json",
        ]
    
    for endpoint in endpoints:
        try:
            resp = requests.get(endpoint, timeout=10)
            secrets = scan_for_secrets(resp.text, source=endpoint)
            all_secrets.extend(secrets)
            
            # Also check error messages
            if resp.status_code >= 400:
                error_secrets = scan_for_secrets(resp.text, source=f"{endpoint}:error")
                all_secrets.extend(error_secrets)
        except Exception:
            continue
    
    return all_secrets


def validate_secret_exposure(
    target_url: str,
    scan_js: bool = True,
    scan_responses: bool = True,
    validate_secrets: bool = True
) -> Dict[str, Any]:
    """Main validation function for secret exposure
    
    Args:
        target_url: Target URL
        scan_js: Whether to scan JavaScript files
        scan_responses: Whether to scan HTTP responses
        validate_secrets: Whether to validate found secrets
        
    Returns:
        Dict with validation results
    """
    results = {
        "target_url": target_url,
        "secrets_found": [],
        "validated_secrets": [],
        "severity": "low",
        "high_severity_count": 0
    }
    
    all_secrets = []
    
    # Scan JavaScript files
    if scan_js:
        js_secrets = scan_js_files(target_url)
        all_secrets.extend(js_secrets)
    
    # Scan HTTP responses
    if scan_responses:
        response_secrets = scan_http_responses(target_url)
        all_secrets.extend(response_secrets)
    
    # Deduplicate secrets
    seen = set()
    unique_secrets = []
    for secret in all_secrets:
        secret_key = (secret["type"], secret["value"])
        if secret_key not in seen:
            seen.add(secret_key)
            unique_secrets.append(secret)
    
    results["secrets_found"] = unique_secrets
    
    # Validate secrets if requested
    if validate_secrets:
        for secret in unique_secrets:
            validation = validate_secret(secret["type"], secret["value"])
            if validation["active"]:
                results["validated_secrets"].append({
                    "secret": secret,
                    "validation": validation
                })
    
    # Calculate overall severity
    high_severity = [s for s in unique_secrets if s["severity"] == "high"]
    results["high_severity_count"] = len(high_severity)
    
    if high_severity:
        results["severity"] = "high"
    elif len(unique_secrets) > 5:
        results["severity"] = "medium"
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="Secret Exposure Tester")
    ap.add_argument("--target", required=True, help="Target URL")
    ap.add_argument("--scan-js", action="store_true", default=True, help="Scan JavaScript files")
    ap.add_argument("--scan-responses", action="store_true", default=True, help="Scan HTTP responses")
    ap.add_argument("--validate-secrets", action="store_true", default=True, help="Validate found secrets")
    args = ap.parse_args()
    
    result = validate_secret_exposure(
        args.target,
        scan_js=args.scan_js,
        scan_responses=args.scan_responses,
        validate_secrets=args.validate_secrets
    )
    
    import json
    print(json.dumps(result, indent=2))

