#!/usr/bin/env python3
"""Cloud Storage Tester

Tests for cloud storage bucket misconfigurations (S3, GCS, Azure Blob).
"""

import requests
import re
from typing import Dict, Any, List, Optional


def test_s3_bucket(bucket_name: str, region: Optional[str] = None) -> Dict[str, Any]:
    """Test S3 bucket permissions
    
    Args:
        bucket_name: S3 bucket name
        region: Optional AWS region
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "s3_bucket",
        "bucket": bucket_name,
        "vulnerable": False,
        "permissions": [],
        "evidence": None
    }
    
    # Test various S3 endpoints
    s3_endpoints = [
        f"https://{bucket_name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{bucket_name}/",
    ]
    
    if region:
        s3_endpoints.append(f"https://{bucket_name}.s3.{region}.amazonaws.com/")
    
    for endpoint in s3_endpoints:
        try:
            # Test list access
            resp = requests.get(endpoint, timeout=10)
            if resp.status_code == 200:
                result["vulnerable"] = True
                result["permissions"].append("list")
                result["evidence"] = {
                    "endpoint": endpoint,
                    "status_code": resp.status_code,
                    "response_snippet": resp.text[:500]
                }
            
            # Test write access
            test_key = "test-write-access.txt"
            resp = requests.put(f"{endpoint}{test_key}", data="test", timeout=10)
            if resp.status_code in (200, 201):
                result["permissions"].append("write")
                # Try to delete
                requests.delete(f"{endpoint}{test_key}", timeout=10)
            
        except Exception:
            continue
    
    return result


def test_gcs_bucket(bucket_name: str) -> Dict[str, Any]:
    """Test GCS bucket permissions
    
    Args:
        bucket_name: GCS bucket name
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "gcs_bucket",
        "bucket": bucket_name,
        "vulnerable": False,
        "permissions": [],
        "evidence": None
    }
    
    gcs_endpoints = [
        f"https://storage.googleapis.com/{bucket_name}/",
        f"https://{bucket_name}.storage.googleapis.com/",
    ]
    
    for endpoint in gcs_endpoints:
        try:
            resp = requests.get(endpoint, timeout=10)
            if resp.status_code == 200:
                result["vulnerable"] = True
                result["permissions"].append("list")
                result["evidence"] = {
                    "endpoint": endpoint,
                    "status_code": resp.status_code
                }
        except Exception:
            continue
    
    return result


def enumerate_buckets_from_metadata(metadata_response: str) -> List[str]:
    """Extract bucket names from metadata response
    
    Args:
        metadata_response: Response from metadata endpoint
        
    Returns:
        List of potential bucket names
    """
    buckets = []
    
    # Look for bucket patterns
    bucket_patterns = [
        r'([a-z0-9-]+)\.s3\.amazonaws\.com',
        r's3://([a-z0-9-]+)',
        r'gs://([a-z0-9-]+)',
    ]
    
    for pattern in bucket_patterns:
        matches = re.findall(pattern, metadata_response, re.IGNORECASE)
        buckets.extend(matches)
    
    return list(set(buckets))


def test_cloud_storage(discovery_data: Dict[str, Any]) -> Dict[str, Any]:
    """Test cloud storage buckets
    
    Args:
        discovery_data: Discovery data containing bucket names or metadata
        
    Returns:
        Dict with test results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    # Extract bucket names from discovery data
    bucket_names = discovery_data.get("buckets", [])
    
    # If metadata available, try to extract buckets
    if discovery_data.get("metadata_response"):
        extracted = enumerate_buckets_from_metadata(discovery_data["metadata_response"])
        bucket_names.extend(extracted)
    
    # Test each bucket
    for bucket in bucket_names:
        # Try S3 first
        s3_result = test_s3_bucket(bucket)
        results["tests_run"] += 1
        if s3_result["vulnerable"]:
            results["vulnerable"] = True
            results["findings"].append(s3_result)
        
        # Try GCS
        gcs_result = test_gcs_bucket(bucket)
        results["tests_run"] += 1
        if gcs_result["vulnerable"]:
            results["vulnerable"] = True
            results["findings"].append(gcs_result)
    
    return results

