#!/usr/bin/env python3
"""Cloud IAM Analyzer

Analyzes IAM configurations from metadata responses.
Tests for IAM role assumption and privilege escalation.
"""

import json
import re
from typing import Dict, Any, List, Optional


def analyze_iam_role(role_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze IAM role for misconfigurations
    
    Args:
        role_data: IAM role data from metadata
        
    Returns:
        Dict with analysis results
    """
    result = {
        "role_name": role_data.get("RoleName", ""),
        "vulnerable": False,
        "issues": [],
        "permissions": []
    }
    
    # Extract policies
    policies = role_data.get("Policies", [])
    assume_role_policy = role_data.get("AssumeRolePolicyDocument", {})
    
    # Check for overly permissive assume role policy
    if assume_role_policy:
        statements = assume_role_policy.get("Statement", [])
        for stmt in statements:
            principal = stmt.get("Principal", {})
            if principal.get("AWS") == "*" or principal.get("Service") == "*":
                result["vulnerable"] = True
                result["issues"].append("overly_permissive_assume_role_policy")
    
    # Check for admin permissions
    for policy in policies:
        policy_doc = policy.get("PolicyDocument", {})
        statements = policy_doc.get("Statement", [])
        for stmt in statements:
            effect = stmt.get("Effect", "")
            action = stmt.get("Action", [])
            
            if effect == "Allow":
                if isinstance(action, str):
                    action = [action]
                
                # Check for admin actions
                admin_actions = ["*", "iam:*", "s3:*", "ec2:*"]
                if any(act in action or act == "*" for act in admin_actions):
                    result["vulnerable"] = True
                    result["issues"].append("admin_permissions")
                    result["permissions"].extend(action)
    
    return result


def extract_iam_from_metadata(metadata_response: str) -> Dict[str, Any]:
    """Extract IAM information from metadata response
    
    Args:
        metadata_response: Response from metadata endpoint
        
    Returns:
        Dict with extracted IAM data
    """
    iam_data = {
        "roles": [],
        "credentials": None,
        "policies": []
    }
    
    # Try to parse as JSON
    try:
        data = json.loads(metadata_response)
        if isinstance(data, dict):
            # AWS format
            if "Code" in data and "AccessKeyId" in data:
                iam_data["credentials"] = data
            elif "RoleName" in data:
                iam_data["roles"].append(data)
    except json.JSONDecodeError:
        # Try to extract credentials from text
        access_key_match = re.search(r'AccessKeyId["\']?\s*[:=]\s*["\']?([A-Z0-9]+)', metadata_response)
        secret_key_match = re.search(r'SecretAccessKey["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=]+)', metadata_response)
        
        if access_key_match and secret_key_match:
            iam_data["credentials"] = {
                "AccessKeyId": access_key_match.group(1),
                "SecretAccessKey": secret_key_match.group(1)
            }
    
    return iam_data


def analyze_cloud_iam(metadata_response: str) -> Dict[str, Any]:
    """Analyze cloud IAM from metadata
    
    Args:
        metadata_response: Response from metadata endpoint
        
    Returns:
        Dict with analysis results
    """
    results = {
        "vulnerable": False,
        "findings": [],
        "iam_data": None
    }
    
    # Extract IAM data
    iam_data = extract_iam_from_metadata(metadata_response)
    results["iam_data"] = iam_data
    
    # Analyze credentials
    if iam_data.get("credentials"):
        results["vulnerable"] = True
        results["findings"].append({
            "type": "credentials_exposed",
            "severity": "critical",
            "description": "IAM credentials found in metadata response"
        })
    
    # Analyze roles
    for role in iam_data.get("roles", []):
        role_analysis = analyze_iam_role(role)
        if role_analysis["vulnerable"]:
            results["vulnerable"] = True
            results["findings"].append({
                "type": "iam_misconfiguration",
                "role": role_analysis["role_name"],
                "issues": role_analysis["issues"],
                "permissions": role_analysis["permissions"]
            })
    
    return results

