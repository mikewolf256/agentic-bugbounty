#!/usr/bin/env python3
"""Business Logic Analyzer

Analyzes application workflows and business rules to identify logic flaws:
- Workflow state transitions
- Pricing/quantity manipulation
- Rate limit bypasses
- Permission escalation
- Workflow bypasses
"""

import os
import re
import requests
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


def analyze_workflow(discovery_data: Dict[str, Any], auth_context: Optional[Dict] = None) -> Dict[str, Any]:
    """Analyze application workflow from discovery data
    
    Args:
        discovery_data: Discovery data containing endpoints, URLs, etc.
        auth_context: Optional authentication context (cookies, headers)
        
    Returns:
        Dict with workflow analysis
    """
    workflow = {
        "endpoints": [],
        "state_transitions": [],
        "business_rules": [],
        "workflow_patterns": []
    }
    
    # Extract endpoints from discovery data
    endpoints = []
    if "api_endpoints" in discovery_data:
        endpoints = discovery_data["api_endpoints"]
    elif "endpoints" in discovery_data:
        endpoints = discovery_data["endpoints"]
    elif "web" in discovery_data and "api_endpoints" in discovery_data["web"]:
        endpoints = discovery_data["web"]["api_endpoints"]
    
    # Extract URLs if endpoints not available
    urls = []
    if "urls" in discovery_data:
        urls = discovery_data["urls"]
    elif "web" in discovery_data and "urls" in discovery_data["web"]:
        urls = discovery_data["web"]["urls"]
    
    # Convert URLs to endpoint-like structures
    for url in urls:
        parsed = urlparse(url)
        endpoint = {
            "url": url,
            "method": "GET",  # Default, will be discovered
            "path": parsed.path,
            "parameters": []
        }
        endpoints.append(endpoint)
    
    workflow["endpoints"] = endpoints
    
    # Identify workflow patterns
    # E-commerce: cart → checkout → payment → confirmation
    # User management: register → verify → login → profile
    # Content: create → review → publish
    
    # Detect e-commerce workflow
    cart_endpoints = [e for e in endpoints if any(kw in str(e).lower() for kw in ["cart", "basket", "add-to-cart"])]
    checkout_endpoints = [e for e in endpoints if any(kw in str(e).lower() for kw in ["checkout", "payment", "pay"])]
    order_endpoints = [e for e in endpoints if any(kw in str(e).lower() for kw in ["order", "purchase", "confirm"])]
    
    if cart_endpoints and checkout_endpoints:
        workflow["workflow_patterns"].append({
            "type": "ecommerce",
            "steps": [
                {"name": "cart", "endpoints": cart_endpoints},
                {"name": "checkout", "endpoints": checkout_endpoints},
                {"name": "order", "endpoints": order_endpoints}
            ]
        })
    
    # Detect user management workflow
    register_endpoints = [e for e in endpoints if any(kw in str(e).lower() for kw in ["register", "signup", "create-account"])]
    verify_endpoints = [e for e in endpoints if any(kw in str(e).lower() for kw in ["verify", "confirm", "activation"])]
    login_endpoints = [e for e in endpoints if any(kw in str(e).lower() for kw in ["login", "signin", "auth"])]
    
    if register_endpoints and login_endpoints:
        workflow["workflow_patterns"].append({
            "type": "user_management",
            "steps": [
                {"name": "register", "endpoints": register_endpoints},
                {"name": "verify", "endpoints": verify_endpoints},
                {"name": "login", "endpoints": login_endpoints}
            ]
        })
    
    # Detect content workflow
    create_endpoints = [e for e in endpoints if any(kw in str(e).lower() for kw in ["create", "new", "add"])]
    review_endpoints = [e for e in endpoints if any(kw in str(e).lower() for kw in ["review", "approve", "moderate"])]
    publish_endpoints = [e for e in endpoints if any(kw in str(e).lower() for kw in ["publish", "post", "submit"])]
    
    if create_endpoints and publish_endpoints:
        workflow["workflow_patterns"].append({
            "type": "content",
            "steps": [
                {"name": "create", "endpoints": create_endpoints},
                {"name": "review", "endpoints": review_endpoints},
                {"name": "publish", "endpoints": publish_endpoints}
            ]
        })
    
    return workflow


def test_pricing_manipulation(target_url: str, auth_context: Optional[Dict] = None) -> Dict[str, Any]:
    """Test for pricing manipulation vulnerabilities
    
    Args:
        target_url: Target URL (e.g., cart/checkout endpoint)
        auth_context: Optional authentication context
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "pricing_manipulation",
        "vulnerable": False,
        "evidence": None,
        "target_url": target_url
    }
    
    # Build request with auth context
    headers = {}
    cookies = {}
    if auth_context:
        headers.update(auth_context.get("headers", {}))
        cookies.update(auth_context.get("cookies", {}))
    
    # Test negative prices
    test_payloads = [
        {"price": -100, "quantity": 1},
        {"price": 0, "quantity": 1},
        {"price": 0.01, "quantity": 1000},  # Very low price, high quantity
        {"price": 999999, "quantity": -1},  # Negative quantity
        {"price": "abc", "quantity": 1},  # Invalid price type
    ]
    
    for payload in test_payloads:
        try:
            resp = requests.post(
                target_url,
                json=payload,
                headers=headers,
                cookies=cookies,
                timeout=10,
                allow_redirects=False
            )
            
            # Check if request was accepted (status 200, 201, 302)
            if resp.status_code in (200, 201, 302):
                # Check response for price confirmation
                if "price" in resp.text.lower() or "total" in resp.text.lower():
                    # Try to extract price from response
                    price_match = re.search(r'[\$€£]?\s*(\d+\.?\d*)', resp.text)
                    if price_match:
                        confirmed_price = float(price_match.group(1))
                        # Get payload price and safely convert to float
                        payload_price = payload.get("price", 999999)
                        try:
                            payload_price_float = float(payload_price)
                        except (ValueError, TypeError):
                            # Non-numeric price - just check if confirmed price is <= 0
                            payload_price_float = None
                        
                        if confirmed_price <= 0 or (payload_price_float is not None and confirmed_price < payload_price_float):
                            result["vulnerable"] = True
                            result["evidence"] = {
                                "payload": payload,
                                "confirmed_price": confirmed_price,
                                "status_code": resp.status_code,
                                "response_snippet": resp.text[:500]
                            }
                            break
        except Exception:
            continue
    
    # Test price modification in request
    # Try to modify price parameter directly
    try:
        # First, get a normal request to see structure
        resp = requests.get(target_url, headers=headers, cookies=cookies, timeout=10)
        if resp.status_code == 200:
            # Try to find price in response and modify it
            # This is a simplified test - real implementation would parse forms/JSON
            pass
    except Exception:
        pass
    
    return result


def test_workflow_bypass(target_url: str, workflow: Dict[str, Any], auth_context: Optional[Dict] = None) -> Dict[str, Any]:
    """Test for workflow bypass vulnerabilities
    
    Args:
        target_url: Target URL
        workflow: Workflow analysis result
        auth_context: Optional authentication context
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "workflow_bypass",
        "vulnerable": False,
        "evidence": None,
        "target_url": target_url
    }
    
    # Build request with auth context
    headers = {}
    cookies = {}
    if auth_context:
        headers.update(auth_context.get("headers", {}))
        cookies.update(auth_context.get("cookies", {}))
    
    # Test skipping steps
    # For e-commerce: try to go directly to payment without cart/checkout
    for pattern in workflow.get("workflow_patterns", []):
        if pattern["type"] == "ecommerce":
            # Try to access payment endpoint directly
            payment_endpoints = pattern["steps"][-1].get("endpoints", [])
            for endpoint in payment_endpoints:
                endpoint_url = endpoint.get("url") or endpoint.get("path", "")
                if not endpoint_url.startswith("http"):
                    # Construct full URL
                    parsed = urlparse(target_url)
                    endpoint_url = f"{parsed.scheme}://{parsed.netloc}{endpoint_url}"
                
                try:
                    resp = requests.post(
                        endpoint_url,
                        json={"skip_steps": True},
                        headers=headers,
                        cookies=cookies,
                        timeout=10,
                        allow_redirects=False
                    )
                    
                    # If we can access payment without going through cart/checkout
                    if resp.status_code in (200, 201, 302):
                        result["vulnerable"] = True
                        result["evidence"] = {
                            "bypass_type": "step_skip",
                            "skipped_to": endpoint_url,
                            "status_code": resp.status_code,
                            "response_snippet": resp.text[:500]
                        }
                        break
                except Exception:
                    continue
    
    # Test replay attacks
    # Try to replay a completed workflow step
    # This would require capturing a previous request/response
    
    return result


def test_rate_limit_bypass(target_url: str, auth_context: Optional[Dict] = None) -> Dict[str, Any]:
    """Test for rate limit bypass vulnerabilities
    
    Args:
        target_url: Target URL
        auth_context: Optional authentication context
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "rate_limit_bypass",
        "vulnerable": False,
        "evidence": None,
        "target_url": target_url
    }
    
    # Build request with auth context
    headers = {}
    cookies = {}
    if auth_context:
        headers.update(auth_context.get("headers", {}))
        cookies.update(auth_context.get("cookies", {}))
    
    # Test various bypass techniques
    bypass_techniques = [
        # IP rotation (simulated by changing headers)
        {"X-Forwarded-For": "1.2.3.4"},
        {"X-Real-IP": "5.6.7.8"},
        {"X-Originating-IP": "9.10.11.12"},
        # User-Agent rotation
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        # Header case variation
        {"X-API-Key": headers.get("x-api-key", "test")},
    ]
    
    success_count = 0
    for technique in bypass_techniques:
        test_headers = headers.copy()
        test_headers.update(technique)
        
        try:
            resp = requests.post(
                target_url,
                headers=test_headers,
                cookies=cookies,
                timeout=10
            )
            
            # If request succeeds, rate limit might be bypassed
            if resp.status_code in (200, 201):
                success_count += 1
        except Exception:
            continue
    
    # If multiple techniques work, might indicate rate limit bypass
    if success_count >= 3:
        result["vulnerable"] = True
        result["evidence"] = {
            "bypass_techniques_working": success_count,
            "note": "Multiple rate limit bypass techniques successful"
        }
    
    return result


def validate_business_logic(discovery_data: Dict[str, Any], auth_context: Optional[Dict] = None) -> Dict[str, Any]:
    """Main validation function for business logic vulnerabilities
    
    Args:
        discovery_data: Discovery data containing endpoints, URLs, etc.
        auth_context: Optional authentication context
        
    Returns:
        Dict with validation results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": [],
        "workflow": None
    }
    
    # Analyze workflow
    workflow = analyze_workflow(discovery_data, auth_context)
    results["workflow"] = workflow
    
    # Get target URL
    target = discovery_data.get("target")
    if not target:
        # Try to extract from endpoints
        endpoints = workflow.get("endpoints", [])
        if endpoints:
            first_endpoint = endpoints[0]
            target = first_endpoint.get("url") or first_endpoint.get("path", "")
            if target and not target.startswith("http"):
                target = f"http://{target}"
    
    if not target:
        return results
    
    # Test pricing manipulation (if e-commerce workflow detected)
    if any(p["type"] == "ecommerce" for p in workflow.get("workflow_patterns", [])):
        # Find checkout/payment endpoint
        for pattern in workflow["workflow_patterns"]:
            if pattern["type"] == "ecommerce":
                checkout_endpoints = pattern["steps"][1].get("endpoints", [])
                if checkout_endpoints:
                    checkout_url = checkout_endpoints[0].get("url") or checkout_endpoints[0].get("path", "")
                    if checkout_url and not checkout_url.startswith("http"):
                        parsed = urlparse(target)
                        checkout_url = f"{parsed.scheme}://{parsed.netloc}{checkout_url}"
                    
                    pricing_result = test_pricing_manipulation(checkout_url, auth_context)
                    results["tests_run"] += 1
                    if pricing_result["vulnerable"]:
                        results["vulnerable"] = True
                        results["findings"].append(pricing_result)
                    break
    
    # Test workflow bypass
    bypass_result = test_workflow_bypass(target, workflow, auth_context)
    results["tests_run"] += 1
    if bypass_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(bypass_result)
    
    # Test rate limit bypass
    rate_limit_result = test_rate_limit_bypass(target, auth_context)
    results["tests_run"] += 1
    if rate_limit_result["vulnerable"]:
        results["vulnerable"] = True
        results["findings"].append(rate_limit_result)
    
    return results


if __name__ == "__main__":
    import argparse
    import json
    
    ap = argparse.ArgumentParser(description="Business Logic Analyzer")
    ap.add_argument("--target", required=True, help="Target URL")
    ap.add_argument("--discovery-file", help="JSON file with discovery data")
    args = ap.parse_args()
    
    discovery_data = {"target": args.target}
    if args.discovery_file and os.path.exists(args.discovery_file):
        with open(args.discovery_file, "r") as f:
            discovery_data.update(json.load(f))
    
    results = validate_business_logic(discovery_data)
    print(json.dumps(results, indent=2))

