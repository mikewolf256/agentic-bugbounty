#!/usr/bin/env python3
"""Test script to evaluate vulnerability detection against new labs"""

import requests
import json
import os
from typing import Dict, List, Any

MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8000")

# Expected findings from lab metadata
EXPECTED_FINDINGS = {
    "localhost:5005": {  # XXE Lab
        "type": "xxe",
        "count": 6,
        "endpoints": ["/parse", "/upload", "/api/xml"]
    },
    "localhost:5006": {  # Business Logic Lab
        "type": "business_logic",
        "count": 6,
        "endpoints": ["/cart", "/checkout", "/api/purchase", "/api/rate-limit"]
    },
    "localhost:5007": {  # Cloud Lab
        "type": "cloud",
        "count": 7,
        "endpoints": ["/latest/meta-data/", "/computeMetadata/v1/", "/s3/bucket"]
    },
    "localhost:5008": {  # Template Injection Lab
        "type": "ssti",
        "count": 3,
        "endpoints": ["/render", "/search", "/api/render"]
    },
    "localhost:5009": {  # Deserialization Lab
        "type": "deserialization",
        "count": 3,
        "endpoints": ["/pickle", "/yaml", "/api/deserialize"]
    },
    "localhost:5010": {  # GraphQL Lab
        "type": "graphql",
        "count": 4,
        "endpoints": ["/graphql"]
    },
    "localhost:5011": {  # gRPC Lab
        "type": "grpc",
        "count": 3,
        "endpoints": ["/"]
    }
}

def test_xxe_lab(target: str):
    """Test XXE lab"""
    print(f"\n[XXE] Testing {target}...")
    try:
        resp = requests.post(
            f"{MCP_SERVER_URL}/mcp/run_xxe_checks",
            json={"target": f"http://{target}/parse", "use_callback": False},
            timeout=30
        )
        if resp.status_code == 200:
            result = resp.json()
            print(f"  ✓ XXE check completed")
            print(f"  Vulnerable: {result.get('meta', {}).get('vulnerable', False)}")
            print(f"  Findings: {result.get('meta', {}).get('findings_count', 0)}")
            return result
        else:
            print(f"  ✗ Error: HTTP {resp.status_code}")
            return None
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        return None

def test_business_logic_lab(target: str):
    """Test Business Logic lab"""
    print(f"\n[Business Logic] Testing {target}...")
    try:
        resp = requests.post(
            f"{MCP_SERVER_URL}/mcp/run_business_logic_checks",
            json={"target": f"http://{target}"},
            timeout=30
        )
        if resp.status_code == 200:
            result = resp.json()
            print(f"  ✓ Business logic check completed")
            print(f"  Vulnerable: {result.get('meta', {}).get('vulnerable', False)}")
            print(f"  Findings: {result.get('meta', {}).get('findings_count', 0)}")
            return result
        else:
            print(f"  ✗ Error: HTTP {resp.status_code}")
            return None
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        return None

def test_cloud_lab(target: str):
    """Test Cloud lab"""
    print(f"\n[Cloud] Testing {target}...")
    try:
        resp = requests.post(
            f"{MCP_SERVER_URL}/mcp/run_cloud_checks",
            json={"target": f"http://{target}/fetch?url=http://169.254.169.254/latest/meta-data/"},
            timeout=30
        )
        if resp.status_code == 200:
            result = resp.json()
            print(f"  ✓ Cloud check completed")
            print(f"  Vulnerable: {result.get('meta', {}).get('vulnerable', False)}")
            return result
        else:
            print(f"  ✗ Error: HTTP {resp.status_code}")
            return None
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        return None

def test_graphql_lab(target: str):
    """Test GraphQL lab"""
    print(f"\n[GraphQL] Testing {target}...")
    try:
        # Test introspection
        query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
          }
        }
        """
        resp = requests.post(
            f"http://{target}/graphql",
            json={"query": query},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data") and data["data"].get("__schema"):
                print(f"  ✓ GraphQL introspection enabled (vulnerable)")
                return {"vulnerable": True, "type": "introspection"}
            else:
                print(f"  ⚠ GraphQL endpoint works but introspection may be disabled")
                return {"vulnerable": False}
        else:
            print(f"  ✗ Error: HTTP {resp.status_code}")
            return None
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        return None

def test_ssrf_checks(target: str):
    """Test SSRF checks (for cloud lab)"""
    print(f"\n[SSRF] Testing {target}...")
    try:
        resp = requests.post(
            f"{MCP_SERVER_URL}/mcp/run_ssrf_checks",
            json={"target": f"http://{target}/fetch", "param": "url", "use_callback": False},
            timeout=30
        )
        if resp.status_code == 200:
            result = resp.json()
            print(f"  ✓ SSRF check completed")
            issues = result.get("meta", {}).get("confirmed_issues", [])
            print(f"  Confirmed issues: {len(issues)}")
            return result
        else:
            print(f"  ✗ Error: HTTP {resp.status_code}")
            return None
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        return None

def main():
    print("=" * 60)
    print("Testing New Vulnerability Labs")
    print("=" * 60)
    
    # Check MCP server
    try:
        resp = requests.get(f"{MCP_SERVER_URL}/", timeout=5)
        print(f"✓ MCP Server accessible at {MCP_SERVER_URL}")
    except Exception as e:
        print(f"✗ MCP Server not accessible: {e}")
        return
    
    results = {}
    
    # Test XXE Lab
    results["xxe"] = test_xxe_lab("localhost:5005")
    
    # Test Business Logic Lab
    results["business_logic"] = test_business_logic_lab("localhost:5006")
    
    # Test Cloud Lab (via SSRF)
    results["cloud"] = test_ssrf_checks("localhost:5007")
    
    # Test GraphQL Lab
    results["graphql"] = test_graphql_lab("localhost:5010")
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    total_expected = sum(EXPECTED_FINDINGS[t]["count"] for t in EXPECTED_FINDINGS)
    print(f"Total expected findings: {total_expected}")
    
    detected = 0
    for test_type, result in results.items():
        if result:
            if isinstance(result, dict):
                if result.get("vulnerable") or result.get("meta", {}).get("vulnerable"):
                    detected += 1
                    print(f"✓ {test_type}: Vulnerable detected")
                else:
                    print(f"✗ {test_type}: Not detected")
            else:
                print(f"? {test_type}: Unknown result")
        else:
            print(f"✗ {test_type}: Test failed")
    
    print(f"\nDetection rate: {detected}/{len(results)} tests detected vulnerabilities")
    
    # Save results
    with open("/tmp/lab_test_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to /tmp/lab_test_results.json")

if __name__ == "__main__":
    main()

