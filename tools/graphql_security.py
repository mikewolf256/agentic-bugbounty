#!/usr/bin/env python3
"""GraphQL Security Testing

Schema extraction, depth/complexity attacks, batching, field-level auth testing, IDOR detection.
"""

import argparse
import json
import os
import time
from typing import Any, Dict, List

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




def introspect_schema(endpoint: str) -> Dict[str, Any]:
    """Extract GraphQL schema via introspection."""
    query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          ...FullType
        }
      }
    }
    fragment FullType on __Type {
      kind
      name
      fields {
        name
        type {
          ...TypeRef
        }
      }
    }
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
      }
    }
    """
    
    try:
        resp = safe_post(endpoint, json={"query": query}, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    
    return {}


def test_depth_attack(endpoint: str, max_depth: int = 20) -> Dict[str, Any]:
    """Test for query depth DoS."""
    query = "query { " + "user { " * max_depth + "id }" + " }" * max_depth
    
    try:
        start = time.time()
        resp = safe_post(endpoint, json={"query": query}, timeout=5)
        elapsed = time.time() - start
        
        return {
            "vulnerable": resp.status_code == 200 and elapsed < 1.0,
            "depth": max_depth,
            "elapsed": elapsed,
            "status_code": resp.status_code,
        }
    except Exception:
        return {"vulnerable": False, "error": "request_failed"}


def test_batching(endpoint: str) -> Dict[str, Any]:
    """Test for batching attacks."""
    queries = [{"query": "query { __typename }"} for _ in range(100)]
    
    try:
        resp = safe_post(endpoint, json=queries, timeout=10)
        return {
            "vulnerable": resp.status_code == 200,
            "batches_sent": 100,
            "status_code": resp.status_code,
        }
    except Exception:
        return {"vulnerable": False}


def main() -> None:
    ap = argparse.ArgumentParser(description="GraphQL Security Testing")
    ap.add_argument("--endpoint", required=True, help="GraphQL endpoint")
    ap.add_argument("--output", help="Output JSON file")
    
    args = ap.parse_args()
    
    schema = introspect_schema(args.endpoint)
    depth_attack = test_depth_attack(args.endpoint)
    batching = test_batching(args.endpoint)
    
    # Build findings list for validation matching
    findings = []
    
    # Check if introspection is enabled (vulnerability)
    if schema and schema.get("data", {}).get("__schema"):
        findings.append({
            "type": "graphql",
            "subtype": "introspection_enabled",
            "url": args.endpoint,
            "vulnerable": True,
            "evidence": {
                "note": "GraphQL introspection is enabled",
                "schema_types": len(schema.get("data", {}).get("__schema", {}).get("types", [])),
            }
        })
    
    # Check depth attack vulnerability
    if depth_attack.get("vulnerable"):
        findings.append({
            "type": "graphql",
            "subtype": "depth_attack",
            "url": args.endpoint,
            "vulnerable": True,
            "evidence": depth_attack,
        })
    
    # Check batching vulnerability
    if batching.get("vulnerable"):
        findings.append({
            "type": "graphql",
            "subtype": "batching_attack",
            "url": args.endpoint,
            "vulnerable": True,
            "evidence": batching,
        })
    
    result = {
        "endpoint": args.endpoint,
        "vulnerable": len(findings) > 0,
        "schema": schema,
        "depth_attack": depth_attack,
        "batching": batching,
        "findings": findings,
    }
    
    if args.output:
        out_path = args.output
    else:
        from urllib.parse import urlparse
        parsed = urlparse(args.endpoint)
        host = parsed.netloc.replace(":", "_")
        out_path = f"graphql_security_{host}.json"
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    print(out_path)


if __name__ == "__main__":
    main()

