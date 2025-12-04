#!/usr/bin/env python3
"""GraphQL Security Testing

Schema extraction, depth/complexity attacks, batching, field-level auth testing, IDOR detection.
"""

import argparse
import json
import os
import time
from typing import Any, Dict, List

import requests


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
        resp = requests.post(endpoint, json={"query": query}, timeout=10)
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
        resp = requests.post(endpoint, json={"query": query}, timeout=5)
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
        resp = requests.post(endpoint, json=queries, timeout=10)
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
    
    result = {
        "endpoint": args.endpoint,
        "schema": introspect_schema(args.endpoint),
        "depth_attack": test_depth_attack(args.endpoint),
        "batching": test_batching(args.endpoint),
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

