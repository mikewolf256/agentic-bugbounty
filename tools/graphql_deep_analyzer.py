#!/usr/bin/env python3
"""GraphQL Deep Analyzer

Performs deep analysis of GraphQL endpoints:
- Full schema extraction via introspection
- Query complexity analysis
- Nested query detection
"""

import requests
import json
from typing import Dict, Any, List, Optional


def introspect_schema(endpoint: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
    """Extract full GraphQL schema via introspection
    
    Args:
        endpoint: GraphQL endpoint URL
        headers: Optional headers (auth, etc.)
        
    Returns:
        Dict with schema information
    """
    result = {
        "success": False,
        "schema": None,
        "types": [],
        "queries": [],
        "mutations": [],
        "subscriptions": []
    }
    
    introspection_query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }
    
    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }
    
    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }
    
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    
    try:
        resp = requests.post(
            endpoint,
            json={"query": introspection_query},
            headers=headers or {},
            timeout=30
        )
        
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and "__schema" in data["data"]:
                result["success"] = True
                result["schema"] = data["data"]["__schema"]
                
                # Extract types
                result["types"] = data["data"]["__schema"].get("types", [])
                
                # Extract query/mutation/subscription types
                query_type = data["data"]["__schema"].get("queryType", {})
                mutation_type = data["data"]["__schema"].get("mutationType", {})
                subscription_type = data["data"]["__schema"].get("subscriptionType", {})
                
                if query_type:
                    result["queries"] = [t for t in result["types"] if t.get("name") == query_type.get("name")]
                if mutation_type:
                    result["mutations"] = [t for t in result["types"] if t.get("name") == mutation_type.get("name")]
                if subscription_type:
                    result["subscriptions"] = [t for t in result["types"] if t.get("name") == subscription_type.get("name")]
    except Exception as e:
        result["error"] = str(e)
    
    return result


def analyze_query_complexity(schema: Dict[str, Any], query: str) -> Dict[str, Any]:
    """Analyze query complexity
    
    Args:
        schema: GraphQL schema
        query: GraphQL query string
        
    Returns:
        Dict with complexity analysis
    """
    result = {
        "complexity_score": 0,
        "depth": 0,
        "field_count": 0,
        "nested_levels": 0
    }
    
    # Count fields
    field_count = query.count("{")
    result["field_count"] = field_count
    
    # Calculate depth (nesting level)
    max_depth = 0
    current_depth = 0
    for char in query:
        if char == "{":
            current_depth += 1
            max_depth = max(max_depth, current_depth)
        elif char == "}":
            current_depth -= 1
    
    result["depth"] = max_depth
    result["nested_levels"] = max_depth
    
    # Calculate complexity score
    result["complexity_score"] = field_count * max_depth
    
    return result


def analyze_graphql(endpoint: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
    """Perform deep GraphQL analysis
    
    Args:
        endpoint: GraphQL endpoint URL
        headers: Optional headers
        
    Returns:
        Dict with analysis results
    """
    results = {
        "endpoint": endpoint,
        "introspection": {},
        "vulnerabilities": []
    }
    
    # Run introspection
    introspection = introspect_schema(endpoint, headers)
    results["introspection"] = introspection
    
    if introspection["success"]:
        # Check for introspection enabled (potential info disclosure)
        results["vulnerabilities"].append({
            "type": "introspection_enabled",
            "severity": "medium",
            "description": "GraphQL introspection is enabled, exposing full schema"
        })
        
        # Check for sensitive fields in schema
        sensitive_keywords = ["password", "secret", "token", "key", "credential"]
        for type_info in introspection.get("types", []):
            type_name = type_info.get("name", "").lower()
            if any(kw in type_name for kw in sensitive_keywords):
                results["vulnerabilities"].append({
                    "type": "sensitive_field_exposure",
                    "severity": "high",
                    "description": f"Sensitive type found in schema: {type_info.get('name')}"
                })
    
    return results

