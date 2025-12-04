#!/usr/bin/env python3
"""Finding Correlation Engine

Detects vulnerability chains and builds attack path graphs.
Examples: SSRF → metadata → takeover, XSS → CSRF → account takeover
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse


# Vulnerability chain patterns
CHAIN_PATTERNS = [
    {
        "name": "ssrf_to_metadata",
        "steps": ["ssrf", "metadata_exposure", "cloud_takeover"],
        "description": "SSRF leading to cloud metadata exposure and potential takeover",
    },
    {
        "name": "xss_to_csrf",
        "steps": ["xss", "csrf", "account_takeover"],
        "description": "XSS enabling CSRF attacks leading to account takeover",
    },
    {
        "name": "idor_to_data_exposure",
        "steps": ["idor", "sensitive_data_exposure"],
        "description": "IDOR leading to sensitive data exposure",
    },
    {
        "name": "auth_bypass_to_privilege_escalation",
        "steps": ["authentication_bypass", "privilege_escalation"],
        "description": "Authentication bypass leading to privilege escalation",
    },
]


def classify_vulnerability(finding: Dict[str, Any]) -> List[str]:
    """Classify a finding into vulnerability types."""
    types = []
    
    name = (finding.get("name") or finding.get("vulnerability_type") or "").lower()
    cwe = str(finding.get("cwe") or finding.get("cweid") or "")
    description = (finding.get("description") or "").lower()
    
    # XSS
    if "xss" in name or "cross-site scripting" in name or "79" in cwe:
        types.append("xss")
    
    # SSRF
    if "ssrf" in name or "server-side request forgery" in name or "918" in cwe:
        types.append("ssrf")
    
    # IDOR
    if "idor" in name or "insecure direct object reference" in name or "639" in cwe:
        types.append("idor")
    
    # CSRF
    if "csrf" in name or "cross-site request forgery" in name or "352" in cwe:
        types.append("csrf")
    
    # Authentication bypass
    if "auth" in name and ("bypass" in name or "broken" in name):
        types.append("authentication_bypass")
    
    # Privilege escalation
    if "privilege" in name or "escalation" in name:
        types.append("privilege_escalation")
    
    # Metadata exposure
    if "metadata" in description or "169.254.169.254" in description:
        types.append("metadata_exposure")
    
    # Cloud takeover
    if "cloud" in description or "aws" in description or "gcp" in description:
        types.append("cloud_takeover")
    
    # Sensitive data exposure
    if "sensitive" in description or "data exposure" in name:
        types.append("sensitive_data_exposure")
    
    return types


def build_attack_graph(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build an attack graph from findings."""
    graph = {
        "nodes": [],
        "edges": [],
        "chains": [],
    }
    
    # Create nodes for each finding
    finding_nodes = {}
    for i, finding in enumerate(findings):
        node_id = f"finding_{i}"
        vuln_types = classify_vulnerability(finding)
        
        node = {
            "id": node_id,
            "finding": finding,
            "vulnerability_types": vuln_types,
            "url": finding.get("url") or finding.get("uri", ""),
        }
        
        graph["nodes"].append(node)
        finding_nodes[i] = node
        
        # Store node by vulnerability type for chain detection
        for vuln_type in vuln_types:
            if vuln_type not in finding_nodes:
                finding_nodes[vuln_type] = []
            if isinstance(finding_nodes[vuln_type], list):
                finding_nodes[vuln_type].append(node)
    
    # Detect chains
    for pattern in CHAIN_PATTERNS:
        steps = pattern["steps"]
        chain_findings = []
        
        for step in steps:
            # Find nodes matching this step
            matching_nodes = []
            for node in graph["nodes"]:
                if step in node["vulnerability_types"]:
                    matching_nodes.append(node)
            
            if matching_nodes:
                chain_findings.append(matching_nodes)
            else:
                break  # Chain broken, can't continue
        
        # If we found all steps, create a chain
        if len(chain_findings) == len(steps):
            chain = {
                "name": pattern["name"],
                "description": pattern["description"],
                "steps": [n[0]["id"] for n in chain_findings],  # Use first matching node per step
                "confidence": "high" if len(chain_findings) == len(steps) else "medium",
            }
            graph["chains"].append(chain)
            
            # Create edges between chain steps
            for i in range(len(chain_findings) - 1):
                from_node = chain_findings[i][0]["id"]
                to_node = chain_findings[i + 1][0]["id"]
                graph["edges"].append({
                    "from": from_node,
                    "to": to_node,
                    "type": "chain",
                    "chain": pattern["name"],
                })
    
    # Create edges between findings on same host/domain
    for i, node1 in enumerate(graph["nodes"]):
        for j, node2 in enumerate(graph["nodes"]):
            if i >= j:
                continue
            
            url1 = node1.get("url", "")
            url2 = node2.get("url", "")
            
            if url1 and url2:
                parsed1 = urlparse(url1)
                parsed2 = urlparse(url2)
                
                # Same domain
                if parsed1.netloc == parsed2.netloc:
                    graph["edges"].append({
                        "from": node1["id"],
                        "to": node2["id"],
                        "type": "same_domain",
                    })
    
    return graph


def correlate_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Correlate findings to detect chains and attack paths."""
    result = {
        "findings_count": len(findings),
        "attack_graph": build_attack_graph(findings),
        "chains_detected": [],
        "high_value_paths": [],
    }
    
    # Extract chains
    for chain in result["attack_graph"]["chains"]:
        result["chains_detected"].append({
            "name": chain["name"],
            "description": chain["description"],
            "steps_count": len(chain["steps"]),
            "confidence": chain["confidence"],
        })
    
    # Identify high-value paths (chains with high confidence)
    result["high_value_paths"] = [
        chain for chain in result["chains_detected"]
        if chain["confidence"] == "high"
    ]
    
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="Finding Correlation Engine")
    ap.add_argument("--findings-file", required=True, help="JSON file with findings")
    ap.add_argument("--output", help="Output JSON file (default: correlated_<input_file>)")
    
    args = ap.parse_args()
    
    # Load findings
    with open(args.findings_file, "r", encoding="utf-8") as fh:
        findings = json.load(fh)
    
    if not isinstance(findings, list):
        findings = [findings]
    
    print(f"[CORRELATION] Analyzing {len(findings)} findings...", file=sys.stderr)
    
    # Correlate
    result = correlate_findings(findings)
    
    print(f"[CORRELATION] Detected {len(result['chains_detected'])} vulnerability chains", file=sys.stderr)
    print(f"[CORRELATION] Found {len(result['high_value_paths'])} high-value attack paths", file=sys.stderr)
    
    # Output file
    if args.output:
        out_path = args.output
    else:
        base = os.path.basename(args.findings_file)
        name, ext = os.path.splitext(base)
        out_path = f"correlated_{name}{ext}"
    
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    print(out_path)


if __name__ == "__main__":
    main()

