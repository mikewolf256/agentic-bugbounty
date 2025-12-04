#!/usr/bin/env python3
"""Finding Deduplication Engine

Deduplicates findings using:
- Semantic similarity matching (embedding-based)
- URL + parameter + vulnerability type clustering
- Confidence scoring for duplicates
- Merge similar findings with evidence aggregation
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse, parse_qs

try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False
    print("[WARNING] sentence-transformers not installed. Using basic deduplication.", file=sys.stderr)


def extract_finding_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    """Extract a key for basic deduplication: (url, param, vuln_type)."""
    url = finding.get("url") or finding.get("uri") or ""
    param = finding.get("param") or ""
    vuln_type = finding.get("vulnerability_type") or finding.get("type") or finding.get("name", "").lower()
    
    # Normalize URL (remove query params for key, keep path)
    parsed = urlparse(url)
    normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    return (normalized_url, param, vuln_type)


def cluster_by_key(findings: List[Dict[str, Any]]) -> Dict[Tuple[str, str, str], List[Dict[str, Any]]]:
    """Cluster findings by URL+param+vuln_type key."""
    clusters = {}
    
    for finding in findings:
        key = extract_finding_key(finding)
        if key not in clusters:
            clusters[key] = []
        clusters[key].append(finding)
    
    return clusters


def merge_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge a cluster of similar findings into one."""
    if not findings:
        return {}
    
    # Use the first finding as base
    merged = findings[0].copy()
    
    # Aggregate evidence
    all_evidence = []
    all_payloads = set()
    all_confidence = []
    
    for f in findings:
        if f.get("evidence"):
            all_evidence.append(f["evidence"])
        if f.get("payload"):
            all_payloads.add(str(f["payload"]))
        if f.get("confidence"):
            all_confidence.append(f["confidence"])
    
    # Merge evidence
    if all_evidence:
        merged["evidence"] = all_evidence
    if all_payloads:
        merged["payloads"] = list(all_payloads)
    
    # Use highest confidence
    if all_confidence:
        confidence_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        merged["confidence"] = max(all_confidence, key=lambda c: confidence_map.get(c.lower(), 0))
    
    # Add deduplication metadata
    merged["_dedup"] = {
        "merged_count": len(findings),
        "original_findings": [f.get("_id") or i for i, f in enumerate(findings)],
    }
    
    return merged


def semantic_similarity_dedup(findings: List[Dict[str, Any]], threshold: float = 0.85) -> List[Dict[str, Any]]:
    """Use semantic similarity to find duplicate findings."""
    if not EMBEDDINGS_AVAILABLE or len(findings) < 2:
        return findings
    
    try:
        # Load embedding model
        model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Create text representations of findings
        finding_texts = []
        for f in findings:
            text_parts = [
                f.get("url", ""),
                f.get("param", ""),
                f.get("vulnerability_type") or f.get("type") or f.get("name", ""),
                f.get("description", "")[:200],
            ]
            finding_texts.append(" ".join(str(p) for p in text_parts if p))
        
        # Compute embeddings
        embeddings = model.encode(finding_texts)
        
        # Find similar pairs
        similar_pairs = []
        for i in range(len(embeddings)):
            for j in range(i + 1, len(embeddings)):
                similarity = np.dot(embeddings[i], embeddings[j]) / (
                    np.linalg.norm(embeddings[i]) * np.linalg.norm(embeddings[j])
                )
                if similarity >= threshold:
                    similar_pairs.append((i, j, similarity))
        
        # Group similar findings
        groups = []
        used = set()
        for i, j, sim in similar_pairs:
            if i not in used and j not in used:
                groups.append([i, j])
                used.add(i)
                used.add(j)
            elif i in used:
                for group in groups:
                    if i in group:
                        group.append(j)
                        used.add(j)
                        break
            elif j in used:
                for group in groups:
                    if j in group:
                        group.append(i)
                        used.add(i)
                        break
        
        # Merge groups
        deduplicated = []
        merged_indices = set()
        
        for group in groups:
            group_findings = [findings[i] for i in group]
            merged = merge_findings(group_findings)
            deduplicated.append(merged)
            merged_indices.update(group)
        
        # Add non-merged findings
        for i, finding in enumerate(findings):
            if i not in merged_indices:
                deduplicated.append(finding)
        
        return deduplicated
    
    except Exception as e:
        print(f"[DEDUP] Semantic similarity failed: {e}, using basic deduplication", file=sys.stderr)
        return findings


def deduplicate_findings(findings: List[Dict[str, Any]], use_semantic: bool = True) -> List[Dict[str, Any]]:
    """Main deduplication function."""
    if not findings:
        return []
    
    # Step 1: Basic clustering by URL+param+vuln_type
    clusters = cluster_by_key(findings)
    
    # Step 2: Merge clusters
    merged = []
    for key, cluster in clusters.items():
        if len(cluster) > 1:
            # Multiple findings with same key - merge them
            merged.append(merge_findings(cluster))
        else:
            # Single finding - keep as is
            merged.append(cluster[0])
    
    # Step 3: Semantic similarity deduplication (if enabled and embeddings available)
    if use_semantic and EMBEDDINGS_AVAILABLE:
        merged = semantic_similarity_dedup(merged)
    
    return merged


def main() -> None:
    ap = argparse.ArgumentParser(description="Finding Deduplication")
    ap.add_argument("--findings-file", required=True, help="JSON file with findings to deduplicate")
    ap.add_argument("--output", help="Output JSON file (default: deduplicated_<input_file>)")
    ap.add_argument("--no-semantic", action="store_true", help="Disable semantic similarity deduplication")
    
    args = ap.parse_args()
    
    # Load findings
    with open(args.findings_file, "r", encoding="utf-8") as fh:
        findings = json.load(fh)
    
    if not isinstance(findings, list):
        findings = [findings]
    
    print(f"[DEDUP] Input: {len(findings)} findings", file=sys.stderr)
    
    # Deduplicate
    deduplicated = deduplicate_findings(findings, use_semantic=not args.no_semantic)
    
    print(f"[DEDUP] Output: {len(deduplicated)} findings ({len(findings) - len(deduplicated)} duplicates removed)", file=sys.stderr)
    
    # Output file
    if args.output:
        out_path = args.output
    else:
        base = os.path.basename(args.findings_file)
        name, ext = os.path.splitext(base)
        out_path = f"deduplicated_{name}{ext}"
    
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(deduplicated, fh, indent=2)
    
    print(out_path)


if __name__ == "__main__":
    main()

