#!/usr/bin/env python3
"""Attack Graph Builder

Builds comprehensive attack graphs from findings.
"""

from tools.finding_correlation import build_attack_graph, find_chains
from typing import Dict, Any, List


def build_comprehensive_graph(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build comprehensive attack graph
    
    Args:
        findings: List of findings
        
    Returns:
        Dict with comprehensive attack graph
    """
    # Build base graph
    graph = build_attack_graph(findings)
    
    # Find all chains
    chains = find_chains(findings)
    
    # Enhance graph with chain information
    graph["exploitable_chains"] = chains
    graph["chain_count"] = len(chains)
    
    return graph

