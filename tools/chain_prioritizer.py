#!/usr/bin/env python3
"""Chain Prioritizer

Prioritizes attack chains by exploitability and impact.
"""

from tools.finding_correlation import find_chains, calculate_exploitability_score
from typing import Dict, Any, List


def prioritize_chains(chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Prioritize chains by exploitability and impact
    
    Args:
        chains: List of chains
        
    Returns:
        Prioritized list of chains
    """
    prioritized = []
    
    for chain in chains:
        # Calculate priority score
        exploitability = chain.get("exploitability_score", 0.0)
        confidence = 1.0 if chain.get("confidence") == "high" else 0.5
        
        priority_score = (exploitability * 0.7) + (confidence * 0.3)
        
        chain["priority_score"] = priority_score
        prioritized.append(chain)
    
    # Sort by priority score
    prioritized.sort(key=lambda c: c.get("priority_score", 0.0), reverse=True)
    
    return prioritized

