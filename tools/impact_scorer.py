#!/usr/bin/env python3
"""Impact Scorer

Calculates business impact score for findings.
Considers data exposure, user impact, revenue impact.
"""

from typing import Dict, Any, List, Optional


def calculate_impact_score(finding: Dict[str, Any]) -> float:
    """Calculate business impact score (0.0-1.0)
    
    Args:
        finding: Finding dictionary
        
    Returns:
        Impact score (0.0 = low impact, 1.0 = critical impact)
    """
    score = 0.0
    
    # Factor 1: Data exposure
    data_types = finding.get("data_types_exposed", [])
    sensitive_data = ["pii", "credentials", "financial", "health", "ssn", "credit_card"]
    if any(dt.lower() in str(data_types).lower() for dt in sensitive_data):
        score += 0.4
    
    # Factor 2: User impact
    user_impact = finding.get("user_impact", "low")
    if user_impact == "critical":
        score += 0.3
    elif user_impact == "high":
        score += 0.2
    elif user_impact == "medium":
        score += 0.1
    
    # Factor 3: Revenue impact
    revenue_impact = finding.get("revenue_impact", False)
    if revenue_impact:
        score += 0.2
    
    # Factor 4: Attack surface
    attack_surface = finding.get("attack_surface", "limited")
    if attack_surface == "wide":
        score += 0.1
    
    return min(1.0, score)


def score_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Score all findings by business impact
    
    Args:
        findings: List of findings
        
    Returns:
        List of findings with impact scores, sorted by score
    """
    scored = []
    for finding in findings:
        impact_score = calculate_impact_score(finding)
        finding["business_impact_score"] = impact_score
        scored.append(finding)
    
    # Sort by impact score (highest first)
    scored.sort(key=lambda f: f.get("business_impact_score", 0.0), reverse=True)
    
    return scored

