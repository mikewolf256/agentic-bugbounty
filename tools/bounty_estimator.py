#!/usr/bin/env python3
"""Bounty Estimator

Estimates bug bounty value based on:
- Historical bounty data
- Vulnerability type
- Impact assessment
- Program history
"""

from typing import Dict, Any, List, Optional


def estimate_bounty(finding: Dict[str, Any], program_history: Optional[Dict] = None) -> Dict[str, Any]:
    """Estimate bug bounty value
    
    Args:
        finding: Finding dictionary
        program_history: Optional historical bounty data
        
    Returns:
        Dict with bounty estimate
    """
    estimate = {
        "min": 0,
        "max": 0,
        "estimated": 0,
        "confidence": "low"
    }
    
    # Base estimates by vulnerability type
    base_estimates = {
        "rce": {"min": 5000, "max": 50000, "avg": 15000},
        "ssrf": {"min": 1000, "max": 10000, "avg": 3000},
        "sql_injection": {"min": 2000, "max": 15000, "avg": 5000},
        "xss": {"min": 500, "max": 5000, "avg": 1500},
        "idor": {"min": 500, "max": 5000, "avg": 1500},
        "xxe": {"min": 1000, "max": 10000, "avg": 3000},
        "auth_bypass": {"min": 2000, "max": 20000, "avg": 6000},
    }
    
    vuln_type = finding.get("type", "").lower()
    
    # Find matching base estimate
    base = None
    for key, value in base_estimates.items():
        if key in vuln_type:
            base = value
            break
    
    if not base:
        base = {"min": 100, "max": 1000, "avg": 500}
    
    # Adjust based on impact
    impact_score = finding.get("business_impact_score", 0.5)
    multiplier = 0.5 + (impact_score * 1.5)  # 0.5x to 2.0x
    
    estimate["min"] = int(base["min"] * multiplier)
    estimate["max"] = int(base["max"] * multiplier)
    estimate["estimated"] = int(base["avg"] * multiplier)
    
    # Adjust confidence based on validation
    if finding.get("validated") or finding.get("poc_validated"):
        estimate["confidence"] = "high"
    elif finding.get("confidence") == "high":
        estimate["confidence"] = "medium"
    
    # Use program history if available
    if program_history:
        similar_findings = program_history.get("similar_findings", [])
        if similar_findings:
            avg_bounty = sum(f.get("bounty", 0) for f in similar_findings) / len(similar_findings)
            estimate["estimated"] = int(avg_bounty)
            estimate["confidence"] = "high"
    
    return estimate

