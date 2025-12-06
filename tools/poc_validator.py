#!/usr/bin/env python3
"""POC Validator Module

Validates proof of concept exploitability and quality before report inclusion.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional


def validate_poc(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a finding's POC quality and exploitability.
    
    Args:
        finding: Finding dict with validation data
    
    Returns:
        Dict with validation results:
        {
            "poc_validated": bool,
            "poc_quality_score": "high" | "medium" | "low",
            "validation_evidence_complete": bool,
            "reasons": List[str],
            "missing_evidence": List[str],
        }
    """
    result = {
        "poc_validated": False,
        "poc_quality_score": "low",
        "validation_evidence_complete": False,
        "reasons": [],
        "missing_evidence": [],
    }
    
    validation = finding.get("validation") or {}
    validation_status = finding.get("validation_status", "unknown")
    validation_engines = finding.get("validation_engines") or []
    
    # Check for validation evidence
    has_validation_evidence = False
    confirmed_engines = []
    
    # Check each validation engine
    engine_checks = {
        "dalfox": lambda v: v.get("dalfox_confirmed", False) or v.get("dalfox", {}).get("engine_result") == "confirmed",
        "sqlmap": lambda v: v.get("sqlmap", {}).get("engine_result") in ("confirmed", "vulnerable"),
        "bac": lambda v: v.get("bac", {}).get("confirmed_issues_count", 0) > 0,
        "ssrf": lambda v: v.get("ssrf", {}).get("confirmed_issues_count", 0) > 0,
        "oauth": lambda v: v.get("oauth", {}).get("vulnerable_count", 0) > 0,
        "race": lambda v: v.get("race", {}).get("vulnerable", False),
        "smuggling": lambda v: v.get("smuggling", {}).get("vulnerable", False),
        "graphql": lambda v: v.get("graphql", {}).get("vulnerable", False),
    }
    
    for engine_name, check_func in engine_checks.items():
        engine_data = validation.get(engine_name) or {}
        if check_func(validation):
            has_validation_evidence = True
            confirmed_engines.append(engine_name)
            result["reasons"].append(f"{engine_name} confirmed vulnerability")
    
    # Check for request/response capture
    has_capture = bool(validation.get("request_capture") or finding.get("request_capture"))
    
    # Check for screenshot
    has_screenshot = bool(validation.get("screenshot") or finding.get("screenshot"))
    
    # Check for proof snippet/evidence
    has_proof_snippet = False
    for engine_name in confirmed_engines:
        engine_data = validation.get(engine_name) or {}
        if engine_data.get("proof_snippet") or engine_data.get("evidence") or engine_data.get("payload"):
            has_proof_snippet = True
            break
    
    # Check for manual validation
    has_manual_validation = finding.get("manual_validation", False)
    
    # Check for browser validation
    browser_validation_enabled = finding.get("browser_validation_enabled", False)
    browser_validation_result = None
    if browser_validation_enabled:
        try:
            from tools.poc_browser_validator import BrowserPOCValidator
            browser_validator = BrowserPOCValidator()
            browser_validation_result = browser_validator.validate_finding_with_browser(finding)
            
            # Merge browser validation results
            if browser_validation_result:
                if browser_validation_result.get("screenshot_path"):
                    validation["browser_validation"] = browser_validation_result
                    has_screenshot = True  # Update screenshot flag
                    result["reasons"].append("Browser-validated screenshot available")
                
                if browser_validation_result.get("console_logs"):
                    validation["browser_console_logs"] = browser_validation_result["console_logs"]
                
                if browser_validation_result.get("visual_indicators"):
                    validation["browser_visual_indicators"] = browser_validation_result["visual_indicators"]
                    result["reasons"].append("Browser visual validation indicators present")
        except ImportError:
            pass  # Browser validator not available
        except Exception as e:
            print(f"[POC-VALIDATOR] Browser validation failed: {e}", file=sys.stderr)
    
    # Determine POC validation status
    if has_validation_evidence or has_manual_validation or (browser_validation_result and browser_validation_result.get("validated")):
        result["poc_validated"] = True
        result["reasons"].append("Validation evidence present")
    else:
        result["missing_evidence"].append("No validation engine confirmation")
        result["reasons"].append("No validation evidence found")
    
    # Determine quality score
    score_points = 0
    
    # Validation engine confirmation (high weight)
    if has_validation_evidence:
        score_points += 3
        if len(confirmed_engines) > 1:
            score_points += 1  # Multiple engines confirm
    
    # Browser validation (high weight)
    if browser_validation_result and browser_validation_result.get("validated"):
        score_points += 3
        if browser_validation_result.get("screenshot_path"):
            score_points += 1  # Extra point for screenshot
    
    # Request/response capture
    if has_capture:
        score_points += 2
        result["reasons"].append("Request/response capture available")
    else:
        result["missing_evidence"].append("Request/response capture")
    
    # Screenshot
    if has_screenshot:
        score_points += 1
        result["reasons"].append("Screenshot available")
    
    # Proof snippet
    if has_proof_snippet:
        score_points += 2
        result["reasons"].append("Proof snippet/evidence available")
    else:
        if not has_capture:
            result["missing_evidence"].append("Proof snippet or request/response capture")
    
    # Manual validation
    if has_manual_validation:
        score_points += 1
        result["reasons"].append("Manual validation provided")
    
    # Confidence level
    confidence = finding.get("confidence", "low").lower()
    if confidence == "high":
        score_points += 1
    elif confidence == "medium":
        score_points += 0.5
    
    # Determine quality score
    if score_points >= 6:
        result["poc_quality_score"] = "high"
    elif score_points >= 3:
        result["poc_quality_score"] = "medium"
    else:
        result["poc_quality_score"] = "low"
    
    # Check if evidence is complete
    result["validation_evidence_complete"] = (
        has_validation_evidence and
        (has_capture or has_proof_snippet) and
        result["poc_quality_score"] in ("high", "medium")
    )
    
    return result


def validate_findings(findings: List[Dict[str, Any]], require_validation: bool = True) -> Dict[str, Any]:
    """Validate a list of findings and filter by POC validation.
    
    Args:
        findings: List of findings to validate
        require_validation: If True, only return validated findings
    
    Returns:
        Dict with:
        {
            "validated": List[Dict],  # Findings that passed validation
            "rejected": List[Dict],   # Findings that failed validation
            "stats": {
                "total": int,
                "validated": int,
                "rejected": int,
                "high_quality": int,
                "medium_quality": int,
                "low_quality": int,
            }
        }
    """
    validated = []
    rejected = []
    
    stats = {
        "total": len(findings),
        "validated": 0,
        "rejected": 0,
        "high_quality": 0,
        "medium_quality": 0,
        "low_quality": 0,
    }
    
    for finding in findings:
        validation_result = validate_poc(finding)
        
        # Add validation result to finding
        finding["_poc_validation"] = validation_result
        
        if validation_result["poc_validated"]:
            if not require_validation or validation_result["validation_evidence_complete"]:
                validated.append(finding)
                stats["validated"] += 1
                
                quality = validation_result["poc_quality_score"]
                if quality == "high":
                    stats["high_quality"] += 1
                elif quality == "medium":
                    stats["medium_quality"] += 1
                else:
                    stats["low_quality"] += 1
            else:
                rejected.append(finding)
                stats["rejected"] += 1
        else:
            rejected.append(finding)
            stats["rejected"] += 1
    
    return {
        "validated": validated,
        "rejected": rejected,
        "stats": stats,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="POC Validator")
    ap.add_argument("--findings-file", required=True, help="JSON file with findings")
    ap.add_argument("--output", help="Output JSON file (default: validated_<input_file>)")
    ap.add_argument("--require-validation", action="store_true", help="Only include validated findings")
    ap.add_argument("--stats-only", action="store_true", help="Only output statistics")
    
    args = ap.parse_args()
    
    # Load findings
    with open(args.findings_file, "r", encoding="utf-8") as fh:
        findings = json.load(fh)
    
    if not isinstance(findings, list):
        findings = [findings]
    
    print(f"[POC-VALIDATOR] Validating {len(findings)} findings...", file=sys.stderr)
    
    # Validate findings
    result = validate_findings(findings, require_validation=args.require_validation)
    
    stats = result["stats"]
    print(f"[POC-VALIDATOR] Validated: {stats['validated']}, Rejected: {stats['rejected']}", file=sys.stderr)
    print(f"[POC-VALIDATOR] Quality: High: {stats['high_quality']}, Medium: {stats['medium_quality']}, Low: {stats['low_quality']}", file=sys.stderr)
    
    if args.stats_only:
        print(json.dumps(stats, indent=2))
        return
    
    # Output file
    if args.output:
        out_path = args.output
    else:
        base = os.path.basename(args.findings_file)
        name, ext = os.path.splitext(base)
        out_path = f"validated_{name}{ext}"
    
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    
    # Save validated findings
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    print(f"[POC-VALIDATOR] Saved validation results to {out_path}")
    print(out_path)


if __name__ == "__main__":
    main()

