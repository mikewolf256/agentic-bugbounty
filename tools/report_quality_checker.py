#!/usr/bin/env python3
"""Report Quality Checker

Scores report quality and validates completeness before submission.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional


def check_report_completeness(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """Check if a report has all required fields.
    
    Args:
        report_data: Report data (from triage JSON)
    
    Returns:
        Dict with completeness check results
    """
    required_fields = [
        "title",
        "summary",
        "repro",
        "impact",
        "remediation",
        "cvss_score",
        "cvss_vector",
        "cwe",
    ]
    
    missing_fields = []
    for field in required_fields:
        value = report_data.get(field)
        if not value or (isinstance(value, str) and value.lower() in ("tbd", "n/a", "")):
            missing_fields.append(field)
    
    return {
        "complete": len(missing_fields) == 0,
        "missing_fields": missing_fields,
        "completeness_score": (len(required_fields) - len(missing_fields)) / len(required_fields),
    }


def check_poc_validation(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """Check POC validation status.
    
    Args:
        report_data: Report data
    
    Returns:
        Dict with POC validation check results
    """
    poc_validated = report_data.get("poc_validated", False)
    poc_quality = report_data.get("poc_quality_score", "low")
    evidence_complete = report_data.get("validation_evidence_complete", False)
    validation_status = report_data.get("validation_status", "unknown")
    
    validation_engines = report_data.get("validation_engines") or []
    has_validation = len(validation_engines) > 0
    
    return {
        "poc_validated": poc_validated,
        "poc_quality": poc_quality,
        "evidence_complete": evidence_complete,
        "validation_status": validation_status,
        "has_validation": has_validation,
        "validation_engines_count": len(validation_engines),
    }


def check_scope_compliance(report_data: Dict[str, Any], scope: Dict[str, Any]) -> Dict[str, Any]:
    """Check if report is within scope.
    
    Args:
        report_data: Report data
        scope: Scope configuration
    
    Returns:
        Dict with scope compliance check results
    """
    # Extract URL/host from finding
    raw_finding = report_data.get("_raw_finding", {})
    url = raw_finding.get("url") or raw_finding.get("uri") or ""
    
    # Basic scope check (simplified)
    in_scope = True
    if scope and scope.get("in_scope"):
        # Check if URL matches any in-scope entry
        in_scope_entries = scope.get("in_scope", [])
        if in_scope_entries:
            # Simple check - in production, use proper scope matching
            in_scope = any(
                entry.get("url", "") in url or entry.get("target", "") in url
                for entry in in_scope_entries
            )
    
    return {
        "in_scope": in_scope,
        "url": url,
    }


def check_sensitive_data(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """Check for sensitive data exposure in report.
    
    Args:
        report_data: Report data
    
    Returns:
        Dict with sensitive data check results
    """
    issues = []
    
    # Check for potential credential leaks
    text_fields = [
        report_data.get("summary", ""),
        report_data.get("repro", ""),
        report_data.get("impact", ""),
    ]
    
    sensitive_patterns = [
        ("password", "Potential password exposure"),
        ("api_key", "Potential API key exposure"),
        ("secret", "Potential secret exposure"),
        ("token", "Potential token exposure"),
        ("credential", "Potential credential exposure"),
    ]
    
    for field_text in text_fields:
        field_lower = field_text.lower()
        for pattern, issue in sensitive_patterns:
            if pattern in field_lower and len(field_lower) > 50:  # Avoid false positives
                # Check if it's not just a description
                if "example" not in field_lower and "sample" not in field_lower:
                    issues.append(issue)
                    break
    
    return {
        "has_sensitive_data": len(issues) > 0,
        "issues": issues,
    }


def score_report_quality(report_data: Dict[str, Any], scope: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Score overall report quality.
    
    Args:
        report_data: Report data
        scope: Optional scope configuration
    
    Returns:
        Dict with quality score and breakdown
    """
    score = 0
    max_score = 100
    breakdown = {}
    
    # Completeness (30 points)
    completeness = check_report_completeness(report_data)
    completeness_score = completeness["completeness_score"] * 30
    score += completeness_score
    breakdown["completeness"] = {
        "score": completeness_score,
        "max": 30,
        "missing_fields": completeness["missing_fields"],
    }
    
    # POC Validation (40 points)
    poc_check = check_poc_validation(report_data)
    poc_score = 0
    if poc_check["poc_validated"]:
        poc_score += 20
    if poc_check["evidence_complete"]:
        poc_score += 20
    elif poc_check["has_validation"]:
        poc_score += 10
    
    quality_bonus = {"high": 10, "medium": 5, "low": 0}.get(poc_check["poc_quality"], 0)
    poc_score += quality_bonus
    
    score += min(poc_score, 40)
    breakdown["poc_validation"] = {
        "score": poc_score,
        "max": 40,
        "details": poc_check,
    }
    
    # Scope Compliance (15 points)
    if scope:
        scope_check = check_scope_compliance(report_data, scope)
        scope_score = 15 if scope_check["in_scope"] else 0
        score += scope_score
        breakdown["scope_compliance"] = {
            "score": scope_score,
            "max": 15,
            "in_scope": scope_check["in_scope"],
        }
    else:
        breakdown["scope_compliance"] = {
            "score": 0,
            "max": 15,
            "note": "Scope not provided",
        }
    
    # Evidence Quality (15 points)
    validation_engines = report_data.get("validation_engines") or []
    evidence_score = min(len(validation_engines) * 5, 15)
    score += evidence_score
    breakdown["evidence_quality"] = {
        "score": evidence_score,
        "max": 15,
        "validation_engines": len(validation_engines),
    }
    
    # Overall quality rating
    if score >= 80:
        quality_rating = "excellent"
    elif score >= 60:
        quality_rating = "good"
    elif score >= 40:
        quality_rating = "fair"
    else:
        quality_rating = "poor"
    
    # Sensitive data check
    sensitive_check = check_sensitive_data(report_data)
    
    return {
        "total_score": score,
        "max_score": max_score,
        "quality_rating": quality_rating,
        "breakdown": breakdown,
        "sensitive_data_check": sensitive_check,
        "recommendations": _generate_recommendations(breakdown, sensitive_check),
    }


def _generate_recommendations(breakdown: Dict[str, Any], sensitive_check: Dict[str, Any]) -> List[str]:
    """Generate recommendations for improving report quality."""
    recommendations = []
    
    # Completeness recommendations
    missing = breakdown.get("completeness", {}).get("missing_fields", [])
    if missing:
        recommendations.append(f"Fill in missing required fields: {', '.join(missing)}")
    
    # POC validation recommendations
    poc_details = breakdown.get("poc_validation", {}).get("details", {})
    if not poc_details.get("poc_validated"):
        recommendations.append("Add POC validation evidence")
    if not poc_details.get("evidence_complete"):
        recommendations.append("Complete validation evidence (add request/response captures or proof snippets)")
    
    # Scope recommendations
    scope = breakdown.get("scope_compliance", {})
    if not scope.get("in_scope") and scope.get("score", 0) == 0:
        recommendations.append("Verify target is within scope")
    
    # Sensitive data recommendations
    if sensitive_check.get("has_sensitive_data"):
        recommendations.append("Review report for sensitive data exposure - sanitize if needed")
    
    return recommendations


def main() -> None:
    ap = argparse.ArgumentParser(description="Report Quality Checker")
    ap.add_argument("--report-file", required=True, help="JSON file with report/triage data")
    ap.add_argument("--scope-file", help="JSON file with scope configuration")
    ap.add_argument("--output", help="Output JSON file (default: quality_check_<input_file>)")
    
    args = ap.parse_args()
    
    # Load report
    with open(args.report_file, "r", encoding="utf-8") as fh:
        report_data = json.load(fh)
    
    # Load scope if provided
    scope = None
    if args.scope_file and os.path.exists(args.scope_file):
        with open(args.scope_file, "r", encoding="utf-8") as fh:
            scope = json.load(fh)
    
    # Handle both single report and list of reports
    if isinstance(report_data, list):
        results = []
        for report in report_data:
            result = score_report_quality(report, scope)
            results.append({
                "report": report.get("title", "Unknown"),
                "quality_check": result,
            })
        
        output_data = {
            "reports_checked": len(results),
            "results": results,
        }
    else:
        output_data = score_report_quality(report_data, scope)
    
    # Output file
    if args.output:
        out_path = args.output
    else:
        base = os.path.basename(args.report_file)
        name, ext = os.path.splitext(base)
        out_path = f"quality_check_{name}{ext}"
    
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(output_data, fh, indent=2)
    
    # Print summary
    if isinstance(report_data, list):
        avg_score = sum(r["quality_check"]["total_score"] for r in results) / len(results) if results else 0
        print(f"[QUALITY-CHECKER] Checked {len(results)} reports, average score: {avg_score:.1f}/100", file=sys.stderr)
    else:
        score = output_data["total_score"]
        rating = output_data["quality_rating"]
        print(f"[QUALITY-CHECKER] Report quality: {rating.upper()} ({score}/100)", file=sys.stderr)
        if output_data.get("recommendations"):
            print("[QUALITY-CHECKER] Recommendations:", file=sys.stderr)
            for rec in output_data["recommendations"]:
                print(f"  - {rec}", file=sys.stderr)
    
    print(out_path)


if __name__ == "__main__":
    main()

