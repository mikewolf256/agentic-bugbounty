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
    
    # Use enhanced scope validator if available
    in_scope = True
    scope_reason = None
    
    try:
        from tools.scope_validator import is_url_in_scope
        in_scope, scope_reason = is_url_in_scope(url, scope)
    except ImportError:
        # Fallback to basic check
        if scope and scope.get("in_scope"):
            in_scope_entries = scope.get("in_scope", [])
            if in_scope_entries:
                in_scope = any(
                    entry.get("url", "") in url or entry.get("target", "") in url
                    for entry in in_scope_entries
                )
    
    return {
        "in_scope": in_scope,
        "url": url,
        "reason": scope_reason,
    }


def check_duplicate_findings(
    report_data: Dict[str, Any],
    historical_reports: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Check for duplicate findings.
    
    Args:
        report_data: Current report data
        historical_reports: Optional list of historical reports for comparison
    
    Returns:
        Dict with duplicate detection results
    """
    if not historical_reports:
        return {
            "is_duplicate": False,
            "similarity_score": 0.0,
            "similar_reports": [],
        }
    
    # Extract key fields for comparison
    current_title = (report_data.get("title") or "").lower()
    current_url = report_data.get("_raw_finding", {}).get("url") or ""
    current_cwe = str(report_data.get("cwe") or "")
    
    similar_reports = []
    max_similarity = 0.0
    
    for hist_report in historical_reports:
        hist_title = (hist_report.get("title") or "").lower()
        hist_url = hist_report.get("_raw_finding", {}).get("url") or ""
        hist_cwe = str(hist_report.get("cwe") or "")
        
        # Calculate similarity score
        similarity = 0.0
        
        # Title similarity (simple word overlap)
        if current_title and hist_title:
            current_words = set(current_title.split())
            hist_words = set(hist_title.split())
            if current_words and hist_words:
                overlap = len(current_words & hist_words) / len(current_words | hist_words)
                similarity += overlap * 0.4
        
        # URL similarity
        if current_url and hist_url:
            if current_url == hist_url:
                similarity += 0.4
            elif current_url in hist_url or hist_url in current_url:
                similarity += 0.2
        
        # CWE match
        if current_cwe and hist_cwe and current_cwe == hist_cwe:
            similarity += 0.2
        
        if similarity > 0.5:  # Threshold for potential duplicate
            similar_reports.append({
                "title": hist_report.get("title"),
                "url": hist_url,
                "similarity_score": similarity,
            })
            max_similarity = max(max_similarity, similarity)
    
    return {
        "is_duplicate": max_similarity >= 0.8,  # High threshold for duplicate
        "similarity_score": max_similarity,
        "similar_reports": similar_reports[:5],  # Top 5 similar
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


def score_report_quality(
    report_data: Dict[str, Any],
    scope: Optional[Dict[str, Any]] = None,
    historical_reports: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
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
    
    # Duplicate detection
    duplicate_check = check_duplicate_findings(report_data, historical_reports)
    
    # Deduct points for duplicates
    if duplicate_check["is_duplicate"]:
        score = max(0, score - 20)  # Penalty for duplicates
        quality_rating = "duplicate" if score < 40 else quality_rating
    
    return {
        "total_score": score,
        "max_score": max_score,
        "quality_rating": quality_rating,
        "breakdown": breakdown,
        "sensitive_data_check": sensitive_check,
        "duplicate_check": duplicate_check,
        "recommendations": _generate_recommendations(breakdown, sensitive_check, duplicate_check),
    }


def _generate_recommendations(
    breakdown: Dict[str, Any],
    sensitive_check: Dict[str, Any],
    duplicate_check: Optional[Dict[str, Any]] = None,
) -> List[str]:
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
    
    # Duplicate recommendations
    if duplicate_check and duplicate_check.get("is_duplicate"):
        recommendations.append(f"Potential duplicate - similarity score: {duplicate_check.get('similarity_score', 0):.2f}")
        similar = duplicate_check.get("similar_reports", [])
        if similar:
            recommendations.append(f"Similar to: {similar[0].get('title', 'unknown report')}")
    
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

