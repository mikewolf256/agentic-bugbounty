#!/usr/bin/env python3
"""
Evaluate deduplication logic and final report quality.
"""

import json
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "output_zap"
REPORT_FILE = OUTPUT_DIR / "full_scan_dedup_report.json"


def evaluate_deduplication():
    """Evaluate deduplication effectiveness."""
    with open(REPORT_FILE) as f:
        report = json.load(f)
    
    print("=" * 60)
    print("DEDUPLICATION EVALUATION")
    print("=" * 60)
    
    original = report["summary"]["original_findings"]
    deduped = report["summary"]["deduplicated_findings"]
    removed = report["summary"]["duplicates_removed"]
    
    print(f"\n📊 Effectiveness:")
    print(f"   Original findings: {original}")
    print(f"   After deduplication: {deduped}")
    print(f"   Duplicates removed: {removed}")
    print(f"   Deduplication rate: {report['summary']['deduplication_rate']}")
    
    # Check if deduplication was too aggressive or too conservative
    if removed == 0:
        print("\n   ⚠️  No duplicates found - may be too conservative")
    elif removed / original > 0.5:
        print("\n   ⚠️  High deduplication rate - may be too aggressive")
    else:
        print("\n   ✅ Deduplication rate looks reasonable")
    
    # Analyze what was deduplicated
    findings = report["deduplicated_findings"]
    by_type_url = {}
    for f in findings:
        key = (f.get("vulnerability_type"), f.get("url"))
        by_type_url[key] = by_type_url.get(key, 0) + 1
    
    duplicates_found = {k: v for k, v in by_type_url.items() if v > 1}
    if duplicates_found:
        print(f"\n   ⚠️  Found {len(duplicates_found)} duplicate patterns still present")
    else:
        print("\n   ✅ No duplicate patterns found in deduplicated results")


def evaluate_report_quality():
    """Evaluate final report quality."""
    with open(REPORT_FILE) as f:
        report = json.load(f)
    
    print("\n" + "=" * 60)
    print("REPORT QUALITY EVALUATION")
    print("=" * 60)
    
    # Check required fields
    required_fields = ["summary", "scanner_performance", "deduplicated_findings"]
    missing = [f for f in required_fields if f not in report]
    
    if missing:
        print(f"\n   ❌ Missing required fields: {missing}")
    else:
        print("\n   ✅ All required fields present")
    
    # Check scanner coverage
    scanners = report["scanner_performance"]
    print(f"\n📊 Scanner Coverage:")
    for scanner, count in sorted(scanners.items(), key=lambda x: -x[1]):
        print(f"   {scanner}: {count} findings")
    
    # Check vulnerability distribution
    vuln_dist = report["vulnerability_distribution"]
    print(f"\n📊 Vulnerability Distribution:")
    for vuln_type, count in sorted(vuln_dist.items(), key=lambda x: -x[1])[:10]:
        print(f"   {vuln_type}: {count}")
    
    # Check correlation graph
    if report.get("correlation_graph"):
        chains = report["correlation_graph"].get("chains_detected", [])
        print(f"\n   ✅ Correlation graph present: {len(chains)} chains detected")
    else:
        print("\n   ⚠️  No correlation graph generated")
    
    # Evaluate findings quality
    findings = report["deduplicated_findings"]
    findings_with_url = sum(1 for f in findings if f.get("url"))
    findings_with_evidence = sum(1 for f in findings if f.get("evidence"))
    
    print(f"\n📊 Findings Quality:")
    print(f"   Findings with URL: {findings_with_url}/{len(findings)} ({findings_with_url/len(findings)*100:.1f}%)")
    print(f"   Findings with evidence: {findings_with_evidence}/{len(findings)} ({findings_with_evidence/len(findings)*100:.1f}%)")
    
    if findings_with_url / len(findings) < 0.8:
        print("   ⚠️  Low URL coverage - many findings missing URLs")
    if findings_with_evidence / len(findings) < 0.8:
        print("   ⚠️  Low evidence coverage - many findings missing evidence")


def compare_tool_vs_manual():
    """Compare tool detection vs manual detection."""
    with open(REPORT_FILE) as f:
        report = json.load(f)
    
    print("\n" + "=" * 60)
    print("TOOL VS MANUAL DETECTION COMPARISON")
    print("=" * 60)
    
    tool_total = report["evaluation"]["tool_coverage"]["total_tool_findings"]
    manual_total = report["evaluation"]["tool_coverage"]["manual_findings"]
    
    print(f"\n📊 Detection Breakdown:")
    print(f"   Tool findings: {tool_total}")
    print(f"   Manual findings: {manual_total}")
    
    if manual_total == 0:
        print("\n   ⚠️  No manual findings in report - cannot compare")
        print("   Note: Manual findings should be collected from validation test")
    else:
        ratio = tool_total / manual_total if manual_total > 0 else 0
        print(f"   Tool/Manual ratio: {ratio:.2f}")
        
        if ratio > 2:
            print("   ⚠️  High tool/manual ratio - tools may be generating false positives")
        elif ratio < 0.5:
            print("   ⚠️  Low tool/manual ratio - tools may be missing vulnerabilities")
        else:
            print("   ✅ Tool/manual ratio looks balanced")


def main():
    """Main evaluation."""
    if not REPORT_FILE.exists():
        print(f"❌ Report file not found: {REPORT_FILE}")
        print("   Run test_full_scan_dedup_report.py first")
        return
    
    evaluate_deduplication()
    evaluate_report_quality()
    compare_tool_vs_manual()
    
    print("\n" + "=" * 60)
    print("✅ EVALUATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()


