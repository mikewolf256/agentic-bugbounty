#!/usr/bin/env python3
"""
Full scan test with deduplication and report evaluation.

This script:
1. Collects findings from all scanners
2. Tests deduplication logic
3. Generates and evaluates final report
4. Compares tool vs manual detection
"""

import json
import os
import sys
import requests
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

MCP_BASE_URL = os.environ.get("MCP_BASE_URL", "http://127.0.0.1:8000")
OUTPUT_DIR = Path(__file__).parent.parent / "output_zap"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _mcp_post(endpoint: str, data: Dict, timeout: int = 300) -> Dict:
    """Make POST request to MCP server."""
    url = f"{MCP_BASE_URL}{endpoint}"
    try:
        resp = requests.post(url, json=data, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"  ❌ Error calling {endpoint}: {e}")
        return {}


def collect_all_findings() -> List[Dict[str, Any]]:
    """Collect findings from all scanner output files."""
    findings = []
    
    print("=" * 60)
    print("COLLECTING FINDINGS FROM ALL SCANNERS")
    print("=" * 60)
    
    # Find latest files for each scanner type
    scanner_patterns = {
        "bac_checks": "bac_checks_*.json",
        "jwt_checks": "jwt_checks_*.json",
        "auth_checks": "auth_checks_*.json",
        "fingerprints": "fingerprints_*.json",
        "nuclei": "*_findings.json",
    }
    
    latest_files = {}
    for scanner, pattern in scanner_patterns.items():
        files = list(OUTPUT_DIR.glob(pattern))
        if files:
            # Get most recent
            latest = max(files, key=lambda f: f.stat().st_mtime)
            latest_files[scanner] = latest
            print(f"  📁 {scanner}: {latest.name}")
    
    # Also load validation report for manual findings
    validation_report = OUTPUT_DIR / "auth_lab_validation_report.json"
    if validation_report.exists():
        latest_files["validation_report"] = validation_report
        print(f"  📁 validation_report: {validation_report.name}")
    
    # Load and format findings
    for scanner, filepath in latest_files.items():
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            
            # Extract findings based on scanner type
            if scanner == "bac_checks":
                issues = data.get("confirmed_issues", [])
                for issue in issues:
                    findings.append({
                        "scanner": "bac_checks",
                        "vulnerability_type": issue.get("type", "unknown"),
                        "url": issue.get("url") or issue.get("test_url", ""),
                        "confidence": issue.get("confidence", "medium"),
                        "note": issue.get("note", ""),
                        "evidence": issue,
                        "source_file": str(filepath),
                    })
            
            elif scanner == "jwt_checks":
                # Try both formats: meta.issues or confirmed_issues
                issues = data.get("meta", {}).get("issues", []) or data.get("confirmed_issues", [])
                for issue in issues:
                    findings.append({
                        "scanner": "jwt_checks",
                        "vulnerability_type": issue.get("type", "unknown"),
                        "url": issue.get("test_url") or data.get("target", ""),
                        "confidence": issue.get("confidence", "medium"),
                        "note": issue.get("note", ""),
                        "evidence": issue,
                        "source_file": str(filepath),
                    })
            
            elif scanner == "auth_checks":
                # Try both formats: meta.issues or confirmed_issues
                issues = data.get("meta", {}).get("issues", []) or data.get("confirmed_issues", [])
                for issue in issues:
                    findings.append({
                        "scanner": "auth_checks",
                        "vulnerability_type": issue.get("type", "unknown"),
                        "url": issue.get("endpoint") or issue.get("url") or data.get("target", ""),
                        "confidence": issue.get("confidence", "medium"),
                        "note": issue.get("note", ""),
                        "evidence": issue,
                        "source_file": str(filepath),
                    })
            
            elif scanner == "fingerprints":
                # Fingerprints are usually metadata, not vulnerabilities
                # But we can extract security headers issues
                tech = data.get("technologies", [])
                if tech:
                    findings.append({
                        "scanner": "fingerprints",
                        "vulnerability_type": "technology_fingerprint",
                        "url": data.get("target", ""),
                        "confidence": "info",
                        "note": f"Technologies detected: {', '.join(tech)}",
                        "evidence": {"technologies": tech},
                        "source_file": str(filepath),
                    })
            
            elif scanner == "nuclei":
                # Nuclei findings are already in the right format
                if isinstance(data, list):
                    for finding in data:
                        finding["scanner"] = "nuclei"
                        finding["source_file"] = str(filepath)
                        findings.append(finding)
                elif isinstance(data, dict) and "nuclei_findings" in data:
                    for finding in data["nuclei_findings"]:
                        finding["scanner"] = "nuclei"
                        finding["source_file"] = str(filepath)
                        findings.append(finding)
            
            elif scanner == "validation_report":
                # Extract manual findings from validation report
                details = data.get("details", [])
                for detail in details:
                    if detail.get("detected") and "manual" in detail.get("detected_by", []):
                        findings.append({
                            "scanner": "manual",
                            "vulnerability_type": detail.get("vuln_id", "unknown"),
                            "url": "",  # Manual findings may not have URLs
                            "confidence": detail.get("severity", "medium"),
                            "note": detail.get("title", ""),
                            "evidence": detail,
                            "source_file": str(filepath),
                        })
        
        except Exception as e:
            print(f"  ⚠️  Error loading {scanner}: {e}")
    
    print(f"\n  ✅ Collected {len(findings)} total findings")
    return findings


def test_deduplication(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Test the deduplication endpoint."""
    print("\n" + "=" * 60)
    print("TESTING DEDUPLICATION")
    print("=" * 60)
    
    print(f"  Input: {len(findings)} findings")
    
    result = _mcp_post("/mcp/deduplicate_findings", {
        "findings": findings,
        "use_semantic": True,
    }, timeout=600)
    
    if result:
        original = result.get("original_count", len(findings))
        deduped = result.get("deduplicated_count", 0)
        removed = result.get("duplicates_removed", 0)
        
        print(f"  ✅ Deduplication complete:")
        print(f"     Original: {original}")
        print(f"     Deduplicated: {deduped}")
        print(f"     Removed: {removed} duplicates")
        
        if result.get("correlation_graph"):
            chains = result.get("correlation_graph", {}).get("chains_detected", [])
            print(f"     Vulnerability chains: {len(chains)}")
        
        return result
    else:
        print("  ❌ Deduplication failed")
        return {}


def analyze_tool_vs_manual(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze tool detection vs manual detection."""
    print("\n" + "=" * 60)
    print("TOOL VS MANUAL DETECTION ANALYSIS")
    print("=" * 60)
    
    by_scanner = {}
    by_type = {}
    
    for finding in findings:
        scanner = finding.get("scanner", "unknown")
        vuln_type = finding.get("vulnerability_type", "unknown")
        
        by_scanner[scanner] = by_scanner.get(scanner, 0) + 1
        by_type[vuln_type] = by_type.get(vuln_type, 0) + 1
    
    print("\n  📊 Findings by Scanner:")
    for scanner, count in sorted(by_scanner.items(), key=lambda x: -x[1]):
        print(f"     {scanner}: {count}")
    
    print("\n  📊 Findings by Type:")
    for vuln_type, count in sorted(by_type.items(), key=lambda x: -x[1])[:10]:
        print(f"     {vuln_type}: {count}")
    
    return {
        "by_scanner": by_scanner,
        "by_type": by_type,
        "total_findings": len(findings),
    }


def generate_final_report(
    original_findings: List[Dict],
    dedup_result: Dict,
    analysis: Dict
) -> Dict[str, Any]:
    """Generate final comprehensive report."""
    print("\n" + "=" * 60)
    print("GENERATING FINAL REPORT")
    print("=" * 60)
    
    deduped_findings = dedup_result.get("deduplicated_findings", original_findings)
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "original_findings": len(original_findings),
            "deduplicated_findings": len(deduped_findings),
            "duplicates_removed": dedup_result.get("duplicates_removed", 0),
            "deduplication_rate": f"{(dedup_result.get('duplicates_removed', 0) / len(original_findings) * 100):.1f}%" if original_findings else "0%",
        },
        "scanner_performance": analysis.get("by_scanner", {}),
        "vulnerability_distribution": analysis.get("by_type", {}),
        "deduplicated_findings": deduped_findings,
        "correlation_graph": dedup_result.get("correlation_graph"),
        "evaluation": {
            "deduplication_effective": len(deduped_findings) < len(original_findings),
            "tool_coverage": {
                "total_tool_findings": sum(v for k, v in analysis.get("by_scanner", {}).items() if k != "manual"),
                "manual_findings": analysis.get("by_scanner", {}).get("manual", 0),
            },
        },
    }
    
    # Save report
    report_path = OUTPUT_DIR / "full_scan_dedup_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"  ✅ Report saved to: {report_path}")
    
    # Print summary
    print("\n  📋 Report Summary:")
    print(f"     Original findings: {report['summary']['original_findings']}")
    print(f"     After deduplication: {report['summary']['deduplicated_findings']}")
    print(f"     Duplicates removed: {report['summary']['duplicates_removed']}")
    print(f"     Deduplication rate: {report['summary']['deduplication_rate']}")
    
    tool_total = report['evaluation']['tool_coverage']['total_tool_findings']
    manual_total = report['evaluation']['tool_coverage']['manual_findings']
    print(f"\n     Tool findings: {tool_total}")
    print(f"     Manual findings: {manual_total}")
    print(f"     Tool/Manual ratio: {tool_total/manual_total:.2f}" if manual_total > 0 else "     Tool/Manual ratio: N/A")
    
    return report


def main():
    """Main execution."""
    print("=" * 60)
    print("FULL SCAN WITH DEDUPLICATION AND REPORT EVALUATION")
    print("=" * 60)
    
    # Step 1: Collect findings
    findings = collect_all_findings()
    
    if not findings:
        print("\n❌ No findings collected. Run scans first.")
        return
    
    # Step 2: Analyze tool vs manual
    analysis = analyze_tool_vs_manual(findings)
    
    # Step 3: Test deduplication
    dedup_result = test_deduplication(findings)
    
    # Step 4: Generate final report
    report = generate_final_report(findings, dedup_result, analysis)
    
    print("\n" + "=" * 60)
    print("✅ COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()

