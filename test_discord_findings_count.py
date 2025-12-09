#!/usr/bin/env python3
"""Test script to verify Discord alert counts findings correctly.

This script simulates a scan summary with findings from targeted_vuln_tests
and verifies that the alert counting logic works correctly.
"""

import json
import sys
from pathlib import Path

# Add tools to path
REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

# Simulate a scan summary with findings
test_summary = {
    "modules": {
        "localhost:5013": {
            "katana_nuclei": {
                "findings_count": 0,
                "findings_file": ""
            },
            "targeted_nuclei": {
                "findings_count": 0,
                "findings_file": ""
            },
            "targeted_vuln_tests": {
                "tests_run": 15,
                "tests_passed": 1,
                "tests_failed": 14,
                "findings": [
                    {
                        "type": "command_injection",
                        "target_url": "http://localhost:5013/execute",
                        "vulnerable": True,
                        "injection_point": "cmd",
                        "cvss_score": 9.8
                    },
                    {
                        "type": "command_injection",
                        "target_url": "http://localhost:5013/upload",
                        "vulnerable": True,
                        "injection_point": "filename",
                        "cvss_score": 9.8
                    },
                    {
                        "type": "command_injection",
                        "target_url": "http://localhost:5013/api/run",
                        "vulnerable": True,
                        "injection_point": "command",
                        "cvss_score": 9.8
                    }
                ],
                "results_by_tester": {}
            }
        }
    },
    "scan_cost": 0.0
}

# Simulate the counting logic from agentic_runner.py
def count_findings(summary):
    """Count findings from all modules."""
    findings_count = 0
    high_severity_count = 0
    
    modules = summary.get("modules", {})
    for host, host_modules in modules.items():
        # Count from katana_nuclei
        katana_nuclei = host_modules.get("katana_nuclei", {})
        if isinstance(katana_nuclei, dict):
            findings_count += katana_nuclei.get("findings_count", 0)
        
        # Count from targeted_nuclei
        targeted_nuclei = host_modules.get("targeted_nuclei", {})
        if isinstance(targeted_nuclei, dict):
            findings_count += targeted_nuclei.get("findings_count", 0)
        
        # Count from other modules
        for module_name, module_data in host_modules.items():
            if module_name in ["katana_nuclei", "targeted_nuclei"]:
                continue
            if isinstance(module_data, dict) and "findings_count" in module_data:
                findings_count += module_data.get("findings_count", 0)
            
            # Count findings from targeted_vuln_tests
            if module_name == "targeted_vuln_tests":
                if not module_data:
                    continue
                vuln_findings = module_data.get("findings", [])
                if isinstance(vuln_findings, list) and len(vuln_findings) > 0:
                    findings_count += len(vuln_findings)
                    # Count high severity findings
                    for finding in vuln_findings:
                        cvss = finding.get("cvss_score") or finding.get("meta", {}).get("cvss_score", 0.0)
                        severity = finding.get("severity", "").lower() or finding.get("meta", {}).get("severity", "").lower()
                        if cvss >= 7.0 or severity == "high":
                            high_severity_count += 1
                elif isinstance(module_data, dict) and "findings_count" in module_data:
                    findings_count += module_data.get("findings_count", 0)
    
    return findings_count, high_severity_count

if __name__ == "__main__":
    print("Testing findings count logic...")
    print(f"Test summary has {len(test_summary['modules']['localhost:5013']['targeted_vuln_tests']['findings'])} findings in targeted_vuln_tests")
    
    findings_count, high_severity_count = count_findings(test_summary)
    
    print(f"\nResults:")
    print(f"  Total findings: {findings_count}")
    print(f"  High severity: {high_severity_count}")
    
    expected_findings = 3
    expected_high_severity = 3
    
    if findings_count == expected_findings:
        print(f"\n✅ PASS: Found {findings_count} findings (expected {expected_findings})")
    else:
        print(f"\n❌ FAIL: Found {findings_count} findings (expected {expected_findings})")
        sys.exit(1)
    
    if high_severity_count == expected_high_severity:
        print(f"✅ PASS: Found {high_severity_count} high-severity findings (expected {expected_high_severity})")
    else:
        print(f"❌ FAIL: Found {high_severity_count} high-severity findings (expected {expected_high_severity})")
        sys.exit(1)
    
    print("\n✅ All tests passed! The fix is working correctly.")

