#!/usr/bin/env python3
"""
Full Scan Test with Deduplication and Report Evaluation

This script:
1. Runs all scanners against auth_scan_lab
2. Collects findings from all sources (tools + manual)
3. Tests deduplication logic
4. Compares tool detection vs manual detection
5. Generates comprehensive evaluation report
"""

import json
import os
import sys
import time
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict

# MCP Server configuration
MCP_BASE_URL = os.environ.get("MCP_BASE_URL", "http://127.0.0.1:8000")
LAB_BASE_URL = "http://auth_scan_lab:5000"
LAB_HEALTH_URL = "http://localhost:5004/health"

# Enable lab testing mode
os.environ["LAB_TESTING"] = "true"

# Load vulnerability manifest
MANIFEST_PATH = Path(__file__).parent.parent / "labs" / "auth_scan_lab" / "lab_metadata.json"


class FullScanTester:
    def __init__(self):
        self.session = requests.Session()
        self.all_findings = []  # Raw findings from all sources
        self.tool_findings = []  # Findings from automated tools
        self.manual_findings = []  # Findings from manual checks
        self.scanner_results = {}
        
    def _mcp_post(self, endpoint: str, data: Dict, timeout: int = 300) -> Optional[Dict]:
        """Make POST request to MCP server"""
        url = f"{MCP_BASE_URL}{endpoint}"
        try:
            resp = self.session.post(url, json=data, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            print(f"  ❌ Error calling {endpoint}: {e}")
            return None
    
    def check_lab_health(self) -> bool:
        """Check if lab is running"""
        try:
            resp = requests.get(LAB_HEALTH_URL, timeout=5)
            return resp.status_code == 200
        except:
            return False
    
    def set_scope(self):
        """Set MCP scope"""
        return self._mcp_post("/mcp/set_scope", {
            "program_name": "auth_scan_lab_full_test",
            "primary_targets": ["auth_scan_lab:5000", "auth_scan_lab"],
            "secondary_targets": [],
            "rules": {}
        })
    
    def run_all_scanners(self):
        """Run all automated scanners"""
        print("\n" + "="*60)
        print("RUNNING AUTOMATED SCANNERS")
        print("="*60)
        
        scanners = [
            ("Fingerprints", self._run_fingerprints),
            ("BAC Checks", self._run_bac_checks),
            ("JWT Checks", self._run_jwt_checks),
            ("Auth Checks", self._run_auth_checks),
            ("Katana + Nuclei", self._run_katana_nuclei),
        ]
        
        for name, func in scanners:
            print(f"\n[{name}] Starting...")
            result = func()
            if result:
                self.scanner_results[name.lower().replace(" ", "_")] = result
                findings = self._extract_findings(result, name)
                self.tool_findings.extend(findings)
                self.all_findings.extend(findings)
                print(f"[{name}] ✅ Complete - {len(findings)} findings")
            else:
                print(f"[{name}] ❌ Failed")
    
    def _run_fingerprints(self) -> Optional[Dict]:
        return self._mcp_post("/mcp/run_fingerprints", {"target": LAB_BASE_URL})
    
    def _run_bac_checks(self) -> Optional[Dict]:
        return self._mcp_post("/mcp/run_bac_checks", {
            "host": "auth_scan_lab:5000",
            "quick_login_url": "/login/alice",
        })
    
    def _run_jwt_checks(self) -> Optional[Dict]:
        return self._mcp_post("/mcp/run_jwt_checks", {
            "target": LAB_BASE_URL,
            "quick_login_url": "/login/alice",
        })
    
    def _run_auth_checks(self) -> Optional[Dict]:
        return self._mcp_post("/mcp/run_auth_checks", {
            "target": LAB_BASE_URL,
            "login_url": "/login",
        })
    
    def _run_katana_nuclei(self) -> Optional[Dict]:
        return self._mcp_post("/mcp/run_katana_nuclei", {
            "target": LAB_BASE_URL,
            "output_name": "full_scan_test",
            "mode": "targeted"
        }, timeout=1200)
    
    def _extract_findings(self, result: Dict, scanner_name: str) -> List[Dict]:
        """Extract findings from scanner result"""
        findings = []
        
        if not result:
            return findings
        
        # Handle different result structures
        meta = result.get("meta", {})
        issues = meta.get("issues", [])
        
        # Also check for findings_file
        findings_file = meta.get("findings_file") or result.get("findings_file")
        if findings_file and os.path.exists(findings_file):
            try:
                with open(findings_file, "r") as f:
                    file_data = json.load(f)
                    if isinstance(file_data, list):
                        issues.extend(file_data)
                    elif isinstance(file_data, dict):
                        issues.extend(file_data.get("issues", []))
                        issues.extend(file_data.get("confirmed_issues", []))
                        issues.extend(file_data.get("nuclei_findings", []))
            except:
                pass
        
        # Convert issues to standardized format
        for issue in issues:
            finding = {
                "scanner": scanner_name,
                "type": issue.get("type", "unknown"),
                "url": issue.get("url") or issue.get("test_url") or issue.get("matched-at", ""),
                "severity": issue.get("severity") or issue.get("confidence", "medium"),
                "description": issue.get("note") or issue.get("info", {}).get("description", ""),
                "raw": issue,
            }
            findings.append(finding)
        
        return findings
    
    def run_manual_checks(self):
        """Run manual validation checks"""
        print("\n" + "="*60)
        print("RUNNING MANUAL CHECKS")
        print("="*60)
        
        manual_tests = [
            ("Default Credentials", self._check_default_creds),
            ("Username Enumeration", self._check_username_enum),
            ("Exposed Admin", self._check_exposed_admin),
            ("Sensitive Config", self._check_sensitive_config),
            ("Debug Endpoint", self._check_debug_endpoint),
            ("IDOR Users", self._check_idor_users),
            ("IDOR Orders", self._check_idor_orders),
            ("Privilege Escalation", self._check_priv_esc),
            ("Robots.txt", self._check_robots),
        ]
        
        for name, func in manual_tests:
            print(f"  Checking {name}...")
            findings = func()
            if findings:
                self.manual_findings.extend(findings)
                self.all_findings.extend(findings)
                print(f"    ✅ Found {len(findings)} issue(s)")
            else:
                print(f"    ❌ Not found")
    
    def _check_default_creds(self) -> List[Dict]:
        findings = []
        try:
            resp = requests.post(
                f"{LAB_HEALTH_URL.replace('/health', '/login')}",
                json={"username": "admin", "password": "admin"},
                timeout=10
            )
            if resp.status_code == 200 and resp.json().get("success"):
                findings.append({
                    "scanner": "manual",
                    "type": "default_credentials",
                    "url": "/login",
                    "severity": "critical",
                    "description": "Default credentials work: admin/admin",
                })
        except:
            pass
        return findings
    
    def _check_username_enum(self) -> List[Dict]:
        findings = []
        try:
            resp_valid = requests.post(
                f"{LAB_HEALTH_URL.replace('/health', '/login')}",
                json={"username": "admin", "password": "wrong"},
                timeout=10
            )
            resp_invalid = requests.post(
                f"{LAB_HEALTH_URL.replace('/health', '/login')}",
                json={"username": "nonexistent", "password": "wrong"},
                timeout=10
            )
            if resp_valid.status_code == 401 and resp_invalid.status_code == 401:
                msg_valid = resp_valid.json().get("error", "")
                msg_invalid = resp_invalid.json().get("error", "")
                if msg_valid != msg_invalid:
                    findings.append({
                        "scanner": "manual",
                        "type": "username_enumeration",
                        "url": "/login",
                        "severity": "low",
                        "description": "Different error messages reveal valid usernames",
                    })
        except:
            pass
        return findings
    
    def _check_exposed_admin(self) -> List[Dict]:
        findings = []
        try:
            resp = requests.get(f"{LAB_HEALTH_URL.replace('/health', '/admin')}", timeout=10)
            if resp.status_code == 200 and "admin" in resp.text.lower():
                findings.append({
                    "scanner": "manual",
                    "type": "exposed_admin",
                    "url": "/admin",
                    "severity": "medium",
                    "description": "Admin panel accessible without authentication",
                })
        except:
            pass
        return findings
    
    def _check_sensitive_config(self) -> List[Dict]:
        findings = []
        try:
            resp = requests.get(f"{LAB_HEALTH_URL.replace('/health', '/admin/config')}", timeout=10)
            if resp.status_code == 200:
                content = resp.text.lower()
                if any(kw in content for kw in ["secret", "password", "api_key"]):
                    findings.append({
                        "scanner": "manual",
                        "type": "sensitive_data_exposure",
                        "url": "/admin/config",
                        "severity": "high",
                        "description": "Sensitive configuration data exposed",
                    })
        except:
            pass
        return findings
    
    def _check_debug_endpoint(self) -> List[Dict]:
        findings = []
        try:
            resp = requests.get(f"{LAB_HEALTH_URL.replace('/health', '/api/internal/debug')}", timeout=10)
            if resp.status_code == 200:
                findings.append({
                    "scanner": "manual",
                    "type": "debug_endpoint",
                    "url": "/api/internal/debug",
                    "severity": "high",
                    "description": "Internal debug endpoint exposed",
                })
        except:
            pass
        return findings
    
    def _check_idor_users(self) -> List[Dict]:
        findings = []
        try:
            # Get token
            login_resp = requests.get(f"{LAB_HEALTH_URL.replace('/health', '/login/alice')}", timeout=10)
            if login_resp.status_code == 200:
                token = login_resp.json().get("token")
                # Try to access other user's data
                resp = requests.get(
                    f"{LAB_HEALTH_URL.replace('/health', '/api/users/3')}",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10
                )
                if resp.status_code == 200:
                    findings.append({
                        "scanner": "manual",
                        "type": "idor",
                        "url": "/api/users/3",
                        "severity": "high",
                        "description": "IDOR - can access other user's data",
                    })
        except:
            pass
        return findings
    
    def _check_idor_orders(self) -> List[Dict]:
        findings = []
        try:
            login_resp = requests.get(f"{LAB_HEALTH_URL.replace('/health', '/login/alice')}", timeout=10)
            if login_resp.status_code == 200:
                token = login_resp.json().get("token")
                resp = requests.get(
                    f"{LAB_HEALTH_URL.replace('/health', '/api/orders/3')}",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10
                )
                if resp.status_code == 200:
                    findings.append({
                        "scanner": "manual",
                        "type": "idor",
                        "url": "/api/orders/3",
                        "severity": "high",
                        "description": "IDOR - can access other user's orders",
                    })
        except:
            pass
        return findings
    
    def _check_priv_esc(self) -> List[Dict]:
        findings = []
        try:
            login_resp = requests.get(f"{LAB_HEALTH_URL.replace('/health', '/login/alice')}", timeout=10)
            if login_resp.status_code == 200:
                token = login_resp.json().get("token")
                resp = requests.put(
                    f"{LAB_HEALTH_URL.replace('/health', '/api/profile')}",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"role": "admin"},
                    timeout=10
                )
                if resp.status_code == 200:
                    findings.append({
                        "scanner": "manual",
                        "type": "privilege_escalation",
                        "url": "/api/profile",
                        "severity": "critical",
                        "description": "Privilege escalation via profile update",
                    })
        except:
            pass
        return findings
    
    def _check_robots(self) -> List[Dict]:
        findings = []
        try:
            resp = requests.get(f"{LAB_HEALTH_URL.replace('/health', '/robots.txt')}", timeout=10)
            if resp.status_code == 200 and "disallow" in resp.text.lower():
                findings.append({
                    "scanner": "manual",
                    "type": "robots_txt",
                    "url": "/robots.txt",
                    "severity": "info",
                    "description": "Sensitive paths in robots.txt",
                })
        except:
            pass
        return findings
    
    def _compare_tool_vs_manual(self) -> Dict[str, Any]:
        """Compare tool and manual findings to detect overlaps"""
        tool_only = []
        manual_only = []
        both = []
        
        # Normalize findings for comparison
        def normalize(finding):
            return {
                "type": finding.get("type", "").lower(),
                "url": finding.get("url", "").lower().replace("http://auth_scan_lab:5000", "").replace("http://localhost:5004", ""),
            }
        
        tool_normalized = [normalize(f) for f in self.tool_findings]
        manual_normalized = [normalize(f) for f in self.manual_findings]
        
        # Find overlaps
        for tool_f in self.tool_findings:
            tool_norm = normalize(tool_f)
            found_overlap = False
            
            for manual_f in self.manual_findings:
                manual_norm = normalize(manual_f)
                
                # Check if same type and similar URL
                type_match = tool_norm["type"] == manual_norm["type"]
                url_match = (
                    tool_norm["url"] == manual_norm["url"] or
                    tool_norm["url"] in manual_norm["url"] or
                    manual_norm["url"] in tool_norm["url"]
                )
                
                if type_match and url_match:
                    both.append({
                        "tool": tool_f,
                        "manual": manual_f,
                    })
                    found_overlap = True
                    break
            
            if not found_overlap:
                tool_only.append(tool_f)
        
        # Find manual-only
        for manual_f in self.manual_findings:
            manual_norm = normalize(manual_f)
            found_overlap = False
            
            for tool_f in self.tool_findings:
                tool_norm = normalize(tool_f)
                
                type_match = tool_norm["type"] == manual_norm["type"]
                url_match = (
                    tool_norm["url"] == manual_norm["url"] or
                    tool_norm["url"] in manual_norm["url"] or
                    manual_norm["url"] in tool_norm["url"]
                )
                
                if type_match and url_match:
                    found_overlap = True
                    break
            
            if not found_overlap:
                manual_only.append(manual_f)
        
        return {
            "tool_only": len(tool_only),
            "manual_only": len(manual_only),
            "both": len(both),
            "tool_only_examples": tool_only[:5],
            "manual_only_examples": manual_only[:5],
            "both_examples": both[:5],
        }
    
    def run_deduplication(self):
        """Test deduplication logic"""
        print("\n" + "="*60)
        print("RUNNING DEDUPLICATION")
        print("="*60)
        
        if not self.all_findings:
            print("  ⚠️  No findings to deduplicate")
            return None
        
        print(f"  Original findings count: {len(self.all_findings)}")
        
        result = self._mcp_post("/mcp/deduplicate_findings", {
            "findings": self.all_findings,
            "use_semantic": True,
        }, timeout=600)
        
        if result:
            original = result.get("original_count", len(self.all_findings))
            deduped = result.get("deduplicated_count", 0)
            removed = result.get("duplicates_removed", 0)
            
            print(f"  ✅ Deduplication complete")
            print(f"     Original: {original}")
            print(f"     Deduplicated: {deduped}")
            print(f"     Removed: {removed} duplicates")
            
            if result.get("correlation_graph"):
                print(f"     Correlation graph generated")
            
            return result
        else:
            print("  ❌ Deduplication failed")
            return None
    
    def generate_comparison_report(self, dedup_result: Optional[Dict] = None):
        """Generate comprehensive comparison report"""
        print("\n" + "="*60)
        print("GENERATING COMPREHENSIVE REPORT")
        print("="*60)
        
        # Load manifest
        with open(MANIFEST_PATH, "r") as f:
            manifest = json.load(f)
        
        # Analyze findings
        tool_count = len(self.tool_findings)
        manual_count = len(self.manual_findings)
        total_count = len(self.all_findings)
        
        # Group by scanner
        by_scanner = defaultdict(list)
        for finding in self.all_findings:
            scanner = finding.get("scanner", "unknown")
            by_scanner[scanner].append(finding)
        
        # Group by type
        by_type = defaultdict(list)
        for finding in self.all_findings:
            vuln_type = finding.get("type", "unknown")
            by_type[vuln_type].append(finding)
        
        # Compare with manifest
        manifest_vulns = manifest.get("vulnerabilities", {})
        detected_vulns = set()
        missed_vulns = []
        
        for vuln_id, vuln_data in manifest_vulns.items():
            # Check if detected
            detected = False
            for finding in self.all_findings:
                finding_type = finding.get("type", "").lower()
                vuln_type = vuln_data.get("type", "").lower()
                finding_url = finding.get("url", "").lower()
                
                # Improved matching logic
                # Match by type
                type_match = vuln_type in finding_type or finding_type in vuln_type
                # Match by URL pattern
                url_match = False
                if vuln_data.get("url"):
                    vuln_url = vuln_data.get("url", "").lower()
                    url_match = vuln_url in finding_url or finding_url in vuln_url
                
                if type_match or url_match:
                    detected = True
                    detected_vulns.add(vuln_id)
                    break
            
            if not detected:
                missed_vulns.append({
                    "id": vuln_id,
                    "title": vuln_data.get("title", ""),
                    "severity": vuln_data.get("severity", ""),
                })
        
        # Build report
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": LAB_BASE_URL,
            "summary": {
                "total_findings": total_count,
                "tool_findings": tool_count,
                "manual_findings": manual_count,
                "detection_rate": f"{(len(detected_vulns) / len(manifest_vulns) * 100):.1f}%" if manifest_vulns else "N/A",
                "detected_vulns": len(detected_vulns),
                "total_vulns": len(manifest_vulns),
                "missed_vulns": len(missed_vulns),
            },
            "scanner_performance": {
                name: len(findings) for name, findings in by_scanner.items()
            },
            "findings_by_type": {
                name: len(findings) for name, findings in by_type.items()
            },
            "deduplication": {
                "original_count": dedup_result.get("original_count") if dedup_result else total_count,
                "deduplicated_count": dedup_result.get("deduplicated_count") if dedup_result else total_count,
                "duplicates_removed": dedup_result.get("duplicates_removed", 0) if dedup_result else 0,
            } if dedup_result else None,
            "tool_vs_manual": self._compare_tool_vs_manual(),
            "missed_vulnerabilities": missed_vulns,
            "all_findings": self.all_findings[:50],  # Limit to first 50 for readability
        }
        
        # Save report
        report_path = Path(__file__).parent.parent / "output_zap" / "full_scan_report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print(f"\n📊 SUMMARY")
        print(f"   Total Findings: {total_count}")
        print(f"   Tool Findings: {tool_count}")
        print(f"   Manual Findings: {manual_count}")
        print(f"   Detection Rate: {report['summary']['detection_rate']}")
        print(f"   Detected: {len(detected_vulns)}/{len(manifest_vulns)}")
        
        print(f"\n🔍 SCANNER PERFORMANCE")
        for scanner, count in sorted(by_scanner.items(), key=lambda x: -len(x[1])):
            print(f"   {scanner}: {count} findings")
        
        print(f"\n📋 FINDINGS BY TYPE")
        for vuln_type, count in sorted(by_type.items(), key=lambda x: -len(x[1])):
            print(f"   {vuln_type}: {count}")
        
        if dedup_result:
            print(f"\n🔄 DEDUPLICATION")
            print(f"   Original: {dedup_result.get('original_count')}")
            print(f"   Deduplicated: {dedup_result.get('deduplicated_count')}")
            print(f"   Removed: {dedup_result.get('duplicates_removed')} duplicates")
        
        print(f"\n⚖️  TOOL VS MANUAL")
        print(f"   Tool Only: {report['tool_vs_manual']['tool_only']}")
        print(f"   Manual Only: {report['tool_vs_manual']['manual_only']}")
        print(f"   Both: {report['tool_vs_manual']['both']}")
        
        if missed_vulns:
            print(f"\n❌ MISSED VULNERABILITIES ({len(missed_vulns)})")
            for vuln in missed_vulns[:10]:
                print(f"   - {vuln['id']}: {vuln['title']} ({vuln['severity']})")
        
        print(f"\n📁 Full report saved to: {report_path}")
        
        return report
    
    def run(self):
        """Run full test suite"""
        print("="*60)
        print("FULL SCAN TEST WITH DEDUPLICATION")
        print("="*60)
        
        # Check lab
        if not self.check_lab_health():
            print("❌ Lab is not running!")
            return
        
        # Set scope
        if not self.set_scope():
            print("❌ Failed to set scope")
            return
        
        # Run scanners
        self.run_all_scanners()
        
        # Run manual checks
        self.run_manual_checks()
        
        # Run deduplication
        dedup_result = self.run_deduplication()
        
        # Generate report
        report = self.generate_comparison_report(dedup_result)
        
        print("\n✅ Full scan test complete!")


if __name__ == "__main__":
    tester = FullScanTester()
    tester.run()

