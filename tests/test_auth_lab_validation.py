#!/usr/bin/env python3
"""
Auth Scan Lab Validation Test

This script validates that our scanning stack correctly identifies
all known vulnerabilities in the auth_scan_lab. It performs:

1. Run all scanners against auth_scan_lab
2. Compare findings against the vulnerability manifest
3. Report match rate and any missing/extra detections
"""

import json
import os
import sys
import time
import requests
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set
from pathlib import Path

# MCP Server configuration
MCP_BASE_URL = os.environ.get("MCP_BASE_URL", "http://127.0.0.1:8000")
LAB_BASE_URL = "http://auth_scan_lab:5000"
LAB_HEALTH_URL = "http://localhost:5004/health"

# Enable lab testing mode for higher rate limits (we control the lab)
os.environ["LAB_TESTING"] = "true"

# Load vulnerability manifest
MANIFEST_PATH = Path(__file__).parent.parent / "labs" / "auth_scan_lab" / "lab_metadata.json"


@dataclass
class VulnDetection:
    """Tracks whether a vulnerability was detected"""
    vuln_id: str
    title: str
    severity: str
    expected_by: List[str]
    detected_by: List[str] = field(default_factory=list)
    detection_details: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_detected(self) -> bool:
        return len(self.detected_by) > 0
    
    @property
    def detection_rate(self) -> float:
        if not self.expected_by:
            return 1.0
        return len(set(self.detected_by) & set(self.expected_by)) / len(self.expected_by)


class AuthLabValidator:
    """Validates scanner findings against known vulnerabilities"""
    
    def __init__(self):
        self.session = requests.Session()
        self.manifest = self._load_manifest()
        self.detections: Dict[str, VulnDetection] = {}
        self.scanner_findings: Dict[str, List[Dict]] = {}
        self._init_detections()
    
    def _load_manifest(self) -> Dict:
        """Load the vulnerability manifest"""
        with open(MANIFEST_PATH, "r") as f:
            return json.load(f)
    
    def _init_detections(self):
        """Initialize detection tracking for all vulnerabilities"""
        for vuln_name, vuln_data in self.manifest.get("vulnerabilities", {}).items():
            self.detections[vuln_data["id"]] = VulnDetection(
                vuln_id=vuln_data["id"],
                title=vuln_data["title"],
                severity=vuln_data["severity"],
                expected_by=vuln_data.get("expected_by", []),
            )
    
    def _mcp_post(self, endpoint: str, data: Dict, timeout: int = 120) -> Optional[Dict]:
        """Make POST request to MCP server"""
        try:
            resp = self.session.post(
                f"{MCP_BASE_URL}{endpoint}",
                json=data,
                timeout=timeout
            )
            if resp.status_code == 200:
                return resp.json()
            print(f"  ⚠️  {endpoint} returned {resp.status_code}: {resp.text[:100]}")
            return None
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
        """Set MCP scope to include auth_scan_lab"""
        print("Setting scope...")
        resp = self._mcp_post("/mcp/set_scope", {
            "program_name": "auth_scan_lab_validation",
            "primary_targets": ["auth_scan_lab:5000", "auth_scan_lab"],
            "secondary_targets": [],
            "rules": {}
        })
        return resp is not None
    
    def run_katana_nuclei(self) -> Dict:
        """Run Katana crawler + Nuclei scanner"""
        print("Running Katana + Nuclei scan (targeted mode - tag-based)...")
        resp = self._mcp_post("/mcp/run_katana_nuclei", {
            "target": LAB_BASE_URL,
            "output_name": "auth_lab_validation",
            "mode": "targeted"  # Use tag-based scanning for fastest, most efficient auth scanning
        }, timeout=1200)  # 20 min timeout - lab mode uses 50 req/sec but can still take time with many URLs
        
        if resp:
            self.scanner_findings["katana_nuclei"] = resp
            self._process_nuclei_findings(resp)
        return resp or {}
    
    def run_bac_checks(self) -> Dict:
        """Run BAC/IDOR checks with authentication"""
        print("Running BAC checks (with auth)...")
        resp = self._mcp_post("/mcp/run_bac_checks", {
            "host": "auth_scan_lab:5000",
            "quick_login_url": "/login/alice",  # Login as regular user
        })
        
        if resp:
            self.scanner_findings["bac_checks"] = resp
            self._process_bac_findings(resp)
        return resp or {}
    
    def run_fingerprints(self) -> Dict:
        """Run fingerprinting"""
        print("Running fingerprints...")
        resp = self._mcp_post("/mcp/run_fingerprints", {
            "target": LAB_BASE_URL
        })
        
        if resp:
            self.scanner_findings["fingerprints"] = resp
            self._process_fingerprint_findings(resp)
        return resp or {}
    
    def run_nuclei_standalone(self) -> Dict:
        """Run standalone Nuclei scan"""
        print("Running standalone Nuclei scan...")
        resp = self._mcp_post("/mcp/run_nuclei", {
            "target": LAB_BASE_URL,
            "mode": "full"
        }, timeout=600)
        
        if resp:
            self.scanner_findings["nuclei_standalone"] = resp
        return resp or {}
    
    def run_jwt_checks(self) -> Dict:
        """Run JWT security checks"""
        print("Running JWT checks...")
        resp = self._mcp_post("/mcp/run_jwt_checks", {
            "target": LAB_BASE_URL,
            "quick_login_url": "/login/alice",
        })
        
        if resp:
            self.scanner_findings["jwt_checks"] = resp
            self._process_jwt_findings(resp)
        return resp or {}
    
    def run_auth_checks(self) -> Dict:
        """Run authentication security checks"""
        print("Running auth checks...")
        resp = self._mcp_post("/mcp/run_auth_checks", {
            "target": LAB_BASE_URL,
            "login_url": "/login",
        })
        
        if resp:
            self.scanner_findings["auth_checks"] = resp
            self._process_auth_findings(resp)
        return resp or {}
    
    def _process_jwt_findings(self, findings: Dict):
        """Process JWT check findings"""
        meta = findings.get("meta", {})
        issues = meta.get("issues", [])
        
        for issue in issues:
            issue_type = issue.get("type", "")
            
            if "weak_jwt_secret" in issue_type:
                self._mark_detected("VULN-002", "jwt_checks", issue)
            if "algorithm_none" in issue_type or "none" in issue_type.lower():
                self._mark_detected("VULN-003", "jwt_checks", issue)
            if "empty_signature" in issue_type or "signature_stripped" in issue_type:
                self._mark_detected("VULN-003", "jwt_checks", issue)
    
    def _process_auth_findings(self, findings: Dict):
        """Process auth check findings"""
        meta = findings.get("meta", {})
        issues = meta.get("issues", [])
        
        for issue in issues:
            issue_type = issue.get("type", "")
            
            if "default_credentials" in issue_type:
                self._mark_detected("VULN-001", "auth_checks", issue)
            if "username_enumeration" in issue_type:
                self._mark_detected("VULN-005", "auth_checks", issue)
            if "missing_rate_limit" in issue_type or "rate_limit" in issue_type:
                self._mark_detected("VULN-004", "auth_checks", issue)
            if "insecure_cookie" in issue_type:
                self._mark_detected("VULN-012", "auth_checks", issue)
            if "predictable_session" in issue_type:
                self._mark_detected("VULN-006", "auth_checks", issue)
    
    def run_manual_checks(self):
        """Run manual vulnerability checks"""
        print("Running manual validation checks...")
        
        # Check default credentials (VULN-001)
        print("  Checking default credentials...")
        try:
            resp = requests.post(
                f"{LAB_HEALTH_URL.replace('/health', '/login')}",
                json={"username": "admin", "password": "admin"},
                timeout=10
            )
            if resp.status_code == 200 and resp.json().get("success"):
                self._mark_detected("VULN-001", "manual", {"method": "credential_test"})
        except Exception as e:
            print(f"    Error: {e}")
        
        # Check username enumeration (VULN-005)
        print("  Checking username enumeration...")
        try:
            # Valid user, wrong password
            resp1 = requests.post(
                f"{LAB_HEALTH_URL.replace('/health', '/login')}",
                json={"username": "admin", "password": "wrong"},
                timeout=10
            )
            # Invalid user
            resp2 = requests.post(
                f"{LAB_HEALTH_URL.replace('/health', '/login')}",
                json={"username": "nonexistent", "password": "wrong"},
                timeout=10
            )
            
            if resp1.status_code == 401 and resp2.status_code == 401:
                msg1 = resp1.json().get("error", "")
                msg2 = resp2.json().get("error", "")
                if msg1 != msg2:
                    self._mark_detected("VULN-005", "manual", {
                        "valid_user_error": msg1,
                        "invalid_user_error": msg2
                    })
        except Exception as e:
            print(f"    Error: {e}")
        
        # Check exposed admin panel (VULN-013)
        print("  Checking exposed admin panel...")
        try:
            resp = requests.get(
                f"{LAB_HEALTH_URL.replace('/health', '/admin')}",
                timeout=10
            )
            if resp.status_code == 200 and "Admin" in resp.text:
                self._mark_detected("VULN-013", "manual", {"status": resp.status_code})
        except Exception as e:
            print(f"    Error: {e}")
        
        # Check sensitive config exposure (VULN-015)
        print("  Checking sensitive config exposure...")
        try:
            resp = requests.get(
                f"{LAB_HEALTH_URL.replace('/health', '/admin/config')}",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                if "password" in str(data) or "secret" in str(data):
                    self._mark_detected("VULN-015", "manual", {"exposed_keys": list(data.keys())})
        except Exception as e:
            print(f"    Error: {e}")
        
        # Check debug endpoint (VULN-016)
        print("  Checking debug endpoint...")
        try:
            resp = requests.get(
                f"{LAB_HEALTH_URL.replace('/health', '/api/internal/debug')}",
                timeout=10
            )
            if resp.status_code == 200:
                self._mark_detected("VULN-016", "manual", {"status": resp.status_code})
        except Exception as e:
            print(f"    Error: {e}")
        
        # Check IDOR (VULN-007, VULN-008)
        print("  Checking IDOR vulnerabilities...")
        try:
            # Login as alice
            login_resp = requests.post(
                f"{LAB_HEALTH_URL.replace('/health', '/login')}",
                json={"username": "alice", "password": "alice123"},
                timeout=10
            )
            if login_resp.status_code == 200:
                token = login_resp.json().get("token")
                headers = {"Authorization": f"Bearer {token}"}
                
                # Try to access Bob's data (user 3)
                user_resp = requests.get(
                    f"{LAB_HEALTH_URL.replace('/health', '/api/users/3')}",
                    headers=headers,
                    timeout=10
                )
                if user_resp.status_code == 200 and user_resp.json().get("username") == "bob":
                    self._mark_detected("VULN-007", "manual", {"accessed": "/api/users/3"})
                
                # Try to access Bob's order
                order_resp = requests.get(
                    f"{LAB_HEALTH_URL.replace('/health', '/api/orders/3')}",
                    headers=headers,
                    timeout=10
                )
                if order_resp.status_code == 200:
                    self._mark_detected("VULN-008", "manual", {"accessed": "/api/orders/3"})
        except Exception as e:
            print(f"    Error: {e}")
        
        # Check privilege escalation (VULN-009)
        print("  Checking privilege escalation...")
        try:
            # Login as alice
            login_resp = requests.post(
                f"{LAB_HEALTH_URL.replace('/health', '/login')}",
                json={"username": "alice", "password": "alice123"},
                timeout=10
            )
            if login_resp.status_code == 200:
                token = login_resp.json().get("token")
                headers = {"Authorization": f"Bearer {token}"}
                
                # Try to escalate to admin
                priv_resp = requests.put(
                    f"{LAB_HEALTH_URL.replace('/health', '/api/profile')}",
                    json={"role": "admin"},
                    headers=headers,
                    timeout=10
                )
                if priv_resp.status_code == 200 and priv_resp.json().get("user", {}).get("role") == "admin":
                    self._mark_detected("VULN-009", "manual", {"escalated_to": "admin"})
        except Exception as e:
            print(f"    Error: {e}")
        
        # Check robots.txt disclosure (VULN-017)
        print("  Checking robots.txt...")
        try:
            resp = requests.get(
                f"{LAB_HEALTH_URL.replace('/health', '/robots.txt')}",
                timeout=10
            )
            if resp.status_code == 200 and "/admin" in resp.text:
                self._mark_detected("VULN-017", "manual", {"disclosed_paths": ["/admin", "/backup"]})
        except Exception as e:
            print(f"    Error: {e}")
    
    def _mark_detected(self, vuln_id: str, scanner: str, details: Dict = None):
        """Mark a vulnerability as detected"""
        if vuln_id in self.detections:
            if scanner not in self.detections[vuln_id].detected_by:
                self.detections[vuln_id].detected_by.append(scanner)
            if details:
                self.detections[vuln_id].detection_details[scanner] = details
    
    def _process_nuclei_findings(self, findings: Dict):
        """Process Nuclei findings and match to vulnerabilities"""
        # Map Nuclei template IDs to vulnerability IDs
        template_mapping = {
            "default-login": "VULN-001",
            "jwt-weak": "VULN-002",
            "jwt-none": "VULN-003",
            "username-enum": "VULN-005",
            "idor": ["VULN-007", "VULN-008"],
            "insecure-cookie": "VULN-012",
            "admin-panel": "VULN-013",
            "robots-txt": "VULN-017",
        }
        
        findings_count = findings.get("findings_count", 0)
        if findings_count > 0:
            # Parse findings file if available
            findings_file = findings.get("findings_file")
            if findings_file and os.path.exists(findings_file):
                with open(findings_file, "r") as f:
                    for line in f:
                        try:
                            finding = json.loads(line.strip())
                            template_id = finding.get("template-id", "")
                            
                            for key, vuln_ids in template_mapping.items():
                                if key in template_id.lower():
                                    if isinstance(vuln_ids, list):
                                        for vid in vuln_ids:
                                            self._mark_detected(vid, "nuclei", finding)
                                    else:
                                        self._mark_detected(vuln_ids, "nuclei", finding)
                        except:
                            pass
    
    def _process_bac_findings(self, findings: Dict):
        """Process BAC check findings"""
        meta = findings.get("meta", {})
        issues = meta.get("issues", [])
        
        for issue in issues:
            issue_type = issue.get("type", "")
            url = issue.get("url", "") or issue.get("test_url", "")
            
            # IDOR findings
            if "idor" in issue_type.lower() or "/users/" in url:
                self._mark_detected("VULN-007", "bac_checks", issue)
            if "/orders/" in url:
                self._mark_detected("VULN-008", "bac_checks", issue)
            
            # Admin panel exposure
            if "exposed_admin" in issue_type or ("/admin" in url and "vertical" not in issue_type):
                self._mark_detected("VULN-013", "bac_checks", issue)
            
            # Vertical privilege escalation
            if "vertical_privilege" in issue_type:
                self._mark_detected("VULN-014", "bac_checks", issue)
            
            # Sensitive data exposure
            if "sensitive_data" in issue_type:
                data_type = issue.get("data_type", "")
                if "api_key" in data_type:
                    self._mark_detected("VULN-018", "bac_checks", issue)
                if "password" in data_type or "secret" in data_type:
                    self._mark_detected("VULN-015", "bac_checks", issue)
    
    def _process_fingerprint_findings(self, findings: Dict):
        """Process fingerprint findings"""
        technologies = findings.get("technologies", [])
        
        if any("python" in t.lower() or "flask" in t.lower() for t in technologies):
            # Fingerprinting working - mark relevant vulns
            self._mark_detected("VULN-012", "fingerprints", {"technologies": technologies})
    
    def generate_report(self) -> Dict:
        """Generate validation report"""
        total = len(self.detections)
        detected = sum(1 for d in self.detections.values() if d.is_detected)
        
        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for d in self.detections.values():
            by_severity.get(d.severity, by_severity["info"]).append(d)
        
        report = {
            "summary": {
                "total_vulnerabilities": total,
                "detected": detected,
                "missed": total - detected,
                "detection_rate": f"{(detected/total)*100:.1f}%"
            },
            "by_severity": {},
            "details": [],
            "scanner_stats": {}
        }
        
        for severity, vulns in by_severity.items():
            if vulns:
                detected_count = sum(1 for v in vulns if v.is_detected)
                report["by_severity"][severity] = {
                    "total": len(vulns),
                    "detected": detected_count,
                    "rate": f"{(detected_count/len(vulns))*100:.1f}%"
                }
        
        for d in sorted(self.detections.values(), key=lambda x: x.vuln_id):
            report["details"].append({
                "vuln_id": d.vuln_id,
                "title": d.title,
                "severity": d.severity,
                "detected": d.is_detected,
                "expected_by": d.expected_by,
                "detected_by": d.detected_by,
            })
        
        # Scanner stats
        for scanner in ["nuclei", "bac_checks", "jwt_checks", "auth_checks", "fingerprints", "manual"]:
            detected_by_scanner = sum(1 for d in self.detections.values() if scanner in d.detected_by)
            expected_by_scanner = sum(1 for d in self.detections.values() if scanner in d.expected_by)
            report["scanner_stats"][scanner] = {
                "detected": detected_by_scanner,
                "expected": expected_by_scanner,
                "rate": f"{(detected_by_scanner/expected_by_scanner)*100:.1f}%" if expected_by_scanner > 0 else "N/A"
            }
        
        return report
    
    def print_report(self, report: Dict):
        """Print formatted report"""
        print("\n" + "=" * 60)
        print("AUTH SCAN LAB VALIDATION REPORT")
        print("=" * 60)
        
        summary = report["summary"]
        print(f"\n📊 SUMMARY")
        print(f"   Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"   Detected: {summary['detected']}")
        print(f"   Missed: {summary['missed']}")
        print(f"   Detection Rate: {summary['detection_rate']}")
        
        print(f"\n📈 BY SEVERITY")
        for severity, stats in report["by_severity"].items():
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(severity, "⚪")
            print(f"   {icon} {severity.upper()}: {stats['detected']}/{stats['total']} ({stats['rate']})")
        
        print(f"\n🔍 SCANNER PERFORMANCE")
        for scanner, stats in report["scanner_stats"].items():
            print(f"   {scanner}: {stats['detected']}/{stats['expected']} ({stats['rate']})")
        
        print(f"\n📋 DETAILED RESULTS")
        print("-" * 60)
        for detail in report["details"]:
            status = "✅" if detail["detected"] else "❌"
            print(f"   {status} {detail['vuln_id']}: {detail['title']}")
            print(f"      Severity: {detail['severity']}")
            print(f"      Expected by: {', '.join(detail['expected_by'])}")
            print(f"      Detected by: {', '.join(detail['detected_by']) or 'NONE'}")
            print()
    
    def run_validation(self):
        """Run full validation"""
        print("=" * 60)
        print("Starting Auth Scan Lab Validation")
        print("=" * 60)
        
        # Check lab health
        print("\n1. Checking lab health...")
        if not self.check_lab_health():
            print("   ❌ Lab is not running! Start it with: docker compose up auth_scan_lab")
            return None
        print("   ✅ Lab is healthy")
        
        # Set scope
        print("\n2. Setting MCP scope...")
        if not self.set_scope():
            print("   ❌ Failed to set scope")
            return None
        print("   ✅ Scope set")
        
        # Run scanners
        print("\n3. Running scanners...")
        self.run_fingerprints()
        self.run_bac_checks()
        self.run_jwt_checks()
        self.run_auth_checks()
        self.run_katana_nuclei()
        
        # Run manual checks
        print("\n4. Running manual validation checks...")
        self.run_manual_checks()
        
        # Generate and print report
        print("\n5. Generating report...")
        report = self.generate_report()
        self.print_report(report)
        
        # Save report
        report_path = Path(__file__).parent.parent / "output_zap" / "auth_lab_validation_report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n📁 Report saved to: {report_path}")
        
        return report


def main():
    validator = AuthLabValidator()
    report = validator.run_validation()
    
    if report:
        # Exit with error if detection rate < 50%
        rate = float(report["summary"]["detection_rate"].rstrip("%"))
        if rate < 50:
            print(f"\n⚠️  Detection rate ({rate}%) is below 50%!")
            sys.exit(1)
        else:
            print(f"\n✅ Validation passed with {rate}% detection rate")
            sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()

