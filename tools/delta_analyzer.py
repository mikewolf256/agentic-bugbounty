#!/usr/bin/env python3
"""Delta Analyzer for New Findings Detection

Compares current scan results with previous scans to detect new findings
and generate alerts for high-severity discoveries.
"""

import os
import json
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path


class DeltaAnalyzer:
    """Analyzes deltas between scan runs to detect new findings."""
    
    def __init__(self, output_dir: str = "output_zap", state_dir: str = "scan_state"):
        self.output_dir = Path(output_dir)
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(exist_ok=True)
    
    def load_previous_findings(self, program_name: str) -> List[Dict[str, Any]]:
        """Load previous findings for a program.
        
        Args:
            program_name: Program identifier
            
        Returns:
            List of previous findings
        """
        state_file = self.state_dir / f"{program_name}_findings.json"
        if not state_file.exists():
            return []
        
        try:
            with open(state_file, "r") as f:
                data = json.load(f)
                return data.get("findings", [])
        except Exception:
            return []
    
    def save_current_findings(self, program_name: str, findings: List[Dict[str, Any]]):
        """Save current findings for future delta comparison.
        
        Args:
            program_name: Program identifier
            findings: List of current findings
        """
        state_file = self.state_dir / f"{program_name}_findings.json"
        data = {
            "program_name": program_name,
            "timestamp": datetime.now().isoformat(),
            "findings": findings,
        }
        
        with open(state_file, "w") as f:
            json.dump(data, f, indent=2)
    
    def normalize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a finding for comparison.
        
        Args:
            finding: Finding dict
            
        Returns:
            Normalized finding with key fields for comparison
        """
        url = finding.get("url") or finding.get("uri") or ""
        title = finding.get("title") or finding.get("name") or ""
        cwe = finding.get("cwe") or ""
        cvss_score = finding.get("cvss_score") or 0.0
        
        # Create signature for comparison
        signature = f"{url}:{title}:{cwe}"
        
        return {
            "url": url,
            "title": title,
            "cwe": cwe,
            "cvss_score": cvss_score,
            "signature": signature,
            "finding": finding,  # Keep full finding for reference
        }
    
    def find_new_findings(
        self,
        current_findings: List[Dict[str, Any]],
        previous_findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Compare current and previous findings to detect new ones.
        
        Args:
            current_findings: Current scan findings
            previous_findings: Previous scan findings
            
        Returns:
            Dict with new findings, removed findings, and statistics
        """
        # Normalize findings
        current_normalized = [self.normalize_finding(f) for f in current_findings]
        previous_normalized = [self.normalize_finding(f) for f in previous_findings]
        
        # Create signature sets
        current_signatures = {f["signature"] for f in current_normalized}
        previous_signatures = {f["signature"] for f in previous_normalized}
        
        # Find new and removed
        new_signatures = current_signatures - previous_signatures
        removed_signatures = previous_signatures - current_signatures
        
        # Get full findings for new/removed
        new_findings = [
            f["finding"] for f in current_normalized
            if f["signature"] in new_signatures
        ]
        removed_findings = [
            f["finding"] for f in previous_normalized
            if f["signature"] in removed_signatures
        ]
        
        # Categorize new findings by severity
        high_severity = [f for f in new_findings if (f.get("cvss_score") or 0.0) >= 7.0]
        critical_severity = [f for f in new_findings if (f.get("cvss_score") or 0.0) >= 9.0]
        
        return {
            "new_findings": new_findings,
            "removed_findings": removed_findings,
            "new_count": len(new_findings),
            "removed_count": len(removed_findings),
            "high_severity_new": high_severity,
            "critical_severity_new": critical_severity,
            "high_severity_count": len(high_severity),
            "critical_severity_count": len(critical_severity),
            "unchanged_count": len(current_signatures & previous_signatures),
        }
    
    def analyze_delta(
        self,
        program_name: str,
        current_findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Analyze delta for a program's findings.
        
        Args:
            program_name: Program identifier
            current_findings: Current scan findings
            
        Returns:
            Delta analysis results
        """
        previous_findings = self.load_previous_findings(program_name)
        
        delta = self.find_new_findings(current_findings, previous_findings)
        
        # Save current findings for next comparison
        self.save_current_findings(program_name, current_findings)
        
        # Add metadata
        delta["program_name"] = program_name
        delta["analysis_timestamp"] = datetime.now().isoformat()
        delta["previous_scan_findings_count"] = len(previous_findings)
        delta["current_scan_findings_count"] = len(current_findings)
        
        return delta
    
    def generate_alerts(self, delta: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate alerts for significant findings.
        
        Args:
            delta: Delta analysis results
            
        Returns:
            List of alert dicts
        """
        alerts = []
        
        # Critical severity alert
        if delta.get("critical_severity_count", 0) > 0:
            critical_findings = delta.get("critical_severity_new", [])
            for finding in critical_findings:
                alerts.append({
                    "level": "critical",
                    "type": "new_critical_finding",
                    "message": f"New critical finding detected: {finding.get('title', 'Unknown')}",
                    "finding": finding,
                    "timestamp": datetime.now().isoformat(),
                })
        
        # High severity alert
        if delta.get("high_severity_count", 0) > 0:
            alerts.append({
                "level": "high",
                "type": "new_high_severity_finding",
                "message": f"New high-severity finding(s) detected: {delta['high_severity_count']}",
                "findings": delta.get("high_severity_new", []),
                "timestamp": datetime.now().isoformat(),
            })
        
        # Significant new findings alert
        if delta.get("new_count", 0) >= 10:
            alerts.append({
                "level": "info",
                "type": "significant_new_findings",
                "message": f"Significant number of new findings: {delta['new_count']}",
                "findings_count": delta["new_count"],
                "timestamp": datetime.now().isoformat(),
            })
        
        # Send alerts via alerting system
        try:
            from tools.alerting import get_alert_manager
            manager = get_alert_manager()
            program_name = delta.get("program_name")
            
            for alert in alerts:
                details = {
                    "type": alert["type"],
                    "timestamp": alert["timestamp"],
                }
                if "finding" in alert:
                    details["finding"] = alert["finding"]
                elif "findings" in alert:
                    details["findings_count"] = len(alert.get("findings", []))
                
                manager.send_alert(
                    alert["level"],
                    alert["message"],
                    program_name,
                    details,
                )
        except Exception as e:
            # Non-fatal if alerting fails
            print(f"[DELTA] Alert sending failed: {e}", file=sys.stderr)
        
        return alerts
    
    def save_delta_report(self, program_name: str, delta: Dict[str, Any], alerts: List[Dict[str, Any]]):
        """Save delta analysis report.
        
        Args:
            program_name: Program identifier
            delta: Delta analysis results
            alerts: Generated alerts
        """
        report = {
            "program_name": program_name,
            "delta": delta,
            "alerts": alerts,
            "report_timestamp": datetime.now().isoformat(),
        }
        
        timestamp = int(time.time())
        report_file = self.state_dir / f"{program_name}_delta_{timestamp}.json"
        
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        return report_file


def analyze_scan_delta(
    program_name: str,
    findings: List[Dict[str, Any]],
    output_dir: str = "output_zap",
) -> Dict[str, Any]:
    """Convenience function to analyze delta for a scan.
    
    Args:
        program_name: Program identifier
        findings: Current scan findings
        output_dir: Output directory
        
    Returns:
        Delta analysis with alerts
    """
    analyzer = DeltaAnalyzer(output_dir=output_dir)
    delta = analyzer.analyze_delta(program_name, findings)
    alerts = analyzer.generate_alerts(delta)
    report_file = analyzer.save_delta_report(program_name, delta, alerts)
    
    return {
        "delta": delta,
        "alerts": alerts,
        "report_file": str(report_file),
    }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Delta Analyzer for New Findings")
    parser.add_argument("--program", required=True, help="Program name")
    parser.add_argument("--findings-file", required=True, help="JSON file with current findings")
    parser.add_argument("--output-dir", default="output_zap", help="Output directory")
    
    args = parser.parse_args()
    
    # Load findings
    with open(args.findings_file, "r") as f:
        findings = json.load(f)
    
    if not isinstance(findings, list):
        findings = [findings]
    
    # Analyze delta
    result = analyze_scan_delta(args.program, findings, args.output_dir)
    
    # Print summary
    delta = result["delta"]
    alerts = result["alerts"]
    
    print(f"\nDelta Analysis for {args.program}:")
    print(f"  New findings: {delta['new_count']}")
    print(f"  Removed findings: {delta['removed_count']}")
    print(f"  High severity new: {delta['high_severity_count']}")
    print(f"  Critical severity new: {delta['critical_severity_count']}")
    
    if alerts:
        print(f"\nAlerts ({len(alerts)}):")
        for alert in alerts:
            print(f"  [{alert['level'].upper()}] {alert['message']}")
    
    print(f"\nReport saved to: {result['report_file']}")

