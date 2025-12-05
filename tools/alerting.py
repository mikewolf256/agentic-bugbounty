#!/usr/bin/env python3
"""Alerting System for Critical Findings and Scan Status

Supports multiple notification channels: Slack, Email, Teams.
Configurable per-program with alert throttling and aggregation.
"""

import os
import json
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path
import requests


class AlertManager:
    """Manages alerts across multiple notification channels."""
    
    def __init__(self, config_dir: str = "scopes", state_dir: str = "scan_state"):
        self.config_dir = Path(config_dir)
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(exist_ok=True)
        
        # Load alerting configuration
        self.slack_webhook = os.environ.get("SLACK_WEBHOOK_URL")
        self.email_smtp_host = os.environ.get("EMAIL_SMTP_HOST")
        self.email_smtp_port = int(os.environ.get("EMAIL_SMTP_PORT", "587"))
        self.email_from = os.environ.get("EMAIL_FROM")
        self.email_password = os.environ.get("EMAIL_PASSWORD")
        self.teams_webhook = os.environ.get("TEAMS_WEBHOOK_URL")
        
        # Alert throttling state
        self.alert_history: Dict[str, List[float]] = {}
        self.throttle_window = 3600  # 1 hour
    
    def load_program_alert_config(self, program_name: str) -> Dict[str, Any]:
        """Load program-specific alerting configuration.
        
        Args:
            program_name: Program identifier
            
        Returns:
            Alert config dict with channels and thresholds
        """
        config_file = self.config_dir / f"{program_name}_config.json"
        if not config_file.exists():
            return {}
        
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
                return config.get("alerting", {})
        except Exception:
            return {}
    
    def should_send_alert(
        self,
        alert_key: str,
        level: str,
        program_name: Optional[str] = None,
    ) -> bool:
        """Check if alert should be sent (throttling).
        
        Args:
            alert_key: Unique key for this alert type
            level: Alert level (critical, high, medium, info)
            program_name: Optional program name for per-program throttling
            
        Returns:
            True if alert should be sent
        """
        # Critical alerts always go through
        if level == "critical":
            return True
        
        # Check throttling
        full_key = f"{program_name}:{alert_key}" if program_name else alert_key
        now = time.time()
        
        if full_key not in self.alert_history:
            self.alert_history[full_key] = []
        
        # Remove old entries
        self.alert_history[full_key] = [
            t for t in self.alert_history[full_key]
            if now - t < self.throttle_window
        ]
        
        # Check if we've sent too many recently
        recent_count = len(self.alert_history[full_key])
        
        # Throttle limits per level
        limits = {
            "critical": 10,  # 10 per hour
            "high": 5,       # 5 per hour
            "medium": 2,     # 2 per hour
            "info": 1,       # 1 per hour
        }
        
        limit = limits.get(level, 1)
        if recent_count >= limit:
            return False
        
        # Record this alert
        self.alert_history[full_key].append(now)
        return True
    
    def send_slack_alert(
        self,
        message: str,
        level: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Send alert to Slack.
        
        Args:
            message: Alert message
            level: Alert level
            details: Optional additional details
            
        Returns:
            True if sent successfully
        """
        if not self.slack_webhook:
            return False
        
        # Color coding by level
        colors = {
            "critical": "#FF0000",  # Red
            "high": "#FF6B00",      # Orange
            "medium": "#FFA500",    # Orange-yellow
            "info": "#0066CC",      # Blue
        }
        
        color = colors.get(level, "#808080")
        
        # Build Slack message
        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"Alert: {level.upper()}",
                    "text": message,
                    "fields": [],
                    "footer": "Agentic Bug Bounty System",
                    "ts": int(time.time()),
                }
            ]
        }
        
        # Add details as fields
        if details:
            for key, value in details.items():
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, indent=2)
                payload["attachments"][0]["fields"].append({
                    "title": key.replace("_", " ").title(),
                    "value": str(value)[:1000],  # Limit length
                    "short": len(str(value)) < 50,
                })
        
        try:
            response = requests.post(
                self.slack_webhook,
                json=payload,
                timeout=10,
            )
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"[ALERT] Slack alert failed: {e}", file=sys.stderr)
            return False
    
    def send_email_alert(
        self,
        subject: str,
        message: str,
        recipients: List[str],
        level: str,
    ) -> bool:
        """Send alert via email.
        
        Args:
            subject: Email subject
            message: Email body
            recipients: List of email addresses
            level: Alert level
            
        Returns:
            True if sent successfully
        """
        if not all([self.email_smtp_host, self.email_from, self.email_password]):
            return False
        
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            msg = MIMEMultipart()
            msg["From"] = self.email_from
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = f"[{level.upper()}] {subject}"
            
            msg.attach(MIMEText(message, "plain"))
            
            with smtplib.SMTP(self.email_smtp_host, self.email_smtp_port) as server:
                server.starttls()
                server.login(self.email_from, self.email_password)
                server.send_message(msg)
            
            return True
        except Exception as e:
            print(f"[ALERT] Email alert failed: {e}", file=sys.stderr)
            return False
    
    def send_teams_alert(
        self,
        title: str,
        message: str,
        level: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Send alert to Microsoft Teams.
        
        Args:
            title: Alert title
            message: Alert message
            level: Alert level
            details: Optional additional details
            
        Returns:
            True if sent successfully
        """
        if not self.teams_webhook:
            return False
        
        # Build Teams message card
        facts = []
        if details:
            for key, value in details.items():
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, indent=2)
                facts.append({
                    "name": key.replace("_", " ").title(),
                    "value": str(value)[:500],
                })
        
        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": title,
            "themeColor": "0078D4" if level != "critical" else "FF0000",
            "title": title,
            "sections": [
                {
                    "activityTitle": f"Alert Level: {level.upper()}",
                    "text": message,
                    "facts": facts,
                }
            ],
        }
        
        try:
            response = requests.post(
                self.teams_webhook,
                json=payload,
                timeout=10,
            )
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"[ALERT] Teams alert failed: {e}", file=sys.stderr)
            return False
    
    def send_alert(
        self,
        level: str,
        message: str,
        program_name: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        channels: Optional[List[str]] = None,
    ) -> Dict[str, bool]:
        """Send alert to configured channels.
        
        Args:
            level: Alert level (critical, high, medium, info)
            message: Alert message
            program_name: Optional program name
            details: Optional additional details
            channels: Optional list of channels to use (default: all configured)
            
        Returns:
            Dict with channel -> success status
        """
        # Check throttling
        alert_key = f"{level}:{message[:50]}"
        if not self.should_send_alert(alert_key, level, program_name):
            return {"throttled": True}
        
        # Load program config for channel preferences
        program_config = {}
        if program_name:
            program_config = self.load_program_alert_config(program_name)
        
        # Determine which channels to use
        if channels is None:
            channels = program_config.get("channels", ["slack", "email", "teams"])
        
        results = {}
        
        # Send to Slack
        if "slack" in channels and self.slack_webhook:
            results["slack"] = self.send_slack_alert(message, level, details)
        
        # Send to Email
        if "email" in channels:
            recipients = program_config.get("email_recipients", [])
            if recipients:
                subject = f"Bug Bounty Alert: {message[:50]}"
                results["email"] = self.send_email_alert(
                    subject, message, recipients, level
                )
        
        # Send to Teams
        if "teams" in channels and self.teams_webhook:
            title = f"Bug Bounty Alert: {level.upper()}"
            results["teams"] = self.send_teams_alert(title, message, level, details)
        
        return results
    
    def alert_critical_finding(
        self,
        finding: Dict[str, Any],
        program_name: Optional[str] = None,
    ):
        """Send alert for a critical finding.
        
        Args:
            finding: Finding dict
            program_name: Program name
        """
        title = finding.get("title") or "Unknown Finding"
        cvss = finding.get("cvss_score", 0.0)
        url = finding.get("url") or finding.get("_raw_finding", {}).get("url", "N/A")
        
        message = f"Critical finding detected: {title} (CVSS: {cvss})"
        
        details = {
            "title": title,
            "url": url,
            "cvss_score": cvss,
            "validation_status": finding.get("validation_status", "unknown"),
            "program": program_name or "unknown",
        }
        
        self.send_alert("critical", message, program_name, details)
    
    def alert_scan_complete(
        self,
        program_name: str,
        scan_summary: Dict[str, Any],
    ):
        """Send alert when scan completes.
        
        Args:
            program_name: Program name
            scan_summary: Scan summary dict
        """
        findings_count = scan_summary.get("findings_count", 0)
        high_severity = scan_summary.get("high_severity_count", 0)
        cost = scan_summary.get("scan_cost", 0.0)
        
        message = f"Scan completed for {program_name}: {findings_count} findings, {high_severity} high-severity"
        
        details = {
            "program": program_name,
            "findings_count": findings_count,
            "high_severity_count": high_severity,
            "scan_cost": f"${cost:.2f}",
            "timestamp": datetime.now().isoformat(),
        }
        
        level = "high" if high_severity > 0 else "info"
        self.send_alert(level, message, program_name, details)


# Global alert manager instance
_alert_manager: Optional[AlertManager] = None


def get_alert_manager() -> AlertManager:
    """Get or create global alert manager instance."""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager


if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Alerting System Test")
    parser.add_argument("--level", default="info", choices=["critical", "high", "medium", "info"])
    parser.add_argument("--message", required=True)
    parser.add_argument("--program", help="Program name")
    
    args = parser.parse_args()
    
    manager = get_alert_manager()
    result = manager.send_alert(args.level, args.message, args.program)
    
    print(f"Alert sent: {result}")

