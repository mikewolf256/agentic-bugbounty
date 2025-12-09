#!/usr/bin/env python3
"""HackerOne API Submission Module

Handles submission of validated findings to HackerOne via API v1.
"""

import os
import sys
import base64
import json
from typing import Dict, Any, Optional

# Import stealth HTTP client for WAF evasion
try:
    from tools.http_client import safe_get, safe_post, get_stealth_session
    USE_STEALTH = True
except ImportError:
    import requests
    USE_STEALTH = False
    
    def safe_get(url, **kwargs):
        return requests.get(url, **kwargs)
    
    def safe_post(url, **kwargs):
        return requests.post(url, **kwargs)



class H1Submitter:
    """Handles HackerOne API submissions."""
    
    def __init__(self, api_token: Optional[str] = None, username: Optional[str] = None):
        """Initialize H1 submitter.
        
        Args:
            api_token: HackerOne API token (defaults to H1_API_TOKEN env var)
            username: HackerOne username (defaults to H1_USERNAME env var)
        """
        self.api_token = api_token or os.environ.get("H1_API_TOKEN")
        self.username = username or os.environ.get("H1_USERNAME")
        self.api_base = "https://api.hackerone.com/v1"
        
        if not self.api_token or not self.username:
            raise ValueError("H1_API_TOKEN and H1_USERNAME must be set")
    
    def _get_auth_token(self) -> str:
        """Get Basic Auth token for H1 API.
        
        Returns:
            Base64-encoded auth token
        """
        credentials = f"{self.username}:{self.api_token}"
        return base64.b64encode(credentials.encode()).decode()
    
    def _map_cvss_to_h1_severity(self, cvss: float) -> str:
        """Map CVSS score to H1 severity rating.
        
        Args:
            cvss: CVSS score (0.0-10.0)
            
        Returns:
            H1 severity rating (critical, high, medium, low, none)
        """
        if cvss >= 9.0:
            return "critical"
        elif cvss >= 7.0:
            return "high"
        elif cvss >= 4.0:
            return "medium"
        elif cvss > 0.0:
            return "low"
        else:
            return "none"
    
    def submit_report(
        self,
        finding: Dict[str, Any],
        program_handle: str,
        report_markdown: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submit a finding to HackerOne.
        
        Args:
            finding: Finding dict with details
            program_handle: HackerOne program handle
            report_markdown: Optional markdown report (will generate if not provided)
            
        Returns:
            Response dict with success status and report_id or error
        """
        if not report_markdown:
            # Generate report from finding data
            report_markdown = self._generate_report_from_finding(finding)
        
        title = finding.get("title") or "Security Finding"
        cvss = float(finding.get("cvss_score", 0) or 0)
        severity_rating = self._map_cvss_to_h1_severity(cvss)
        
        # Build request payload
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": title,
                    "vulnerability_information": report_markdown,
                    "severity_rating": severity_rating,
                },
                "relationships": {
                    "program": {
                        "data": {
                            "type": "program",
                            "attributes": {
                                "handle": program_handle
                            }
                        }
                    }
                }
            }
        }
        
        # Add impact field if available
        impact = finding.get("impact") or finding.get("business_impact")
        if impact:
            payload["data"]["attributes"]["impact"] = str(impact)[:5000]  # H1 limit
        
        # Make API request
        url = f"{self.api_base}/hackers/reports"
        headers = {
            "Authorization": f"Basic {self._get_auth_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        try:
            response = safe_post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            report_id = result.get("data", {}).get("id")
            
            return {
                "success": True,
                "report_id": report_id,
                "response": result,
            }
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP {e.response.status_code}"
            try:
                error_data = e.response.json()
                error_msg = error_data.get("errors", [{}])[0].get("detail", error_msg)
            except:
                pass
            
            return {
                "success": False,
                "error": error_msg,
                "status_code": e.response.status_code,
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }
    
    def _generate_report_from_finding(self, finding: Dict[str, Any]) -> str:
        """Generate markdown report from finding data.
        
        Args:
            finding: Finding dict
            
        Returns:
            Markdown report string
        """
        title = finding.get("title", "Security Finding")
        url = finding.get("url") or finding.get("_raw_finding", {}).get("url", "N/A")
        cvss = finding.get("cvss_score", 0.0)
        description = finding.get("description") or finding.get("summary", "")
        
        report = f"""# {title}

## Summary
{description}

## Vulnerability Details
- **CVSS Score**: {cvss:.1f}
- **Target URL**: {url}

## Proof of Concept
"""
        
        # Add validation evidence
        validation = finding.get("validation", {})
        if validation:
            report += "\n### Validation Evidence\n\n"
            
            # Dalfox evidence
            dalfox = validation.get("dalfox", {})
            if dalfox:
                payload = dalfox.get("payload", "")
                if payload:
                    report += f"- **Payload**: `{payload}`\n"
            
            # SQLMap evidence
            sqlmap = validation.get("sqlmap", {})
            if sqlmap:
                report += f"- **SQL Injection Confirmed**: {sqlmap.get('engine_result', 'N/A')}\n"
        
        # Add request/response if available
        request_capture = finding.get("request_capture")
        if request_capture:
            report += "\n### Request/Response\n\n"
            report += f"```\n{json.dumps(request_capture, indent=2)[:2000]}\n```\n"
        
        # Add impact
        impact = finding.get("impact") or finding.get("business_impact")
        if impact:
            report += f"\n## Impact\n{impact}\n"
        
        # Add remediation
        remediation = finding.get("remediation") or finding.get("recommendation")
        if remediation:
            report += f"\n## Remediation\n{remediation}\n"
        
        return report


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="H1 Submitter Test")
    parser.add_argument("--program", required=True, help="Program handle")
    parser.add_argument("--finding-file", required=True, help="Path to finding JSON file")
    parser.add_argument("--report-file", help="Path to markdown report file")
    
    args = parser.parse_args()
    
    try:
        submitter = H1Submitter()
        
        with open(args.finding_file, "r") as f:
            finding = json.load(f)
        
        report_markdown = None
        if args.report_file:
            with open(args.report_file, "r") as f:
                report_markdown = f.read()
        
        result = submitter.submit_report(finding, args.program, report_markdown)
        
        if result["success"]:
            print(f"✓ Report submitted successfully: {result['report_id']}")
        else:
            print(f"✗ Submission failed: {result.get('error', 'Unknown error')}")
            sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

