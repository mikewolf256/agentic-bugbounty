#!/usr/bin/env python3
"""MCP Server Lab Simulation Test Suite

This script simulates using the MCP server against the docker labs
and generates a report of issues, gaps, and things to work on.

Usage:
    # Start labs first:
    cd labs/xss_js_secrets && docker-compose up -d
    cd labs/backup_leaks_fingerprint && docker-compose up -d
    cd labs/idor_auth && docker-compose up -d
    
    # Start MCP server:
    python mcp_zap_server.py
    
    # Run this test:
    python tests/test_mcp_lab_simulation.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests

# Configuration
MCP_BASE_URL = os.environ.get("MCP_BASE_URL", "http://127.0.0.1:8000")
OUTPUT_DIR = Path(__file__).parent.parent / "output_zap" / "test_reports"

# Use Docker service names for MCP->lab communication (when MCP runs in Docker)
# Use localhost URLs for test script->lab communication (running outside Docker)
USE_DOCKER_URLS = os.environ.get("USE_DOCKER_URLS", "true").lower() in ("1", "true", "yes")

# Lab configurations - these map to actual lab ports when running locally
LABS = {
    "xss_js_secrets": {
        "base_url": "http://localhost:5001",  # For test script health checks
        "docker_url": "http://xss_js_secrets:5000",  # For MCP->lab (inside docker network)
        "description": "Reflected XSS in /search?q= and JS-exposed secrets in config.js",
        "expected_findings": {
            "xss": [{"url": "/search?q=<script>alert(1)</script>", "param": "q"}],
            "js_secrets": {"min_count": 2, "types": ["api_key", "jwt"]},
        },
    },
    "backup_leaks_fingerprint": {
        "base_url": "http://localhost:5003",  # For test script health checks
        "docker_url": "http://backup_leaks_fingerprint:80",  # For MCP->lab (inside docker network)
        "description": "Exposes backup-like config and .git data; PHP over Apache",
        "expected_findings": {
            "backups": ["/config.php.bak", "/.git/HEAD"],
            "fingerprints": {"min_tech_count": 1, "expected_tech_substrings": ["Apache", "PHP"]},
        },
    },
    "idor_auth": {
        "base_url": "http://localhost:5002",  # For test script health checks
        "docker_url": "http://idor_auth:5000",  # For MCP->lab (inside docker network)
        "description": "Simple bearer-token auth plus IDOR on /api/users/<id>",
        "expected_findings": {
            "bac": [{"url": "/api/users/2", "requires_auth": True}],
        },
    },
    "auth_scan_lab": {
        "base_url": "http://localhost:5004",  # For test script health checks
        "docker_url": "http://auth_scan_lab:5000",  # For MCP->lab (inside docker network)
        "description": "Comprehensive auth vulnerability lab with 18 known vulnerabilities",
        "expected_findings": {
            "bac": [
                {"url": "/api/users/3", "requires_auth": True, "vuln_id": "VULN-007"},
                {"url": "/api/orders/3", "requires_auth": True, "vuln_id": "VULN-008"},
                {"url": "/admin", "requires_auth": False, "vuln_id": "VULN-013"},
                {"url": "/admin/users", "requires_auth": True, "vuln_id": "VULN-014"},
            ],
            "default_creds": {"username": "admin", "password": "admin", "vuln_id": "VULN-001"},
            "jwt": {
                "weak_secret": "secret123",
                "accepts_none": True,
                "vuln_ids": ["VULN-002", "VULN-003"]
            },
            "fingerprints": {"min_tech_count": 1, "expected_tech_substrings": ["Python", "Flask"]},
            "sensitive_exposure": [
                {"url": "/admin/config", "vuln_id": "VULN-015"},
                {"url": "/api/internal/debug", "vuln_id": "VULN-016"},
                {"url": "/robots.txt", "vuln_id": "VULN-017"},
            ],
        },
        "auth": {
            "quick_login": "/login/alice",
            "credentials": {"username": "alice", "password": "alice123"},
        },
    },
}


@dataclass
class TestResult:
    """Result of a single test case."""
    name: str
    passed: bool
    message: str
    duration_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    category: str = "general"


@dataclass
class IssueReport:
    """Identified issue or improvement opportunity."""
    severity: str  # critical, high, medium, low, info
    category: str  # bug, missing_feature, improvement, documentation
    title: str
    description: str
    affected_component: str
    suggested_fix: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


class MCPLabSimulator:
    """Simulates MCP server operations against docker labs."""
    
    def __init__(self, mcp_base: str = MCP_BASE_URL):
        self.mcp_base = mcp_base.rstrip("/")
        self.test_results: List[TestResult] = []
        self.issues: List[IssueReport] = []
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
    
    def _mcp_post(self, endpoint: str, data: Dict[str, Any]) -> Tuple[Optional[Dict], Optional[str]]:
        """POST to MCP endpoint, return (response_json, error_message)."""
        url = f"{self.mcp_base}{endpoint}"
        try:
            # Longer timeout for operations that may pull Docker images
            resp = self.session.post(url, json=data, timeout=300)
            if resp.status_code >= 400:
                return None, f"HTTP {resp.status_code}: {resp.text[:500]}"
            return resp.json(), None
        except requests.exceptions.ConnectionError:
            return None, f"Connection refused to {url}"
        except requests.exceptions.Timeout:
            return None, f"Timeout connecting to {url}"
        except Exception as e:
            return None, str(e)
    
    def _mcp_get(self, endpoint: str) -> Tuple[Optional[Dict], Optional[str]]:
        """GET from MCP endpoint."""
        url = f"{self.mcp_base}{endpoint}"
        try:
            resp = self.session.get(url, timeout=30)
            if resp.status_code >= 400:
                return None, f"HTTP {resp.status_code}: {resp.text[:500]}"
            return resp.json(), None
        except Exception as e:
            return None, str(e)
    
    def _check_lab_reachable(self, lab_name: str) -> bool:
        """Check if a lab is reachable."""
        lab = LABS[lab_name]
        try:
            resp = requests.get(lab["base_url"], timeout=5)
            return resp.status_code < 500
        except:
            return False
    
    def _check_mcp_server(self) -> bool:
        """Check if MCP server is running."""
        try:
            resp = requests.get(f"{self.mcp_base}/docs", timeout=5)
            return resp.status_code == 200
        except:
            return False
    
    def test_mcp_server_health(self) -> TestResult:
        """Test: MCP server is running and healthy."""
        start = time.time()
        is_healthy = self._check_mcp_server()
        duration = (time.time() - start) * 1000
        
        if not is_healthy:
            self.issues.append(IssueReport(
                severity="critical",
                category="bug",
                title="MCP Server not reachable",
                description=f"Cannot connect to MCP server at {self.mcp_base}",
                affected_component="mcp_zap_server.py",
                suggested_fix="Start MCP server: python mcp_zap_server.py",
            ))
        
        return TestResult(
            name="MCP Server Health",
            passed=is_healthy,
            message="MCP server is running" if is_healthy else f"Cannot reach MCP server at {self.mcp_base}",
            duration_ms=duration,
            category="infrastructure",
        )
    
    def _get_target_url(self, lab_name: str) -> str:
        """Get the appropriate URL for MCP to use when targeting a lab.
        
        When MCP runs in Docker, it needs to use Docker service names.
        """
        lab = LABS[lab_name]
        if USE_DOCKER_URLS:
            return lab["docker_url"]
        return lab["base_url"]
    
    def test_set_scope(self, lab_name: str) -> TestResult:
        """Test: /mcp/set_scope endpoint."""
        start = time.time()
        lab = LABS[lab_name]
        target_url = self._get_target_url(lab_name)
        
        scope = {
            "program_name": f"lab-{lab_name}",
            "primary_targets": [target_url],
            "secondary_targets": [],
            "rules": {},
        }
        
        resp, err = self._mcp_post("/mcp/set_scope", scope)
        duration = (time.time() - start) * 1000
        
        if err:
            return TestResult(
                name=f"Set Scope ({lab_name})",
                passed=False,
                message=f"Failed: {err}",
                duration_ms=duration,
                category="api",
            )
        
        return TestResult(
            name=f"Set Scope ({lab_name})",
            passed=True,
            message="Scope set successfully",
            duration_ms=duration,
            details=resp,
            category="api",
        )
    
    def test_katana_nuclei(self, lab_name: str) -> TestResult:
        """Test: /mcp/run_katana_nuclei endpoint."""
        start = time.time()
        target_url = self._get_target_url(lab_name)
        
        payload = {"target": target_url}
        resp, err = self._mcp_post("/mcp/run_katana_nuclei", payload)
        duration = (time.time() - start) * 1000
        
        if err:
            # Check if this is a tool availability issue
            if "katana_nuclei_recon.py" in str(err) or "nuclei" in str(err).lower():
                self.issues.append(IssueReport(
                    severity="high",
                    category="missing_feature",
                    title="Katana/Nuclei integration issues",
                    description=f"Error running katana_nuclei: {err}",
                    affected_component="tools/katana_nuclei_recon.py",
                    suggested_fix="Ensure Docker is running and projectdiscovery/katana image is available",
                    evidence={"error": err},
                ))
            
            return TestResult(
                name=f"Katana+Nuclei ({lab_name})",
                passed=False,
                message=f"Failed: {err}",
                duration_ms=duration,
                category="scanning",
            )
        
        # Validate response structure
        katana_count = resp.get("katana_count", 0)
        findings_count = resp.get("findings_count", 0)
        
        return TestResult(
            name=f"Katana+Nuclei ({lab_name})",
            passed=True,
            message=f"Crawled {katana_count} URLs, {findings_count} findings",
            duration_ms=duration,
            details=resp,
            category="scanning",
        )
    
    def test_backup_hunt_job(self, lab_name: str) -> TestResult:
        """Test: /mcp/run_backup_hunt background job."""
        start = time.time()
        target_url = self._get_target_url(lab_name)
        
        payload = {"base_url": target_url}
        resp, err = self._mcp_post("/mcp/run_backup_hunt", payload)
        duration = (time.time() - start) * 1000
        
        if err:
            if "not in scope" in str(err).lower():
                self.issues.append(IssueReport(
                    severity="medium",
                    category="improvement",
                    title="Scope enforcement blocks valid lab targets",
                    description="Backup hunt fails because target not in scope",
                    affected_component="mcp_zap_server.py",
                    suggested_fix="Call /mcp/set_scope before running other endpoints",
                ))
            return TestResult(
                name=f"Backup Hunt ({lab_name})",
                passed=False,
                message=f"Failed: {err}",
                duration_ms=duration,
                category="scanning",
            )
        
        job_id = resp.get("job_id")
        if not job_id:
            return TestResult(
                name=f"Backup Hunt ({lab_name})",
                passed=False,
                message="No job_id returned",
                duration_ms=duration,
                category="scanning",
            )
        
        # Poll job status
        max_wait = 30
        waited = 0
        while waited < max_wait:
            status_resp, status_err = self._mcp_get(f"/mcp/job/{job_id}")
            if status_err:
                break
            if status_resp.get("status") in ("finished", "error"):
                break
            time.sleep(1)
            waited += 1
        
        total_duration = (time.time() - start) * 1000
        
        return TestResult(
            name=f"Backup Hunt ({lab_name})",
            passed=status_resp.get("status") == "finished" if status_resp else False,
            message=f"Job {job_id}: {status_resp.get('status') if status_resp else 'unknown'}",
            duration_ms=total_duration,
            details={"job_id": job_id, "final_status": status_resp},
            category="scanning",
        )
    
    def test_js_miner_job(self, lab_name: str) -> TestResult:
        """Test: /mcp/run_js_miner background job."""
        start = time.time()
        target_url = self._get_target_url(lab_name)
        
        payload = {"base_url": target_url}
        resp, err = self._mcp_post("/mcp/run_js_miner", payload)
        duration = (time.time() - start) * 1000
        
        if err:
            return TestResult(
                name=f"JS Miner ({lab_name})",
                passed=False,
                message=f"Failed: {err}",
                duration_ms=duration,
                category="scanning",
            )
        
        job_id = resp.get("job_id")
        if not job_id:
            return TestResult(
                name=f"JS Miner ({lab_name})",
                passed=False,
                message="No job_id returned",
                duration_ms=duration,
                category="scanning",
            )
        
        # Poll for completion
        max_wait = 30
        waited = 0
        status_resp = None
        while waited < max_wait:
            status_resp, _ = self._mcp_get(f"/mcp/job/{job_id}")
            if status_resp and status_resp.get("status") in ("finished", "error"):
                break
            time.sleep(1)
            waited += 1
        
        total_duration = (time.time() - start) * 1000
        
        return TestResult(
            name=f"JS Miner ({lab_name})",
            passed=status_resp.get("status") == "finished" if status_resp else False,
            message=f"Job {job_id}: {status_resp.get('status') if status_resp else 'timeout'}",
            duration_ms=total_duration,
            details={"job_id": job_id, "final_status": status_resp},
            category="scanning",
        )
    
    def test_host_profile(self, lab_name: str) -> TestResult:
        """Test: /mcp/host_profile endpoint."""
        start = time.time()
        target_url = self._get_target_url(lab_name)
        
        # Extract hostname from URL
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        host = parsed.netloc
        
        payload = {"host": host}
        resp, err = self._mcp_post("/mcp/host_profile", payload)
        duration = (time.time() - start) * 1000
        
        if err:
            return TestResult(
                name=f"Host Profile ({lab_name})",
                passed=False,
                message=f"Failed: {err}",
                duration_ms=duration,
                category="api",
            )
        
        # Validate response structure
        has_web = "web" in resp
        has_host = "host" in resp
        
        if not has_web or not has_host:
            self.issues.append(IssueReport(
                severity="low",
                category="improvement",
                title="Incomplete host_profile response",
                description=f"Missing expected keys in response: web={has_web}, host={has_host}",
                affected_component="mcp_zap_server.py",
                suggested_fix="Ensure host_profile returns complete data structure",
                evidence={"response_keys": list(resp.keys())},
            ))
        
        return TestResult(
            name=f"Host Profile ({lab_name})",
            passed=has_web and has_host,
            message=f"Profile built: {len(resp.get('web', {}).get('urls', []))} URLs",
            duration_ms=duration,
            details=resp,
            category="api",
        )
    
    def test_triage_nuclei_templates(self, lab_name: str) -> TestResult:
        """Test: /mcp/triage_nuclei_templates AI endpoint."""
        start = time.time()
        target_url = self._get_target_url(lab_name)
        
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        host = parsed.netloc
        
        # First need to build host_profile
        self._mcp_post("/mcp/host_profile", {"host": host})
        
        payload = {"host": host, "use_llm": False}  # Skip LLM for faster testing
        resp, err = self._mcp_post("/mcp/triage_nuclei_templates", payload)
        duration = (time.time() - start) * 1000
        
        if err:
            if "No host_profile snapshot found" in str(err):
                self.issues.append(IssueReport(
                    severity="medium",
                    category="improvement",
                    title="AI triage requires prior host_profile",
                    description="triage_nuclei_templates fails without prior host_profile call",
                    affected_component="mcp_zap_server.py",
                    suggested_fix="Auto-trigger host_profile in triage_nuclei_templates if missing",
                ))
            
            return TestResult(
                name=f"AI Nuclei Triage ({lab_name})",
                passed=False,
                message=f"Failed: {err}",
                duration_ms=duration,
                category="ai",
            )
        
        templates = resp.get("templates", [])
        mode = resp.get("mode", "unknown")
        reasoning = resp.get("reasoning", "")
        
        return TestResult(
            name=f"AI Nuclei Triage ({lab_name})",
            passed=True,
            message=f"Mode: {mode}, {len(templates)} templates selected",
            duration_ms=duration,
            details=resp,
            category="ai",
        )
    
    def test_fingerprints(self, lab_name: str) -> TestResult:
        """Test: /mcp/run_fingerprints endpoint."""
        start = time.time()
        target_url = self._get_target_url(lab_name)
        
        payload = {"target": target_url}
        resp, err = self._mcp_post("/mcp/run_fingerprints", payload)
        duration = (time.time() - start) * 1000
        
        if err:
            if "whatweb" in str(err).lower() or "not found" in str(err).lower():
                self.issues.append(IssueReport(
                    severity="medium",
                    category="missing_feature",
                    title="WhatWeb not available for fingerprinting",
                    description="Fingerprinting endpoint requires whatweb binary",
                    affected_component="mcp_zap_server.py",
                    suggested_fix="Install whatweb or provide Docker alternative",
                    evidence={"error": err},
                ))
            
            return TestResult(
                name=f"Fingerprints ({lab_name})",
                passed=False,
                message=f"Failed: {err}",
                duration_ms=duration,
                category="scanning",
            )
        
        technologies = resp.get("technologies", [])
        
        return TestResult(
            name=f"Fingerprints ({lab_name})",
            passed=True,
            message=f"Detected {len(technologies)} technologies",
            duration_ms=duration,
            details=resp,
            category="scanning",
        )
    
    def test_bac_checks(self, lab_name: str) -> TestResult:
        """Test: /mcp/run_bac_checks endpoint."""
        start = time.time()
        target_url = self._get_target_url(lab_name)
        
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        host = parsed.netloc
        
        payload = {"host": host}
        resp, err = self._mcp_post("/mcp/run_bac_checks", payload)
        duration = (time.time() - start) * 1000
        
        if err:
            return TestResult(
                name=f"BAC Checks ({lab_name})",
                passed=False,
                message=f"Failed: {err}",
                duration_ms=duration,
                category="validation",
            )
        
        meta = resp.get("meta", {})
        checks_count = meta.get("checks_count", 0)
        confirmed = meta.get("confirmed_issues_count", 0)
        
        return TestResult(
            name=f"BAC Checks ({lab_name})",
            passed=True,
            message=f"Ran {checks_count} checks, {confirmed} issues found",
            duration_ms=duration,
            details=resp,
            category="validation",
        )
    
    def test_ssrf_checks(self, lab_name: str) -> TestResult:
        """Test: /mcp/run_ssrf_checks endpoint."""
        start = time.time()
        target_url = self._get_target_url(lab_name)
        
        # SSRF test needs a URL with a parameter
        test_url = f"{target_url}?url=http://example.com"
        
        payload = {"target": test_url, "param": "url"}
        resp, err = self._mcp_post("/mcp/run_ssrf_checks", payload)
        duration = (time.time() - start) * 1000
        
        if err:
            return TestResult(
                name=f"SSRF Checks ({lab_name})",
                passed=False,
                message=f"Failed: {err}",
                duration_ms=duration,
                category="validation",
            )
        
        meta = resp.get("meta", {})
        checks_count = meta.get("checks_count", 0)
        confirmed = meta.get("confirmed_issues_count", 0)
        
        return TestResult(
            name=f"SSRF Checks ({lab_name})",
            passed=True,
            message=f"Ran {checks_count} checks, {confirmed} issues found",
            duration_ms=duration,
            details=resp,
            category="validation",
        )
    
    def test_nuclei_scan(self, lab_name: str) -> TestResult:
        """Test: /mcp/run_nuclei endpoint."""
        start = time.time()
        target_url = self._get_target_url(lab_name)
        
        payload = {"target": target_url, "mode": "recon"}
        resp, err = self._mcp_post("/mcp/run_nuclei", payload)
        duration = (time.time() - start) * 1000
        
        if err:
            return TestResult(
                name=f"Nuclei Scan ({lab_name})",
                passed=False,
                message=f"Failed: {err}",
                duration_ms=duration,
                category="scanning",
            )
        
        findings_count = resp.get("findings_count", 0)
        mode = resp.get("mode", "unknown")
        
        return TestResult(
            name=f"Nuclei Scan ({lab_name})",
            passed=True,
            message=f"Mode: {mode}, {findings_count} findings",
            duration_ms=duration,
            details=resp,
            category="scanning",
        )
    
    def analyze_code_issues(self) -> List[IssueReport]:
        """Static analysis of code for potential issues."""
        issues = []
        
        repo_root = Path(__file__).parent.parent
        
        # Check mcp_zap_server.py for common issues
        mcp_server = repo_root / "mcp_zap_server.py"
        if mcp_server.exists():
            content = mcp_server.read_text()
            
            # Check for missing endpoints referenced in docs
            if "/mcp/run_bac_checks" not in content:
                issues.append(IssueReport(
                    severity="high",
                    category="missing_feature",
                    title="Missing /mcp/run_bac_checks endpoint",
                    description="agentic_runner.py references this endpoint but it's not implemented",
                    affected_component="mcp_zap_server.py",
                    suggested_fix="Implement BAC checking endpoint for broken access control testing",
                ))
            
            if "/mcp/run_ssrf_checks" not in content:
                issues.append(IssueReport(
                    severity="high",
                    category="missing_feature",
                    title="Missing /mcp/run_ssrf_checks endpoint",
                    description="agentic_runner.py references this endpoint but it's not implemented",
                    affected_component="mcp_zap_server.py",
                    suggested_fix="Implement SSRF checking endpoint for server-side request forgery testing",
                ))
            
            if "/mcp/start_zap_scan" not in content:
                issues.append(IssueReport(
                    severity="medium",
                    category="missing_feature",
                    title="Missing /mcp/start_zap_scan endpoint",
                    description="Full-scan mode references ZAP integration that's not implemented",
                    affected_component="mcp_zap_server.py",
                    suggested_fix="Implement ZAP integration or remove references",
                ))
            
            if "/mcp/run_sqlmap" not in content:
                issues.append(IssueReport(
                    severity="medium",
                    category="missing_feature",
                    title="Missing /mcp/run_sqlmap endpoint",
                    description="SQLi validation references sqlmap endpoint that's not implemented",
                    affected_component="mcp_zap_server.py",
                    suggested_fix="Implement sqlmap integration for SQL injection testing",
                ))
            
            if "/mcp/run_ffuf" not in content or "def run_ffuf" not in content:
                issues.append(IssueReport(
                    severity="medium",
                    category="missing_feature",
                    title="Missing /mcp/run_ffuf endpoint implementation",
                    description="Ffuf endpoint declared in docstring but not implemented",
                    affected_component="mcp_zap_server.py",
                    suggested_fix="Implement ffuf fuzzing endpoint",
                ))
            
            if "/mcp/run_nuclei" not in content or "def run_nuclei" not in content:
                issues.append(IssueReport(
                    severity="high",
                    category="missing_feature",
                    title="Missing /mcp/run_nuclei endpoint implementation",
                    description="Nuclei endpoint declared in docstring but not implemented separately",
                    affected_component="mcp_zap_server.py",
                    suggested_fix="Implement standalone nuclei scan endpoint",
                ))
            
            if "/mcp/validate_poc_with_nuclei" not in content:
                issues.append(IssueReport(
                    severity="medium",
                    category="missing_feature",
                    title="Missing /mcp/validate_poc_with_nuclei endpoint",
                    description="PoC validation endpoint referenced in docs but not implemented",
                    affected_component="mcp_zap_server.py",
                    suggested_fix="Implement PoC validation with nuclei templates",
                ))
            
            if "/mcp/run_cloud_recon" not in content or "def run_cloud_recon" not in content:
                issues.append(IssueReport(
                    severity="low",
                    category="missing_feature",
                    title="Missing /mcp/run_cloud_recon endpoint implementation",
                    description="Cloud recon endpoint declared but not implemented",
                    affected_component="mcp_zap_server.py",
                    suggested_fix="Implement cloud resource discovery endpoint",
                ))
            
            if "/mcp/prioritize_host" not in content:
                issues.append(IssueReport(
                    severity="low",
                    category="missing_feature",
                    title="Missing /mcp/prioritize_host endpoint",
                    description="Host prioritization endpoint not implemented",
                    affected_component="mcp_zap_server.py",
                    suggested_fix="Implement risk scoring for host prioritization",
                ))
            
            if "/mcp/run_reflector" not in content or "def run_reflector" not in content:
                issues.append(IssueReport(
                    severity="low",
                    category="missing_feature",
                    title="Missing /mcp/run_reflector endpoint",
                    description="Parameter reflector endpoint not implemented",
                    affected_component="mcp_zap_server.py",
                    suggested_fix="Implement parameter reflection testing endpoint",
                ))
        
        # Check for missing tools
        tools_dir = repo_root / "tools"
        expected_tools = [
            ("reflector_tester.py", "Parameter reflection testing"),
        ]
        
        for tool_name, description in expected_tools:
            tool_path = tools_dir / tool_name
            if tool_path.exists():
                content = tool_path.read_text()
                if "def main" not in content or len(content) < 500:
                    issues.append(IssueReport(
                        severity="low",
                        category="improvement",
                        title=f"Incomplete tool: {tool_name}",
                        description=f"{description} tool may be incomplete",
                        affected_component=f"tools/{tool_name}",
                        suggested_fix="Complete implementation of tool",
                    ))
        
        # Check agentic_runner.py for issues
        runner = repo_root / "agentic_runner.py"
        if runner.exists():
            content = runner.read_text()
            
            if "OPENAI_API_KEY" in content and "raise SystemExit" in content:
                issues.append(IssueReport(
                    severity="info",
                    category="documentation",
                    title="Hard dependency on OpenAI API key",
                    description="agentic_runner.py exits if OPENAI_API_KEY not set",
                    affected_component="agentic_runner.py",
                    suggested_fix="Add fallback mode without LLM for basic operation",
                ))
        
        return issues
    
    def run_all_tests(self, labs_to_test: Optional[List[str]] = None) -> None:
        """Run all tests against specified labs."""
        if labs_to_test is None:
            labs_to_test = list(LABS.keys())
        
        print("=" * 60)
        print("MCP Server Lab Simulation Test Suite")
        print(f"Started: {datetime.now().isoformat()}")
        print("=" * 60)
        
        # Infrastructure checks
        self.test_results.append(self.test_mcp_server_health())
        
        # Check which labs are reachable
        reachable_labs = []
        for lab_name in labs_to_test:
            if self._check_lab_reachable(lab_name):
                reachable_labs.append(lab_name)
                print(f"✓ Lab '{lab_name}' is reachable")
            else:
                print(f"✗ Lab '{lab_name}' is NOT reachable")
                self.issues.append(IssueReport(
                    severity="info",
                    category="documentation",
                    title=f"Lab '{lab_name}' not running",
                    description=f"Could not reach {LABS[lab_name]['base_url']}",
                    affected_component=f"labs/{lab_name}",
                    suggested_fix=f"Start lab: cd labs/{lab_name} && docker-compose up -d",
                ))
        
        if not self.test_results[-1].passed:
            print("\n⚠️  MCP Server not running - skipping API tests")
            print("   Start with: python mcp_zap_server.py")
        else:
            # Run API tests for each reachable lab
            for lab_name in reachable_labs:
                print(f"\n--- Testing lab: {lab_name} ---")
                
                # Set scope first
                self.test_results.append(self.test_set_scope(lab_name))
                
                # Core endpoint tests
                self.test_results.append(self.test_host_profile(lab_name))
                self.test_results.append(self.test_triage_nuclei_templates(lab_name))
                
                # Scanning tests (may be slow)
                self.test_results.append(self.test_katana_nuclei(lab_name))
                self.test_results.append(self.test_backup_hunt_job(lab_name))
                self.test_results.append(self.test_js_miner_job(lab_name))
                self.test_results.append(self.test_fingerprints(lab_name))
                
                # Validation tests (BAC, SSRF, Nuclei)
                self.test_results.append(self.test_bac_checks(lab_name))
                self.test_results.append(self.test_ssrf_checks(lab_name))
                self.test_results.append(self.test_nuclei_scan(lab_name))
        
        # Static code analysis
        print("\n--- Analyzing codebase for issues ---")
        code_issues = self.analyze_code_issues()
        self.issues.extend(code_issues)
        
        self._generate_report()
    
    def _generate_report(self) -> None:
        """Generate final report."""
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = OUTPUT_DIR / f"mcp_lab_report_{timestamp}.md"
        json_path = OUTPUT_DIR / f"mcp_lab_report_{timestamp}.json"
        
        # Build markdown report
        lines = [
            "# MCP Server Lab Simulation Report",
            "",
            f"**Generated:** {datetime.now().isoformat()}",
            f"**MCP Server:** {self.mcp_base}",
            "",
            "---",
            "",
            "## Test Results Summary",
            "",
        ]
        
        passed = sum(1 for t in self.test_results if t.passed)
        failed = len(self.test_results) - passed
        
        lines.append(f"- **Passed:** {passed}")
        lines.append(f"- **Failed:** {failed}")
        lines.append(f"- **Total:** {len(self.test_results)}")
        lines.append("")
        
        # Group by category
        by_category: Dict[str, List[TestResult]] = {}
        for t in self.test_results:
            by_category.setdefault(t.category, []).append(t)
        
        for category, tests in sorted(by_category.items()):
            lines.append(f"### {category.title()} Tests")
            lines.append("")
            lines.append("| Test | Status | Duration | Message |")
            lines.append("|------|--------|----------|---------|")
            for t in tests:
                status = "✅" if t.passed else "❌"
                lines.append(f"| {t.name} | {status} | {t.duration_ms:.0f}ms | {t.message[:50]} |")
            lines.append("")
        
        # Issues section
        lines.append("---")
        lines.append("")
        lines.append("## Issues & Improvements")
        lines.append("")
        
        if not self.issues:
            lines.append("No issues identified! 🎉")
        else:
            # Group by severity
            by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
            for issue in self.issues:
                by_severity[issue.severity].append(issue)
            
            for severity in ["critical", "high", "medium", "low", "info"]:
                issues = by_severity[severity]
                if not issues:
                    continue
                
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}[severity]
                lines.append(f"### {emoji} {severity.upper()} ({len(issues)})")
                lines.append("")
                
                for i, issue in enumerate(issues, 1):
                    lines.append(f"#### {i}. {issue.title}")
                    lines.append("")
                    lines.append(f"**Category:** {issue.category}")
                    lines.append(f"**Component:** `{issue.affected_component}`")
                    lines.append("")
                    lines.append(issue.description)
                    lines.append("")
                    if issue.suggested_fix:
                        lines.append(f"**Suggested Fix:** {issue.suggested_fix}")
                        lines.append("")
                    if issue.evidence:
                        lines.append("<details><summary>Evidence</summary>")
                        lines.append("")
                        lines.append("```json")
                        lines.append(json.dumps(issue.evidence, indent=2))
                        lines.append("```")
                        lines.append("</details>")
                        lines.append("")
        
        # Priority action items
        lines.append("---")
        lines.append("")
        lines.append("## Priority Action Items")
        lines.append("")
        
        critical_high = [i for i in self.issues if i.severity in ("critical", "high")]
        if critical_high:
            lines.append("### Must Fix")
            lines.append("")
            for i, issue in enumerate(critical_high, 1):
                lines.append(f"{i}. **{issue.title}** - {issue.suggested_fix or issue.description[:80]}")
            lines.append("")
        
        medium = [i for i in self.issues if i.severity == "medium"]
        if medium:
            lines.append("### Should Fix")
            lines.append("")
            for i, issue in enumerate(medium, 1):
                lines.append(f"{i}. **{issue.title}** - {issue.suggested_fix or issue.description[:80]}")
            lines.append("")
        
        # Write report
        report_content = "\n".join(lines)
        report_path.write_text(report_content)
        
        # Write JSON
        json_data = {
            "timestamp": datetime.now().isoformat(),
            "mcp_base": self.mcp_base,
            "test_results": [
                {
                    "name": t.name,
                    "passed": t.passed,
                    "message": t.message,
                    "duration_ms": t.duration_ms,
                    "category": t.category,
                    "details": t.details,
                }
                for t in self.test_results
            ],
            "issues": [
                {
                    "severity": i.severity,
                    "category": i.category,
                    "title": i.title,
                    "description": i.description,
                    "affected_component": i.affected_component,
                    "suggested_fix": i.suggested_fix,
                    "evidence": i.evidence,
                }
                for i in self.issues
            ],
        }
        json_path.write_text(json.dumps(json_data, indent=2))
        
        print("\n" + "=" * 60)
        print("REPORT GENERATED")
        print("=" * 60)
        print(f"Markdown: {report_path}")
        print(f"JSON: {json_path}")
        print(f"\nTest Results: {passed}/{len(self.test_results)} passed")
        print(f"Issues Found: {len(self.issues)}")
        
        critical_count = sum(1 for i in self.issues if i.severity == "critical")
        high_count = sum(1 for i in self.issues if i.severity == "high")
        if critical_count or high_count:
            print(f"\n⚠️  {critical_count} critical, {high_count} high severity issues need attention!")


def main():
    parser = argparse.ArgumentParser(description="MCP Lab Simulation Test Suite")
    parser.add_argument(
        "--mcp-url",
        default=MCP_BASE_URL,
        help=f"MCP server base URL (default: {MCP_BASE_URL})",
    )
    parser.add_argument(
        "--labs",
        nargs="+",
        choices=list(LABS.keys()),
        help="Specific labs to test (default: all)",
    )
    args = parser.parse_args()
    
    simulator = MCPLabSimulator(mcp_base=args.mcp_url)
    simulator.run_all_tests(labs_to_test=args.labs)


if __name__ == "__main__":
    main()

