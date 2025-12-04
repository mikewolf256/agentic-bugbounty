"""Test utilities for POC validation testing."""

import json
from typing import Dict, Any, List, Optional
from pathlib import Path


def create_mock_finding(
    finding_id: str = "test-finding-1",
    vuln_type: str = "xss",
    url: str = "https://example.com/search?q=test",
    parameter: str = "q",
    **kwargs
) -> Dict[str, Any]:
    """Create a mock finding for testing.
    
    Args:
        finding_id: Unique finding ID
        vuln_type: Vulnerability type (xss, sqli, ssrf, etc.)
        url: Vulnerable URL
        parameter: Vulnerable parameter
        **kwargs: Additional fields to set
    
    Returns:
        Mock finding dict
    """
    base_finding = {
        "id": finding_id,
        "name": f"Test {vuln_type.upper()} Vulnerability",
        "url": url,
        "parameter": parameter,
        "risk": "High",
        "category": vuln_type,
        "cwe": {
            "xss": "CWE-79",
            "sqli": "CWE-89",
            "ssrf": "CWE-918",
            "bac": "CWE-284",
            "oauth": "CWE-639",
        }.get(vuln_type, "CWE-200"),
    }
    
    # Add type-specific evidence
    if vuln_type == "xss":
        base_finding["evidence"] = "<script>alert(1)</script>"
    elif vuln_type == "sqli":
        base_finding["evidence"] = "' OR 1=1 --"
    elif vuln_type == "ssrf":
        base_finding["evidence"] = "http://internal-server:8080"
    
    base_finding.update(kwargs)
    return base_finding


def create_mock_validation_evidence(
    engine: str = "dalfox",
    confirmed: bool = True,
    **kwargs
) -> Dict[str, Any]:
    """Create mock validation evidence for a specific engine.
    
    Args:
        engine: Validation engine name (dalfox, sqlmap, bac, etc.)
        confirmed: Whether vulnerability was confirmed
        **kwargs: Additional evidence fields
    
    Returns:
        Mock validation evidence dict
    """
    base_evidence = {
        "engine_result": "confirmed" if confirmed else "ran",
        "validation_confidence": "high" if confirmed else "medium",
    }
    
    # Engine-specific evidence
    if engine == "dalfox":
        base_evidence.update({
            "payload": "<script>alert(1)</script>",
            "raw_output": "XSS confirmed" if confirmed else "No XSS detected",
        })
    elif engine == "sqlmap":
        base_evidence.update({
            "dbms": "MySQL" if confirmed else None,
            "vulnerable_params": ["id"] if confirmed else [],
        })
    elif engine == "bac":
        base_evidence.update({
            "confirmed_issues_count": 1 if confirmed else 0,
            "checks_count": 5,
        })
    elif engine == "ssrf":
        base_evidence.update({
            "confirmed_issues_count": 1 if confirmed else 0,
            "targets_reached": ["http://internal:8080"] if confirmed else [],
        })
    
    base_evidence.update(kwargs)
    return base_evidence


def assert_poc_validated(finding: Dict[str, Any], expected: bool = True) -> None:
    """Assert POC validation status.
    
    Args:
        finding: Finding dict to check
        expected: Expected validation status
    
    Raises:
        AssertionError: If validation status doesn't match
    """
    poc_validated = finding.get("poc_validated", False)
    assert poc_validated == expected, (
        f"Expected poc_validated={expected}, got {poc_validated}. "
        f"Finding: {finding.get('id', 'unknown')}"
    )


def assert_poc_quality(
    finding: Dict[str, Any],
    min_quality: str = "medium"
) -> None:
    """Assert POC quality score meets minimum threshold.
    
    Args:
        finding: Finding dict to check
        min_quality: Minimum quality level (low, medium, high)
    
    Raises:
        AssertionError: If quality doesn't meet threshold
    """
    quality = finding.get("poc_quality_score", "low")
    quality_levels = {"low": 0, "medium": 1, "high": 2}
    
    actual_level = quality_levels.get(quality, 0)
    min_level = quality_levels.get(min_quality, 0)
    
    assert actual_level >= min_level, (
        f"Expected POC quality >= {min_quality}, got {quality}. "
        f"Finding: {finding.get('id', 'unknown')}"
    )


def assert_validation_evidence_complete(finding: Dict[str, Any]) -> None:
    """Assert validation evidence is complete.
    
    Args:
        finding: Finding dict to check
    
    Raises:
        AssertionError: If evidence is incomplete
    """
    evidence_complete = finding.get("validation_evidence_complete", False)
    assert evidence_complete, (
        f"Expected validation_evidence_complete=True. "
        f"Finding: {finding.get('id', 'unknown')}, "
        f"Validation engines: {finding.get('validation_engines', [])}"
    )


class MCPTestClient:
    """Wrapper for MCP API calls in tests."""
    
    def __init__(self, client):
        """Initialize with FastAPI TestClient."""
        self.client = client
        self.base_url = "/mcp"
    
    def post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """POST to MCP endpoint.
        
        Args:
            endpoint: Endpoint path (e.g., "/set_scope")
            data: Request payload
        
        Returns:
            Response JSON
        
        Raises:
            AssertionError: If request fails
        """
        url = f"{self.base_url}{endpoint}"
        resp = self.client.post(url, json=data)
        assert resp.status_code == 200, (
            f"POST {url} failed with {resp.status_code}: {resp.text}"
        )
        return resp.json()
    
    def get(self, endpoint: str) -> Dict[str, Any]:
        """GET from MCP endpoint.
        
        Args:
            endpoint: Endpoint path
        
        Returns:
            Response JSON
        
        Raises:
            AssertionError: If request fails
        """
        url = f"{self.base_url}{endpoint}"
        resp = self.client.get(url)
        assert resp.status_code == 200, (
            f"GET {url} failed with {resp.status_code}: {resp.text}"
        )
        return resp.json()
    
    def set_scope(self, scope: Dict[str, Any]) -> Dict[str, Any]:
        """Set scope configuration."""
        return self.post("/set_scope", scope)
    
    def host_profile(self, host: str, llm_view: bool = False) -> Dict[str, Any]:
        """Get host profile."""
        return self.post("/host_profile", {"host": host, "llm_view": llm_view})
    
    def run_nuclei(
        self,
        target: str,
        mode: str = "recon",
        templates: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Run Nuclei scan."""
        payload = {"target": target, "mode": mode}
        if templates:
            payload["templates"] = templates
        return self.post("/run_nuclei", payload)
    
    def run_bac_checks(self, host: str) -> Dict[str, Any]:
        """Run BAC checks."""
        return self.post("/run_bac_checks", {"host": host})
    
    def run_ssrf_checks(self, target: str, param: str = "url") -> Dict[str, Any]:
        """Run SSRF checks."""
        return self.post("/run_ssrf_checks", {"target": target, "param": param})


def wait_for_job_completion(
    client: MCPTestClient,
    job_id: str,
    max_wait: int = 60,
    poll_interval: int = 2
) -> Dict[str, Any]:
    """Poll job until completion.
    
    Args:
        client: MCPTestClient instance
        job_id: Job ID to poll
        max_wait: Maximum seconds to wait
        poll_interval: Seconds between polls
    
    Returns:
        Final job status
    
    Raises:
        TimeoutError: If job doesn't complete in time
    """
    import time
    
    start_time = time.time()
    while time.time() - start_time < max_wait:
        status = client.get(f"/job/{job_id}")
        job_status = status.get("status", "unknown")
        
        if job_status in ("finished", "failed", "error"):
            return status
        
        time.sleep(poll_interval)
    
    raise TimeoutError(f"Job {job_id} did not complete within {max_wait} seconds")


def setup_test_scope(client: MCPTestClient, targets: List[str]) -> Dict[str, Any]:
    """Setup test scope configuration.
    
    Args:
        client: MCPTestClient instance
        targets: List of target hosts
    
    Returns:
        Scope configuration
    """
    scope = {
        "program_name": "test-program",
        "primary_targets": targets,
        "secondary_targets": [],
        "rules": {},
    }
    return client.set_scope(scope)


def cleanup_test_artifacts(output_dir: Path, pattern: str = "*") -> None:
    """Cleanup test artifacts.
    
    Args:
        output_dir: Output directory to clean
        pattern: File pattern to match (default: all files)
    """
    import glob
    
    for file_path in glob.glob(str(output_dir / pattern)):
        try:
            Path(file_path).unlink()
        except Exception:
            pass

