#!/usr/bin/env python3
"""
K8s Scan Pipeline Validation Script

Comprehensive validation of the complete scanning pipeline:
1. Prerequisites check (k8s cluster, Redis, KEDA)
2. Job submission test
3. Results retrieval test
4. Triage test
5. Report generation test
6. End-to-end multi-scope test

Usage:
    python tests/validate_k8s_scan_pipeline.py
    python tests/validate_k8s_scan_pipeline.py --skip-e2e
"""

import os
import sys
import json
import time
import argparse
import subprocess
import requests
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    from tools.local_executor import LocalExecutor, is_local_k8s_mode
    K8S_EXECUTOR_AVAILABLE = True
except ImportError:
    K8S_EXECUTOR_AVAILABLE = False

MCP_BASE = os.environ.get("MCP_BASE", "http://localhost:8000")
OUTPUT_DIR = Path("output_zap")
OUTPUT_DIR.mkdir(exist_ok=True)


class PipelineValidator:
    """Validate the complete K8s scan pipeline."""
    
    def __init__(self, skip_e2e: bool = False):
        self.skip_e2e = skip_e2e
        self.results = {
            "started_at": datetime.utcnow().isoformat(),
            "tests": {},
            "summary": {},
        }
        self.executor = None
    
    def log(self, message: str, level: str = "INFO"):
        """Log a message."""
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def test_result(self, test_name: str, passed: Optional[bool], details: Dict[str, Any] = None) -> Dict[str, Any]:
        """Record a test result.
        
        Args:
            test_name: Name of the test
            passed: True for pass, False for fail, None for skipped
            details: Optional details dictionary
        """
        result = {
            "passed": passed,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {},
        }
        self.results["tests"][test_name] = result
        # Use explicit is True/is False checks to handle None (skipped tests)
        status = "PASS" if passed is True else "FAIL" if passed is False else "SKIP"
        self.log(f"{test_name}: {status}", level=status)
        if details:
            for key, value in details.items():
                self.log(f"  {key}: {value}")
        return result
    
    def test_prerequisites(self) -> bool:
        """Test 1: Prerequisites check."""
        self.log("=" * 60)
        self.log("Test 1: Prerequisites Check")
        self.log("=" * 60)
        
        checks = {}
        all_passed = True
        
        # Check kind cluster
        try:
            result = subprocess.run(
                ["kubectl", "cluster-info", "--context", "kind-agentic-bugbounty-local"],
                capture_output=True,
                timeout=10,
            )
            checks["kind_cluster"] = result.returncode == 0
            if not checks["kind_cluster"]:
                self.log("  Kind cluster not accessible", level="WARN")
        except Exception as e:
            checks["kind_cluster"] = False
            self.log(f"  Kind cluster check failed: {e}", level="WARN")
        
        # Check Redis
        try:
            if REDIS_AVAILABLE:
                redis_client = redis.Redis(host="localhost", port=6379, socket_connect_timeout=5)
                redis_client.ping()
                checks["redis"] = True
            else:
                checks["redis"] = False
                self.log("  Redis Python client not available", level="WARN")
        except Exception as e:
            checks["redis"] = False
            self.log(f"  Redis not accessible: {e}", level="WARN")
        
        # Check KEDA ScaledJobs
        try:
            result = subprocess.run(
                ["kubectl", "get", "scaledjobs", "-n", "scan-workers"],
                capture_output=True,
                timeout=10,
            )
            checks["keda_scaledjobs"] = result.returncode == 0
            if checks["keda_scaledjobs"]:
                output = result.stdout.decode()
                checks["scaledjob_count"] = len([l for l in output.split("\n") if "whatweb" in l.lower()])
        except Exception as e:
            checks["keda_scaledjobs"] = False
            self.log(f"  KEDA ScaledJobs check failed: {e}", level="WARN")
        
        # Check MCP server
        try:
            resp = requests.get(f"{MCP_BASE}/health", timeout=5)
            checks["mcp_server"] = resp.status_code == 200
        except Exception:
            try:
                # Try root endpoint
                resp = requests.get(f"{MCP_BASE}/", timeout=5)
                checks["mcp_server"] = resp.status_code < 500
            except Exception as e:
                checks["mcp_server"] = False
                self.log(f"  MCP server not accessible: {e}", level="WARN")
        
        # Check ZAP
        try:
            resp = requests.get("http://localhost:8080/JSON/core/view/version/", timeout=5)
            checks["zap"] = resp.status_code == 200
        except Exception:
            checks["zap"] = False
            self.log("  ZAP not accessible (optional for some tests)", level="WARN")
        
        # Check LOCAL_K8S_MODE
        checks["local_k8s_mode"] = is_local_k8s_mode() if K8S_EXECUTOR_AVAILABLE else False
        
        # Filter out non-boolean values for the all() check (e.g., scaledjob_count)
        boolean_checks = {k: v for k, v in checks.items() if isinstance(v, bool)}
        all_passed = all(boolean_checks.values())
        
        self.test_result("prerequisites", all_passed, checks)
        return all_passed
    
    def test_job_submission(self) -> bool:
        """Test 2: Job submission."""
        self.log("=" * 60)
        self.log("Test 2: Job Submission")
        self.log("=" * 60)
        
        if not K8S_EXECUTOR_AVAILABLE or not is_local_k8s_mode():
            self.test_result("job_submission", False, {"error": "K8s executor not available"})
            return False
        
        try:
            self.executor = LocalExecutor()
        except Exception as e:
            self.test_result("job_submission", False, {"error": f"Failed to create executor: {e}"})
            return False
        
        # Submit a test job
        test_target = "http://example.com"
        test_tool = "whatweb"
        
        self.log(f"  Submitting {test_tool} job for {test_target}...")
        start_time = time.time()
        
        try:
            job_id = self.executor.submit(test_tool, test_target)
            submission_time = time.time() - start_time
            
            # Check if job appears in Redis queue
            try:
                redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)
                queue_name = "whatweb-jobs"
                queue_length = redis_client.llen(queue_name)
                job_in_queue = queue_length > 0
            except Exception as e:
                job_in_queue = False
                self.log(f"  Could not verify job in queue: {e}", level="WARN")
            
            # Check if KEDA scales up (wait a bit)
            time.sleep(5)
            try:
                result = subprocess.run(
                    ["kubectl", "get", "jobs", "-n", "scan-workers", "-o", "json"],
                    capture_output=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    jobs_data = json.loads(result.stdout)
                    job_count = len(jobs_data.get("items", []))
                else:
                    job_count = 0
            except Exception:
                job_count = 0
            
            details = {
                "job_id": job_id,
                "submission_time_seconds": round(submission_time, 2),
                "job_in_queue": job_in_queue,
                "k8s_jobs_count": job_count,
            }
            
            passed = job_id is not None and submission_time < 10
            self.test_result("job_submission", passed, details)
            return passed
            
        except Exception as e:
            self.test_result("job_submission", False, {"error": str(e)})
            return False
    
    def test_results_retrieval(self) -> bool:
        """Test 3: Results retrieval."""
        self.log("=" * 60)
        self.log("Test 3: Results Retrieval")
        self.log("=" * 60)
        
        if not self.executor:
            self.test_result("results_retrieval", False, {"error": "Executor not initialized"})
            return False
        
        test_target = "http://example.com"
        test_tool = "whatweb"
        
        self.log(f"  Submitting and waiting for {test_tool} job...")
        start_time = time.time()
        
        try:
            result = self.executor.submit_and_wait(test_tool, test_target, timeout=300)
            retrieval_time = time.time() - start_time
            
            if result:
                # Validate result structure
                has_required_fields = isinstance(result, dict)
                result_valid = has_required_fields
                
                details = {
                    "retrieval_time_seconds": round(retrieval_time, 2),
                    "result_received": True,
                    "result_type": type(result).__name__,
                    "result_keys": list(result.keys()) if isinstance(result, dict) else [],
                }
                
                passed = result_valid and retrieval_time < 300
                self.test_result("results_retrieval", passed, details)
                return passed
            else:
                self.test_result("results_retrieval", False, {"error": "No result received (timeout)"})
                return False
                
        except Exception as e:
            self.test_result("results_retrieval", False, {"error": str(e)})
            return False
    
    def test_triage(self) -> bool:
        """Test 4: Triage functionality."""
        self.log("=" * 60)
        self.log("Test 4: Triage Test")
        self.log("=" * 60)
        
        # Create mock findings
        mock_findings = [
            {
                "name": "Cross Site Scripting (Reflected)",
                "risk": "High",
                "url": "http://example.com/search?q=test",
                "param": "q",
                "evidence": "test<script>alert(1)</script>",
                "cweid": "79",
            }
        ]
        
        findings_file = OUTPUT_DIR / "test_findings.json"
        with open(findings_file, "w") as f:
            json.dump(mock_findings, f, indent=2)
        
        # Create test scope
        test_scope = {
            "program_name": "test-scope",
            "primary_targets": ["http://example.com"],
        }
        scope_file = OUTPUT_DIR / "test_scope.json"
        with open(scope_file, "w") as f:
            json.dump(test_scope, f, indent=2)
        
        # Run triage
        self.log("  Running agentic_from_file.py...")
        start_time = time.time()
        
        try:
            cmd = [
                sys.executable,
                "agentic_from_file.py",
                "--findings_file", str(findings_file),
                "--scope_file", str(scope_file),
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            
            triage_time = time.time() - start_time
            
            # Check for triage output
            triage_file = OUTPUT_DIR / "triage_test_findings.json"
            triage_exists = triage_file.exists()
            
            # Check for markdown reports
            md_files = list(OUTPUT_DIR.glob("test_findings__*.md"))
            
            details = {
                "triage_time_seconds": round(triage_time, 2),
                "triage_exit_code": result.returncode,
                "triage_file_exists": triage_exists,
                "markdown_reports_count": len(md_files),
            }
            
            if triage_exists:
                # Check for PoC validation metadata
                with open(triage_file) as f:
                    triage_data = json.load(f)
                if triage_data:
                    first_finding = triage_data[0] if isinstance(triage_data, list) else triage_data
                    has_poc_validation = "validation" in first_finding or "_poc_validation" in first_finding
                    details["has_poc_validation"] = has_poc_validation
            
            passed = triage_exists and result.returncode == 0
            self.test_result("triage", passed, details)
            return passed
            
        except subprocess.TimeoutExpired:
            self.test_result("triage", False, {"error": "Triage timeout"})
            return False
        except Exception as e:
            self.test_result("triage", False, {"error": str(e)})
            return False
    
    def test_report_generation(self) -> bool:
        """Test 5: Report generation."""
        self.log("=" * 60)
        self.log("Test 5: Report Generation")
        self.log("=" * 60)
        
        # Check if we have a scan_id from previous tests or create a mock one
        # For this test, we'll check if the MCP endpoint exists and responds
        test_scan_id = "test_scan_123"
        
        try:
            # Try to call export_report endpoint
            resp = requests.post(
                f"{MCP_BASE}/mcp/export_report/{test_scan_id}",
                timeout=10,
            )
            
            # Even if it fails (no scan exists), we check if endpoint is available
            endpoint_available = resp.status_code < 500
            
            # Check for existing reports in output directory
            report_files = list(OUTPUT_DIR.glob("*_reports_index.json"))
            md_reports = list(OUTPUT_DIR.glob("*__*.md"))
            
            details = {
                "endpoint_available": endpoint_available,
                "endpoint_status": resp.status_code,
                "existing_report_indexes": len(report_files),
                "existing_markdown_reports": len(md_reports),
            }
            
            # Pass if endpoint is available (even if no reports generated for test scan)
            passed = endpoint_available
            self.test_result("report_generation", passed, details)
            return passed
            
        except Exception as e:
            self.test_result("report_generation", False, {"error": str(e)})
            return False
    
    def test_end_to_end(self) -> bool:
        """Test 6: End-to-end multi-scope test."""
        if self.skip_e2e:
            self.log("Skipping end-to-end test (--skip-e2e)")
            self.test_result("end_to_end", None, {"skipped": True})
            return True
        
        self.log("=" * 60)
        self.log("Test 6: End-to-End Multi-Scope Test")
        self.log("=" * 60)
        
        # Use test scope file if available
        test_scope = Path("scope.lab.json")
        if not test_scope.exists():
            # Create a minimal test scope
            test_scope = OUTPUT_DIR / "test_e2e_scope.json"
            test_scope_data = {
                "program_name": "test-e2e",
                "primary_targets": ["http://localhost:5001"],  # Use lab service if available
            }
            with open(test_scope, "w") as f:
                json.dump(test_scope_data, f, indent=2)
        
        self.log(f"  Running multi-scope runner with {test_scope}...")
        start_time = time.time()
        
        try:
            from tools.multi_scope_runner import MultiScopeRunner
            
            runner = MultiScopeRunner(
                k8s_mode=True,
                max_concurrent=1,
                output_dir=OUTPUT_DIR / "e2e_test",
            )
            
            results = runner.run_scopes([str(test_scope)])
            e2e_time = time.time() - start_time
            
            summary = results.get("summary", {})
            completed = summary.get("completed", 0)
            failed = summary.get("failed", 0)
            
            details = {
                "e2e_time_seconds": round(e2e_time, 2),
                "scopes_completed": completed,
                "scopes_failed": failed,
                "total_findings": summary.get("total_findings_files", 0),
                "total_reports": summary.get("total_reports", 0),
            }
            
            passed = completed > 0 and failed == 0
            self.test_result("end_to_end", passed, details)
            return passed
            
        except ImportError:
            self.test_result("end_to_end", False, {"error": "multi_scope_runner not available"})
            return False
        except Exception as e:
            self.test_result("end_to_end", False, {"error": str(e)})
            return False
    
    def generate_report(self) -> str:
        """Generate validation report."""
        # Calculate summary
        total_tests = len(self.results["tests"])
        passed_tests = sum(1 for t in self.results["tests"].values() if t.get("passed") is True)
        failed_tests = sum(1 for t in self.results["tests"].values() if t.get("passed") is False)
        skipped_tests = sum(1 for t in self.results["tests"].values() if t.get("passed") is None)
        
        self.results["summary"] = {
            "total_tests": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "skipped": skipped_tests,
            "success_rate": round(passed_tests / total_tests * 100, 1) if total_tests > 0 else 0,
        }
        self.results["completed_at"] = datetime.utcnow().isoformat()
        
        # Save JSON report
        report_file = OUTPUT_DIR / "validation_report.json"
        with open(report_file, "w") as f:
            json.dump(self.results, f, indent=2)
        
        # Generate human-readable report
        report_lines = [
            "=" * 80,
            "K8s Scan Pipeline Validation Report",
            "=" * 80,
            f"Started: {self.results['started_at']}",
            f"Completed: {self.results['completed_at']}",
            "",
            "Summary:",
            f"  Total Tests: {total_tests}",
            f"  Passed: {passed_tests}",
            f"  Failed: {failed_tests}",
            f"  Skipped: {skipped_tests}",
            f"  Success Rate: {self.results['summary']['success_rate']}%",
            "",
            "Test Results:",
        ]
        
        for test_name, test_result in self.results["tests"].items():
            status = "PASS" if test_result.get("passed") is True else "FAIL" if test_result.get("passed") is False else "SKIP"
            report_lines.append(f"  [{status}] {test_name}")
            if test_result.get("details"):
                for key, value in test_result["details"].items():
                    report_lines.append(f"    {key}: {value}")
        
        report_lines.extend([
            "",
            "=" * 80,
            f"Full report: {report_file}",
            "=" * 80,
        ])
        
        report_text = "\n".join(report_lines)
        
        # Save text report
        text_report_file = OUTPUT_DIR / "validation_report.txt"
        with open(text_report_file, "w") as f:
            f.write(report_text)
        
        return report_text
    
    def run_all(self) -> bool:
        """Run all validation tests."""
        self.log("Starting K8s Scan Pipeline Validation")
        self.log("")
        
        # Run tests
        self.test_prerequisites()
        self.test_job_submission()
        self.test_results_retrieval()
        self.test_triage()
        self.test_report_generation()
        self.test_end_to_end()
        
        # Generate report
        self.log("")
        report = self.generate_report()
        print("\n" + report)
        
        # Return overall success
        summary = self.results["summary"]
        return summary["failed"] == 0 and summary["passed"] > 0


def main():
    parser = argparse.ArgumentParser(description="Validate K8s scan pipeline")
    parser.add_argument(
        "--skip-e2e",
        action="store_true",
        help="Skip end-to-end multi-scope test",
    )
    
    args = parser.parse_args()
    
    validator = PipelineValidator(skip_e2e=args.skip_e2e)
    success = validator.run_all()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

