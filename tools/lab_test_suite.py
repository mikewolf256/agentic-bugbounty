#!/usr/bin/env python3
"""Lab Test Suite - Comprehensive lab testing framework.

This module provides functions to test all labs and validate detection capabilities.
"""

import json
import os
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
LABS_DIR = REPO_ROOT / "labs"
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", str(REPO_ROOT / "output_scans")))


def list_all_labs() -> List[str]:
    """List all labs in the labs directory."""
    if not LABS_DIR.exists():
        return []
    return [
        d.name for d in LABS_DIR.iterdir()
        if d.is_dir() and (d / "lab_metadata.json").exists()
    ]


def list_new_labs() -> List[str]:
    """List only the 15 new labs created for new vulnerability testers."""
    new_labs = [
        "command_injection_lab",
        "path_traversal_lab",
        "file_upload_lab",
        "csrf_lab",
        "nosql_injection_lab",
        "ldap_injection_lab",
        "mass_assignment_lab",
        "websocket_lab",
        "ssi_injection_lab",
        "crypto_weakness_lab",
        "parameter_pollution_lab",
        "dns_rebinding_lab",
        "cache_poisoning_lab",
        "random_generation_lab",
    ]
    # Filter to only labs that actually exist
    return [lab for lab in new_labs if (LABS_DIR / lab / "lab_metadata.json").exists()]


def load_lab_metadata(lab_name: str) -> Dict[str, Any]:
    """Load lab metadata."""
    meta_path = LABS_DIR / lab_name / "lab_metadata.json"
    if not meta_path.exists():
        raise FileNotFoundError(f"lab_metadata.json not found for {lab_name}")
    return json.loads(meta_path.read_text(encoding="utf-8"))


def test_single_lab(
    lab_name: str,
    mcp_url: str = "http://127.0.0.1:8000",
    profile: Optional[str] = None,
    start_lab: bool = True,
    stop_lab: bool = True
) -> Dict[str, Any]:
    """Test a single lab and validate findings.
    
    Args:
        lab_name: Name of the lab to test
        mcp_url: MCP server URL
        profile: Optional scan profile to use
        start_lab: Whether to start the lab container
        stop_lab: Whether to stop the lab container after testing
        
    Returns:
        Test results dictionary with validation metrics
    """
    from tools.lab_runner import start_lab, stop_lab as stop_lab_func, run_scan, validate_findings, load_findings
    
    results = {
        "lab_name": lab_name,
        "timestamp": int(time.time()),
        "success": False,
        "error": None,
        "validation": None,
        "scan_result": None,
    }
    
    try:
        # Load expected findings
        meta = load_lab_metadata(lab_name)
        expected_findings = meta.get("expected_findings", [])
        base_url = meta.get("base_url", "http://localhost:8080")
        
        print(f"\n{'='*60}")
        print(f"Testing Lab: {lab_name}")
        print(f"Base URL: {base_url}")
        print(f"Expected Findings: {len(expected_findings)}")
        print(f"{'='*60}\n")
        
        # Start lab if requested
        if start_lab:
            print(f"[TEST] Starting lab: {lab_name}")
            start_lab(lab_name)
            time.sleep(3)  # Wait for lab to be ready
        
        # Run scan
        print(f"[TEST] Running scan against {lab_name}...")
        scan_result = run_scan(lab_name, profile=profile)
        results["scan_result"] = {
            "returncode": scan_result.get("returncode", -1),
            "stdout_length": len(scan_result.get("stdout", "")),
            "stderr_length": len(scan_result.get("stderr", "")),
        }
        
        if scan_result.get("returncode", -1) != 0:
            print(f"[TEST] Warning: Scan returned non-zero exit code")
        
        # Wait a bit for files to be written
        time.sleep(2)
        
        # Load and validate findings
        print(f"[TEST] Loading findings for validation...")
        findings = load_findings(lab_name)
        print(f"[TEST] Loaded {len(findings)} findings")
        
        # Validate findings
        validation = validate_findings(lab_name, findings)
        results["validation"] = validation
        results["success"] = True
        
        # Print summary
        print(f"\n[TEST] Validation Results for {lab_name}:")
        print(f"  Expected: {validation['total_expected']}")
        print(f"  Matched:  {len(validation['matched'])}")
        print(f"  Missed:   {len(validation['missed'])}")
        print(f"  Extra:    {len(validation['extra'])}")
        print(f"  Detection Rate: {validation['detection_rate']:.1%}")
        
        if validation['missed']:
            print(f"\n[TEST] Missed Findings:")
            for m in validation['missed']:
                print(f"  - {m.get('type', 'unknown')}: {m.get('description', 'N/A')}")
        
    except Exception as e:
        results["error"] = str(e)
        results["success"] = False
        print(f"[TEST] Error testing {lab_name}: {e}")
    
    finally:
        # Stop lab if requested
        if stop_lab:
            print(f"[TEST] Stopping lab: {lab_name}")
            try:
                stop_lab_func(lab_name)
            except Exception as e:
                print(f"[TEST] Warning: Failed to stop lab: {e}")
    
    return results


def test_all_labs(
    lab_names: Optional[List[str]] = None,
    mcp_url: str = "http://127.0.0.1:8000",
    profile: Optional[str] = None,
    parallel: bool = False
) -> Dict[str, Any]:
    """Test multiple labs and generate aggregated report.
    
    Args:
        lab_names: List of lab names to test (None = test all labs)
        mcp_url: MCP server URL
        profile: Optional scan profile to use
        parallel: Whether to run tests in parallel (not yet implemented)
        
    Returns:
        Aggregated test results
    """
    if lab_names is None:
        lab_names = list_all_labs()
    
    print(f"\n{'='*60}")
    print(f"Lab Test Suite")
    print(f"Testing {len(lab_names)} labs")
    print(f"{'='*60}\n")
    
    results = {
        "timestamp": int(time.time()),
        "labs_tested": len(lab_names),
        "labs_passed": 0,
        "labs_failed": 0,
        "total_expected": 0,
        "total_matched": 0,
        "total_missed": 0,
        "overall_detection_rate": 0.0,
        "lab_results": {},
    }
    
    for lab_name in lab_names:
        try:
            lab_result = test_single_lab(lab_name, mcp_url=mcp_url, profile=profile)
            results["lab_results"][lab_name] = lab_result
            
            if lab_result["success"]:
                results["labs_passed"] += 1
                validation = lab_result.get("validation", {})
                results["total_expected"] += validation.get("total_expected", 0)
                results["total_matched"] += len(validation.get("matched", []))
                results["total_missed"] += len(validation.get("missed", []))
            else:
                results["labs_failed"] += 1
        except Exception as e:
            print(f"[TEST] Failed to test {lab_name}: {e}")
            results["labs_failed"] += 1
            results["lab_results"][lab_name] = {
                "lab_name": lab_name,
                "success": False,
                "error": str(e)
            }
    
    # Calculate overall detection rate
    if results["total_expected"] > 0:
        results["overall_detection_rate"] = results["total_matched"] / results["total_expected"]
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Test Suite Summary")
    print(f"{'='*60}")
    print(f"Labs Tested: {results['labs_tested']}")
    print(f"Labs Passed: {results['labs_passed']}")
    print(f"Labs Failed: {results['labs_failed']}")
    print(f"Total Expected Findings: {results['total_expected']}")
    print(f"Total Matched: {results['total_matched']}")
    print(f"Total Missed: {results['total_missed']}")
    print(f"Overall Detection Rate: {results['overall_detection_rate']:.1%}")
    print(f"{'='*60}\n")
    
    # Save results
    OUTPUT_DIR.mkdir(exist_ok=True)
    results_file = OUTPUT_DIR / f"lab_test_suite_results_{int(time.time())}.json"
    results_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"[TEST] Results saved to: {results_file}")
    
    return results

