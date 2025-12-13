#!/usr/bin/env python3
"""Validate all 15 new labs - Direct validation without starting/stopping labs.

This script tests labs that are already running in docker-compose.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Any, List

# Add tools to path
REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

import requests
from tools.lab_scope_helper import configure_lab_scope
from tools.vulnerability_tester_orchestrator import run_targeted_vulnerability_tests
from tools.lab_test_suite import load_lab_metadata, list_new_labs

MCP_URL = os.environ.get("MCP_URL", "http://127.0.0.1:8000")
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", str(REPO_ROOT / "output_scans")))


def check_lab_reachable(lab_name: str) -> bool:
    """Check if lab is reachable."""
    try:
        meta = load_lab_metadata(lab_name)
        base_url = meta.get("base_url", "http://localhost:8080")
        
        # Convert Docker service names to localhost URLs
        lab_port_map = {
            "command_injection_lab": 5013,
            "path_traversal_lab": 5014,
            "file_upload_lab": 5015,
            "csrf_lab": 5016,
            "nosql_injection_lab": 5017,
            "ldap_injection_lab": 5018,
            "mass_assignment_lab": 5019,
            "websocket_lab": 5020,
            "ssi_injection_lab": 5022,
            "crypto_weakness_lab": 5023,
            "parameter_pollution_lab": 5024,
            "dns_rebinding_lab": 5025,
            "cache_poisoning_lab": 5026,
            "random_generation_lab": 5027,
        }
        
        if lab_name in lab_port_map and ("_lab:5000" in base_url or not base_url.startswith("http://localhost")):
            port = lab_port_map[lab_name]
            base_url = f"http://localhost:{port}"
        
        resp = requests.get(base_url, timeout=5)
        return resp.status_code < 500
    except Exception:
        return False


def validate_single_lab(lab_name: str) -> Dict[str, Any]:
    """Validate a single lab by running targeted vulnerability tests."""
    results = {
        "lab_name": lab_name,
        "timestamp": int(time.time()),
        "success": False,
        "error": None,
        "validation": None,
    }
    
    try:
        # Load lab metadata
        meta = load_lab_metadata(lab_name)
        base_url = meta.get("base_url", "http://localhost:8080")
        expected_findings = meta.get("expected_findings", [])
        
        # Convert Docker service names to localhost URLs for external access
        # Map lab names to ports (from docker-compose.yml)
        lab_port_map = {
            "command_injection_lab": 5013,
            "path_traversal_lab": 5014,
            "file_upload_lab": 5015,
            "csrf_lab": 5016,
            "nosql_injection_lab": 5017,
            "ldap_injection_lab": 5018,
            "mass_assignment_lab": 5019,
            "websocket_lab": 5020,
            "ssi_injection_lab": 5022,
            "crypto_weakness_lab": 5023,
            "parameter_pollution_lab": 5024,
            "dns_rebinding_lab": 5025,
            "cache_poisoning_lab": 5026,
            "random_generation_lab": 5027,
        }
        
        # If base_url uses Docker service name, convert to localhost
        if lab_name in lab_port_map and ("_lab:5000" in base_url or base_url.startswith("http://") and ":" not in base_url.split("//")[1].split("/")[0]):
            port = lab_port_map[lab_name]
            base_url = f"http://localhost:{port}"
        
        print(f"\n{'='*60}")
        print(f"Validating Lab: {lab_name}")
        print(f"Base URL: {base_url}")
        print(f"Expected Findings: {len(expected_findings)}")
        print(f"{'='*60}\n")
        
        # Check if lab is reachable
        if not check_lab_reachable(lab_name):
            # Try with converted URL
            try:
                resp = requests.get(base_url, timeout=5)
                if resp.status_code >= 500:
                    results["error"] = f"Lab not reachable at {base_url}"
                    print(f"[VALIDATE] ⚠️  Lab not reachable, skipping")
                    return results
            except Exception:
                results["error"] = f"Lab not reachable at {base_url}"
                print(f"[VALIDATE] ⚠️  Lab not reachable, skipping")
                return results
        
        # Configure scope with both localhost and Docker service names
        print(f"[VALIDATE] Configuring scope...")
        try:
            # Build comprehensive scope with all URL variants
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            host = parsed.netloc or parsed.path.split("/")[0]
            
            # Get port from lab_port_map
            port = lab_port_map.get(lab_name, 8080)
            localhost_url = f"http://localhost:{port}"
            docker_url = f"http://{lab_name}:5000"
            
            # Create scope with all URL variants
            scope = {
                "program_name": f"lab-{lab_name}",
                "primary_targets": [localhost_url, docker_url, base_url],
                "secondary_targets": [],
                "rules": {
                    "rate_limit": 100,
                    "excluded_vuln_types": [],
                    "requires_poc": False,
                },
                "in_scope": [
                    {"url": localhost_url},
                    {"url": docker_url},
                    {"url": base_url},
                    {"url": host},  # Just hostname
                    {"url": f"localhost:{port}"},  # hostname:port
                    {"url": f"{lab_name}:5000"},  # Docker service:port
                ],
            }
            
            # Set scope via MCP
            resp = requests.post(f"{MCP_URL}/mcp/set_scope", json=scope, timeout=10)
            resp.raise_for_status()
            print(f"[VALIDATE] ✅ Scope configured with {len(scope['in_scope'])} URLs")
        except Exception as e:
            print(f"[VALIDATE] ⚠️  Scope configuration failed: {e}")
            import traceback
            traceback.print_exc()
            # Continue anyway - scope may already be set
        
        # Extract host from base_url
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        host = parsed.netloc or parsed.path.split("/")[0]
        
        # Discover URLs from multiple sources
        discovered_urls = [base_url]
        
        # Source 1: Use endpoints from lab_metadata.json
        lab_endpoints = meta.get("endpoints", [])
        for ep in lab_endpoints:
            ep_path = ep.get("path", "")
            if ep_path and ep_path != "/":
                # Build full URL
                full_url = f"{base_url.rstrip('/')}{ep_path}"
                if full_url not in discovered_urls:
                    discovered_urls.append(full_url)
        
        # Source 2: Run Katana discovery to find additional endpoints
        print(f"[VALIDATE] Running Katana discovery to find endpoints...")
        try:
            katana_result = requests.post(
                f"{MCP_URL}/mcp/run_katana_nuclei",
                json={
                    "target": base_url,
                    "mode": "recon",
                    "output_name": f"katana_{lab_name}_{int(time.time())}.json"
                },
                timeout=300
            )
            if katana_result.status_code == 200:
                katana_data = katana_result.json()
                katana_urls = katana_data.get("katana", {}).get("all_urls", []) if isinstance(katana_data.get("katana"), dict) else []
                if katana_urls:
                    print(f"[VALIDATE] Katana discovered {len(katana_urls)} URLs")
                    # Add discovered URLs (deduplicate)
                    for url in katana_urls:
                        if url and url not in discovered_urls:
                            discovered_urls.append(url)
                else:
                    print(f"[VALIDATE] Katana found no additional URLs")
            else:
                print(f"[VALIDATE] ⚠️  Katana discovery failed: {katana_result.status_code}")
        except Exception as e:
            print(f"[VALIDATE] ⚠️  Katana discovery error: {e}")
            # Continue with endpoints from metadata
        
        print(f"[VALIDATE] Total discovered URLs: {len(discovered_urls)}")
        if len(discovered_urls) > 1:
            print(f"[VALIDATE] Sample URLs: {discovered_urls[:5]}")
        
        # Run targeted vulnerability tests
        print(f"[VALIDATE] Running targeted vulnerability tests...")
        profile = {
            "targeted_vuln_tests": {
                "enabled": True,
                "use_callback": False
            },
            "name": "full"
        }
        
        # Run targeted vulnerability tests with discovered URLs
        test_results = run_targeted_vulnerability_tests(
            host=host,
            discovered_urls=discovered_urls,
            profile=profile,
            use_callback=False
        )
        
        # Validate findings
        detected_findings = test_results.get("findings", [])
        matched = []
        missed = []
        
        for exp in expected_findings:
            exp_endpoint = exp.get("endpoint", "")
            exp_param = exp.get("parameter", "")
            found = False
            
            for finding in detected_findings:
                target_url = finding.get("target_url", "")
                injection_point = finding.get("injection_point", "")
                
                # Match by endpoint and parameter
                if exp_endpoint in target_url and (not exp_param or exp_param in str(injection_point)):
                    matched.append(exp)
                    found = True
                    break
            
            if not found:
                missed.append(exp)
        
        # Calculate detection rate
        total_expected = len(expected_findings)
        total_matched = len(matched)
        detection_rate = (total_matched / total_expected) if total_expected > 0 else 0.0
        
        results["validation"] = {
            "total_expected": total_expected,
            "total_matched": total_matched,
            "total_missed": len(missed),
            "detection_rate": detection_rate,
            "matched": matched,
            "missed": missed,
            "detected_findings": detected_findings,
        }
        results["success"] = True
        
        # Print summary
        print(f"\n[VALIDATE] Results for {lab_name}:")
        print(f"  Expected: {total_expected}")
        print(f"  Matched:  {total_matched}")
        print(f"  Missed:   {len(missed)}")
        print(f"  Detection Rate: {detection_rate:.1%}")
        
        if missed:
            print(f"\n[VALIDATE] Missed Findings:")
            for m in missed:
                print(f"  - {m.get('type', 'unknown')}: {m.get('description', 'N/A')} at {m.get('endpoint', 'N/A')}")
        
    except Exception as e:
        results["error"] = str(e)
        results["success"] = False
        print(f"[VALIDATE] Error validating {lab_name}: {e}")
        import traceback
        traceback.print_exc()
    
    return results


def main():
    """Main validation function."""
    lab_names = list_new_labs()
    
    if not lab_names:
        print("[VALIDATE] No new labs found")
        return 1
    
    print(f"\n{'='*60}")
    print(f"Lab Validation Suite")
    print(f"Validating {len(lab_names)} labs")
    print(f"MCP URL: {MCP_URL}")
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
        lab_result = validate_single_lab(lab_name)
        results["lab_results"][lab_name] = lab_result
        
        if lab_result["success"]:
            results["labs_passed"] += 1
            validation = lab_result.get("validation", {})
            results["total_expected"] += validation.get("total_expected", 0)
            results["total_matched"] += validation.get("total_matched", 0)
            results["total_missed"] += validation.get("total_missed", 0)
        else:
            results["labs_failed"] += 1
    
    # Calculate overall detection rate
    if results["total_expected"] > 0:
        results["overall_detection_rate"] = results["total_matched"] / results["total_expected"]
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Validation Summary")
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
    OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
    results_file = OUTPUT_DIR / f"lab_validation_results_{int(time.time())}.json"
    results_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"[VALIDATE] Results saved to: {results_file}")
    
    # Update LAB_TEST_VALIDATION_REPORT.md
    update_validation_report(results)
    
    return 0 if results["overall_detection_rate"] >= 0.5 else 1


def update_validation_report(results: Dict[str, Any]) -> None:
    """Update LAB_TEST_VALIDATION_REPORT.md with validation results."""
    report_path = REPO_ROOT / "LAB_TEST_VALIDATION_REPORT.md"
    
    if not report_path.exists():
        print(f"[VALIDATE] Warning: {report_path} not found, skipping report update")
        return
    
    # Read current report
    content = report_path.read_text(encoding="utf-8")
    
    # Find the section to update (after "### Test Results: Command Injection Lab")
    # We'll add a new comprehensive validation section
    
    new_section = f"""
## Comprehensive Lab Validation Results

**Validation Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}

### Overall Summary
- **Labs Tested**: {results['labs_tested']}
- **Labs Passed**: {results['labs_passed']}
- **Labs Failed**: {results['labs_failed']}
- **Total Expected Findings**: {results['total_expected']}
- **Total Matched**: {results['total_matched']}
- **Total Missed**: {results['total_missed']}
- **Overall Detection Rate**: {results['overall_detection_rate']:.1%}

### Per-Lab Results

"""
    
    for lab_name, lab_result in results["lab_results"].items():
        if lab_result.get("success"):
            validation = lab_result.get("validation", {})
            detection_rate = validation.get("detection_rate", 0.0)
            status = "✅" if detection_rate >= 0.5 else "⚠️"
            
            new_section += f"""
#### {status} {lab_name}
- **Detection Rate**: {detection_rate:.1%}
- **Expected**: {validation.get('total_expected', 0)}
- **Matched**: {validation.get('total_matched', 0)}
- **Missed**: {validation.get('total_missed', 0)}
"""
            
            if validation.get("missed"):
                new_section += "\n**Missed Findings:**\n"
                for m in validation["missed"]:
                    new_section += f"- {m.get('type', 'unknown')}: {m.get('description', 'N/A')} at {m.get('endpoint', 'N/A')}\n"
        else:
            new_section += f"""
#### ❌ {lab_name}
- **Error**: {lab_result.get('error', 'Unknown error')}
"""
    
    # Append to report (before "## Known Vulnerabilities with Tools")
    if "## Known Vulnerabilities with Tools" in content:
        content = content.replace(
            "## Known Vulnerabilities with Tools",
            new_section + "\n## Known Vulnerabilities with Tools"
        )
    else:
        content += new_section
    
    report_path.write_text(content, encoding="utf-8")
    print(f"[VALIDATE] Updated {report_path}")


if __name__ == "__main__":
    sys.exit(main())

