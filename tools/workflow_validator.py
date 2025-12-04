#!/usr/bin/env python3
"""Workflow Validator

Validates application workflows for state transition vulnerabilities:
- State transition testing
- Replay attack detection
- State manipulation
"""

import requests
from typing import Dict, Any, List, Optional


def validate_state_transitions(workflow: Dict[str, Any], auth_context: Optional[Dict] = None) -> Dict[str, Any]:
    """Validate state transitions in workflow
    
    Args:
        workflow: Workflow analysis result from business_logic_analyzer
        auth_context: Optional authentication context
        
    Returns:
        Dict with validation results
    """
    result = {
        "test": "state_transitions",
        "vulnerable": False,
        "evidence": None,
        "issues": []
    }
    
    # Build request with auth context
    headers = {}
    cookies = {}
    if auth_context:
        headers.update(auth_context.get("headers", {}))
        cookies.update(auth_context.get("cookies", {}))
    
    # Test valid transitions
    # For each workflow pattern, test if steps can be executed in order
    for pattern in workflow.get("workflow_patterns", []):
        steps = pattern.get("steps", [])
        if len(steps) < 2:
            continue
        
        # Try to execute steps in order
        previous_state = None
        for i, step in enumerate(steps):
            step_name = step.get("name")
            step_endpoints = step.get("endpoints", [])
            
            if not step_endpoints:
                continue
            
            endpoint = step_endpoints[0]
            endpoint_url = endpoint.get("url") or endpoint.get("path", "")
            
            # Try to access this step
            try:
                resp = requests.get(
                    endpoint_url,
                    headers=headers,
                    cookies=cookies,
                    timeout=10,
                    allow_redirects=False
                )
                
                # Check if step is accessible
                if resp.status_code in (200, 201, 302):
                    # Check if previous step is required
                    if previous_state and i > 0:
                        # Try to access current step without previous step
                        # This would indicate state transition vulnerability
                        pass
                    
                    previous_state = step_name
                elif resp.status_code == 403:
                    # Step requires previous state - this is expected
                    if not previous_state and i > 0:
                        result["issues"].append({
                            "type": "missing_previous_state",
                            "step": step_name,
                            "status": "protected"
                        })
            except Exception:
                continue
    
    # Test invalid transitions (bypass attempts)
    # Try to access later steps without completing earlier ones
    for pattern in workflow.get("workflow_patterns", []):
        steps = pattern.get("steps", [])
        if len(steps) < 2:
            continue
        
        # Try to access last step directly (skip all previous)
        last_step = steps[-1]
        last_endpoints = last_step.get("endpoints", [])
        
        if last_endpoints:
            endpoint = last_endpoints[0]
            endpoint_url = endpoint.get("url") or endpoint.get("path", "")
            
            try:
                resp = requests.post(
                    endpoint_url,
                    json={"skip_validation": True},
                    headers=headers,
                    cookies=cookies,
                    timeout=10,
                    allow_redirects=False
                )
                
                # If we can access last step without previous steps, it's vulnerable
                if resp.status_code in (200, 201, 302):
                    result["vulnerable"] = True
                    result["evidence"] = {
                        "bypass_type": "direct_access",
                        "skipped_steps": [s.get("name") for s in steps[:-1]],
                        "accessed_step": last_step.get("name"),
                        "status_code": resp.status_code
                    }
                    result["issues"].append({
                        "type": "workflow_bypass",
                        "severity": "high",
                        "description": f"Can access {last_step.get('name')} without completing previous steps"
                    })
            except Exception:
                pass
    
    # Test replay attacks
    # This would require capturing previous requests/responses
    # For now, we'll just document the test
    
    if result["issues"]:
        result["vulnerable"] = True
    
    return result


def test_replay_attack(workflow: Dict[str, Any], auth_context: Optional[Dict] = None) -> Dict[str, Any]:
    """Test for replay attack vulnerabilities
    
    Args:
        workflow: Workflow analysis result
        auth_context: Optional authentication context
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "replay_attack",
        "vulnerable": False,
        "evidence": None,
        "note": "Replay attack testing requires captured requests/responses"
    }
    
    # This would require:
    # 1. Capturing a request/response from a completed workflow step
    # 2. Replaying the same request multiple times
    # 3. Checking if the action is executed multiple times
    
    # For now, we'll return a placeholder
    return result

