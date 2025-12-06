#!/usr/bin/env python3
"""Program Configuration Generator

Auto-generates program-specific configuration files from HackerOne scope imports.
"""

import os
import json
from typing import Dict, Any, Optional
from pathlib import Path


def generate_program_config(
    program_handle: str,
    h1_program: Any,  # H1Program object
    scope_data: Dict[str, Any],
) -> str:
    """Generate program configuration file from HackerOne program data.
    
    Args:
        program_handle: Program handle/identifier
        h1_program: H1Program object from h1_client
        scope_data: Scope JSON data
        
    Returns:
        Path to generated config file
    """
    config_dir = Path("scopes")
    config_dir.mkdir(exist_ok=True)
    
    config_file = config_dir / f"{program_handle}_config.json"
    
    # Extract configuration from H1 program and scope
    rules = scope_data.get("rules", {})
    
    config = {
        "program_name": program_handle,
        "program_display_name": getattr(h1_program, "name", program_handle),
        "enabled": True,
        
        # Scan scheduling
        "scan_frequency": "daily",  # Default, can be overridden
        "scan_time": "02:00",  # Default 2 AM
        "scan_day": "monday",  # For weekly scans
        
        # Alerting configuration
        "alerting": {
            "channels": ["slack"],  # Default to Slack
            "email_recipients": [],
            "alert_on_critical": True,
            "alert_on_high": True,
            "alert_on_scan_complete": True,
        },
        
        # Program rules from scope
        "rules": {
            "excluded_vuln_types": rules.get("excluded_vuln_types", []),
            "requires_poc": rules.get("requires_poc", False),
            "rate_limit": rules.get("rate_limit", "10 req/sec"),
        },
        
        # Auto-triage settings
        "auto_triage": True,
        
        # Profile selection (can be overridden)
        "scan_profile": "full",  # Use full profile by default
        
        # Safe harbor
        "safe_harbor": {
            "enabled": getattr(h1_program, "safe_harbor", False),
            "requires_statement": False,  # Can be set per program
        },
        
        # Bounty information (for reference)
        "bounty_info": {
            "min_bounty": getattr(h1_program, "min_bounty", None),
            "max_bounty": getattr(h1_program, "max_bounty", None),
            "currency": getattr(h1_program, "currency", "USD"),
        },
        
        # Human validation workflow
        "human_validation": {
            "enabled": True,
            "auto_queue_cvss_threshold": 7.0,
            "auto_queue_bounty_threshold": 500,
            "require_validation": True,  # If true, findings must be approved before submission
        },
        
        # Browser PoC validation
        "browser_validation": {
            "enabled": True,
            "auto_validate_xss": True,
            "auto_validate_ui": True,
            "devtools_port": 9222,
            "screenshot_timeout": 5,
            "require_devtools": False,  # If false, skip browser validation if DevTools unavailable
        },
        
        # HackerOne submission
        "submission": {
            "auto_submit_approved": False,  # Manual submission via CLI
            "h1_api_token": "${H1_API_TOKEN}",
            "h1_username": "${H1_USERNAME}",
            "rate_limit_per_day": 10,
        },
    }
    
    # Write config file
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)
    
    return str(config_file)


if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate Program Config")
    parser.add_argument("--handle", required=True, help="Program handle")
    parser.add_argument("--scope-file", required=True, help="Scope JSON file")
    
    args = parser.parse_args()
    
    # Load scope
    with open(args.scope_file, "r") as f:
        scope_data = json.load(f)
    
    # Create minimal H1Program-like object
    class MockProgram:
        def __init__(self, scope_data):
            self.name = scope_data.get("program_name", args.handle)
            self.safe_harbor = scope_data.get("rules", {}).get("safe_harbor", False)
            self.min_bounty = None
            self.max_bounty = None
            self.currency = "USD"
    
    mock_program = MockProgram(scope_data)
    config_file = generate_program_config(args.handle, mock_program, scope_data)
    print(f"Generated config: {config_file}")

