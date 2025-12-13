#!/usr/bin/env python3
"""Test All New Labs - Test script for all 15 new vulnerability labs.

This script tests all new labs created for the 15 new vulnerability testers
and generates a comprehensive validation report.
"""

import argparse
import sys
from pathlib import Path

# Add tools to path
REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

from tools.lab_test_suite import test_all_labs, list_new_labs, list_all_labs


def main():
    parser = argparse.ArgumentParser(
        description="Test all new vulnerability labs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Test all new labs
  %(prog)s --all              # Test all labs (including old ones)
  %(prog)s --lab command_injection_lab  # Test single lab
  %(prog)s --profile full     # Use full scan profile
        """
    )
    parser.add_argument("--all", action="store_true", help="Test all labs (not just new ones)")
    parser.add_argument("--lab", help="Test a specific lab")
    parser.add_argument("--profile", help="Scan profile to use (e.g., full, xss-heavy)")
    parser.add_argument("--mcp-url", default="http://127.0.0.1:8000", help="MCP server URL")
    
    args = parser.parse_args()
    
    # Determine which labs to test
    if args.lab:
        lab_names = [args.lab]
    elif args.all:
        lab_names = list_all_labs()
        print(f"[TEST] Testing all {len(lab_names)} labs")
    else:
        lab_names = list_new_labs()
        print(f"[TEST] Testing {len(lab_names)} new labs")
    
    if not lab_names:
        print("[TEST] No labs found to test")
        return 1
    
    # Run test suite
    try:
        results = test_all_labs(
            lab_names=lab_names,
            mcp_url=args.mcp_url,
            profile=args.profile
        )
        
        # Exit with error code if detection rate is too low
        if results["overall_detection_rate"] < 0.5:
            print(f"\n[TEST] ⚠️  Warning: Overall detection rate ({results['overall_detection_rate']:.1%}) is below 50%")
            return 1
        
        return 0
    except KeyboardInterrupt:
        print("\n[TEST] Interrupted by user")
        return 130
    except Exception as e:
        print(f"[TEST] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

