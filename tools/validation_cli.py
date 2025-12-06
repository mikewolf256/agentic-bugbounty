#!/usr/bin/env python3
"""CLI tool for managing human validation workflow."""

import sys
import json
import argparse
from typing import Optional
from tools.human_validation_workflow import HumanValidationWorkflow


def format_finding_summary(finding: dict) -> str:
    """Format finding details for display."""
    title = finding.get("title", "Unknown Finding")
    cvss = finding.get("cvss_score", 0.0)
    url = finding.get("url") or finding.get("_raw_finding", {}).get("url", "N/A")
    estimated_bounty = finding.get("estimated_bounty", 0)
    
    return f"""
Title: {title}
CVSS: {cvss:.1f}
Estimated Bounty: ${estimated_bounty}
URL: {url}
"""


def cmd_list(args):
    """List pending validations."""
    workflow = HumanValidationWorkflow()
    validations = workflow.get_pending_validations(args.program)
    
    if not validations:
        print("No pending validations found.")
        if args.program:
            print(f"(Filtered by program: {args.program})")
        return
    
    print(f"\nFound {len(validations)} pending validation(s):\n")
    for v in validations:
        finding = v.get("finding", {})
        title = finding.get("title", "Unknown")
        cvss = finding.get("cvss_score", 0.0)
        estimated_bounty = finding.get("estimated_bounty", 0)
        
        print(f"  [{v['validation_id']}]")
        print(f"    Title: {title}")
        print(f"    CVSS: {cvss:.1f} | Bounty: ${estimated_bounty}")
        print(f"    Program: {v.get('program_name', 'Unknown')}")
        print(f"    Queued: {v.get('queued_at', 'N/A')}")
        print()


def cmd_show(args):
    """Show full details of a validation."""
    workflow = HumanValidationWorkflow()
    validation = workflow.get_validation(args.validation_id)
    
    if not validation:
        print(f"Validation ID not found: {args.validation_id}")
        sys.exit(1)
    
    print(f"\nValidation ID: {validation['validation_id']}")
    print(f"Status: {validation.get('status', 'unknown')}")
    print(f"Program: {validation.get('program_name', 'Unknown')}")
    print(f"Queued: {validation.get('queued_at', 'N/A')}")
    
    if validation.get('status') == 'approved':
        print(f"Approved: {validation.get('approved_at', 'N/A')}")
        if validation.get('approval_notes'):
            print(f"Notes: {validation['approval_notes']}")
        print(f"Submitted: {validation.get('submitted', False)}")
        if validation.get('h1_report_id'):
            print(f"H1 Report ID: {validation['h1_report_id']}")
    
    if validation.get('status') == 'rejected':
        print(f"Rejected: {validation.get('rejected_at', 'N/A')}")
        print(f"Reason: {validation.get('rejection_reason', 'N/A')}")
    
    print("\nFinding Details:")
    finding = validation.get("finding", {})
    print(format_finding_summary(finding))
    
    report_path = validation.get("report_path")
    if report_path:
        print(f"Report Path: {report_path}")


def cmd_approve(args):
    """Approve a finding."""
    workflow = HumanValidationWorkflow()
    
    # Check if validation exists
    validation = workflow.get_validation(args.validation_id)
    if not validation:
        print(f"Validation ID not found: {args.validation_id}")
        sys.exit(1)
    
    if validation.get('status') != 'pending':
        print(f"Validation is not pending (status: {validation.get('status')})")
        sys.exit(1)
    
    success = workflow.approve_finding(args.validation_id, args.notes)
    
    if success:
        print(f"✓ Approved validation: {args.validation_id}")
        if args.notes:
            print(f"  Notes: {args.notes}")
    else:
        print(f"✗ Failed to approve validation: {args.validation_id}")
        sys.exit(1)


def cmd_reject(args):
    """Reject a finding."""
    workflow = HumanValidationWorkflow()
    
    # Check if validation exists
    validation = workflow.get_validation(args.validation_id)
    if not validation:
        print(f"Validation ID not found: {args.validation_id}")
        sys.exit(1)
    
    if validation.get('status') != 'pending':
        print(f"Validation is not pending (status: {validation.get('status')})")
        sys.exit(1)
    
    if not args.reason:
        print("Error: --reason is required for rejection")
        sys.exit(1)
    
    success = workflow.reject_finding(args.validation_id, args.reason)
    
    if success:
        print(f"✓ Rejected validation: {args.validation_id}")
        print(f"  Reason: {args.reason}")
    else:
        print(f"✗ Failed to reject validation: {args.validation_id}")
        sys.exit(1)


def cmd_stats(args):
    """Show validation statistics."""
    workflow = HumanValidationWorkflow()
    stats = workflow.get_stats()
    
    print("\nValidation Statistics:")
    print(f"  Pending:  {stats['pending']}")
    print(f"  Approved: {stats['approved']}")
    print(f"  Rejected: {stats['rejected']}")
    print(f"  Total:    {stats['total']}")
    
    if args.program:
        validations = workflow.get_pending_validations(args.program)
        print(f"\nPending for '{args.program}': {len(validations)}")


def main():
    parser = argparse.ArgumentParser(
        description="Human Validation Workflow CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List pending validations")
    list_parser.add_argument("--program", help="Filter by program name")
    
    # Show command
    show_parser = subparsers.add_parser("show", help="Show validation details")
    show_parser.add_argument("validation_id", help="Validation ID")
    
    # Approve command
    approve_parser = subparsers.add_parser("approve", help="Approve a finding")
    approve_parser.add_argument("validation_id", help="Validation ID")
    approve_parser.add_argument("--notes", help="Approval notes")
    
    # Reject command
    reject_parser = subparsers.add_parser("reject", help="Reject a finding")
    reject_parser.add_argument("validation_id", help="Validation ID")
    reject_parser.add_argument("--reason", required=True, help="Rejection reason")
    
    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show validation statistics")
    stats_parser.add_argument("--program", help="Filter by program name")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == "list":
        cmd_list(args)
    elif args.command == "show":
        cmd_show(args)
    elif args.command == "approve":
        cmd_approve(args)
    elif args.command == "reject":
        cmd_reject(args)
    elif args.command == "stats":
        cmd_stats(args)


if __name__ == "__main__":
    main()

