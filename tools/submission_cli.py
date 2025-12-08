#!/usr/bin/env python3
"""CLI tool for managing HackerOne submissions."""

import sys
import argparse
from tools.human_validation_workflow import HumanValidationWorkflow
from tools.submission_orchestrator import SubmissionOrchestrator


def cmd_list_approved(args):
    """List approved findings ready for submission."""
    workflow = HumanValidationWorkflow()
    approved = workflow.get_approved_findings(
        program_name=args.program,
        submitted_only=False,
    )
    
    if not approved:
        print("No approved findings found ready for submission.")
        if args.program:
            print(f"(Filtered by program: {args.program})")
        return
    
    print(f"\nFound {len(approved)} approved finding(s) ready for submission:\n")
    for entry in approved:
        finding = entry.get("finding", {})
        title = finding.get("title", "Unknown")
        cvss = finding.get("cvss_score", 0.0)
        estimated_bounty = finding.get("estimated_bounty", 0)
        submitted = entry.get("submitted", False)
        h1_report_id = entry.get("h1_report_id")
        
        status = "✓ Submitted" if submitted else "⏳ Pending"
        if h1_report_id:
            status += f" (H1: {h1_report_id})"
        
        print(f"  [{entry['validation_id']}]")
        print(f"    Title: {title}")
        print(f"    CVSS: {cvss:.1f} | Bounty: ${estimated_bounty}")
        print(f"    Program: {entry.get('program_name', 'Unknown')}")
        print(f"    Status: {status}")
        if entry.get("submission_error"):
            print(f"    Error: {entry['submission_error']}")
        print()


def cmd_submit(args):
    """Submit a single approved finding."""
    orchestrator = SubmissionOrchestrator()
    
    result = orchestrator.submit_single(args.validation_id, args.program)
    
    if result["success"]:
        print(f"✓ Successfully submitted to HackerOne")
        print(f"  Validation ID: {args.validation_id}")
        print(f"  H1 Report ID: {result.get('h1_report_id')}")
    else:
        print(f"✗ Submission failed: {result.get('error')}")
        sys.exit(1)


def cmd_submit_all(args):
    """Submit all approved findings for a program."""
    orchestrator = SubmissionOrchestrator()
    
    results = orchestrator.process_approved_findings(
        program_handle=args.program,
        dry_run=args.dry_run,
    )
    
    print(f"\nSubmission Results:")
    print(f"  ✓ Submitted: {len(results['submitted'])}")
    print(f"  ✗ Failed: {len(results['failed'])}")
    print(f"  ⊘ Skipped: {len(results['skipped'])}")
    
    if results["failed"]:
        print(f"\nFailed submissions:")
        for failed in results["failed"]:
            print(f"  - {failed['validation_id']}: {failed.get('error', 'Unknown error')}")
    
    if results["skipped"]:
        print(f"\nSkipped submissions:")
        for skipped in results["skipped"]:
            print(f"  - {skipped.get('validation_id', 'N/A')}: {skipped.get('error', 'Unknown reason')}")


def cmd_status(args):
    """Check submission status for a validation."""
    workflow = HumanValidationWorkflow()
    validation = workflow.get_validation(args.validation_id)
    
    if not validation:
        print(f"Validation ID not found: {args.validation_id}")
        sys.exit(1)
    
    status = validation.get("status", "unknown")
    print(f"\nValidation ID: {args.validation_id}")
    print(f"Status: {status}")
    
    if status == "approved":
        submitted = validation.get("submitted", False)
        print(f"Submitted: {submitted}")
        
        if submitted:
            h1_report_id = validation.get("h1_report_id")
            submitted_at = validation.get("submitted_at")
            print(f"H1 Report ID: {h1_report_id or 'N/A'}")
            print(f"Submitted At: {submitted_at or 'N/A'}")
        else:
            print("Ready for submission")
    elif status == "pending":
        print("Not yet approved - cannot submit")
    elif status == "rejected":
        print(f"Rejected: {validation.get('rejection_reason', 'N/A')}")


def main():
    parser = argparse.ArgumentParser(
        description="HackerOne Submission CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # List-approved command
    list_parser = subparsers.add_parser("list-approved", help="List approved findings ready for submission")
    list_parser.add_argument("--program", help="Filter by program name")
    
    # Submit command
    submit_parser = subparsers.add_parser("submit", help="Submit a single approved finding")
    submit_parser.add_argument("validation_id", help="Validation ID")
    submit_parser.add_argument("--program", help="Program handle (overrides from validation)")
    
    # Submit-all command
    submit_all_parser = subparsers.add_parser("submit-all", help="Submit all approved findings")
    submit_all_parser.add_argument("--program", help="Filter by program name")
    submit_all_parser.add_argument("--dry-run", action="store_true", help="Dry run (don't actually submit)")
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Check submission status")
    status_parser.add_argument("validation_id", help="Validation ID")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == "list-approved":
        cmd_list_approved(args)
    elif args.command == "submit":
        cmd_submit(args)
    elif args.command == "submit-all":
        cmd_submit_all(args)
    elif args.command == "status":
        cmd_status(args)


if __name__ == "__main__":
    main()

