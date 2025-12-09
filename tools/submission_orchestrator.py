#!/usr/bin/env python3
"""Submission Orchestrator for HackerOne

Processes approved findings and submits them to HackerOne via API.
"""

import os
import sys
from typing import Dict, Any, List, Optional
from tools.human_validation_workflow import HumanValidationWorkflow
from tools.h1_submitter import H1Submitter


class SubmissionOrchestrator:
    """Orchestrates submission of approved findings to HackerOne."""
    
    def __init__(
        self,
        validation_workflow: Optional[HumanValidationWorkflow] = None,
        h1_submitter: Optional[H1Submitter] = None,
    ):
        """Initialize submission orchestrator.
        
        Args:
            validation_workflow: HumanValidationWorkflow instance (creates new if None)
            h1_submitter: H1Submitter instance (creates new if None)
        """
        self.validation_workflow = validation_workflow or HumanValidationWorkflow()
        
        try:
            self.h1_submitter = h1_submitter or H1Submitter()
        except ValueError as e:
            print(f"[SUBMISSION] H1 credentials not configured: {e}", file=sys.stderr)
            self.h1_submitter = None
    
    def process_approved_findings(
        self,
        program_handle: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Process approved findings and submit to H1.
        
        Args:
            program_handle: Optional program handle filter
            dry_run: If True, don't actually submit (just validate)
            
        Returns:
            Dict with submitted, failed, and skipped lists
        """
        if not self.h1_submitter:
            return {
                "submitted": [],
                "failed": [],
                "skipped": [{"error": "H1 credentials not configured"}],
            }
        
        # Get approved findings ready for submission
        approved = self.validation_workflow.get_approved_findings(
            program_name=program_handle,
            submitted_only=False,
        )
        
        results = {
            "submitted": [],
            "failed": [],
            "skipped": [],
        }
        
        for validation_entry in approved:
            validation_id = validation_entry["validation_id"]
            finding = validation_entry.get("finding", {})
            report_path = validation_entry.get("report_path")
            program_name = validation_entry.get("program_name")
            
            # Use program_handle from parameter or from validation entry
            target_program = program_handle or program_name
            
            if not target_program:
                results["skipped"].append({
                    "validation_id": validation_id,
                    "error": "No program handle specified",
                })
                continue
            
            # Read report markdown if available
            report_markdown = None
            if report_path and os.path.exists(report_path):
                try:
                    with open(report_path, "r") as f:
                        report_markdown = f.read()
                except Exception as e:
                    print(f"[SUBMISSION] Failed to read report {report_path}: {e}", file=sys.stderr)
            
            if dry_run:
                print(f"[DRY-RUN] Would submit {validation_id} to {target_program}")
                results["submitted"].append({
                    "validation_id": validation_id,
                    "program": target_program,
                    "dry_run": True,
                })
                continue
            
            # Submit to H1
            try:
                result = self.h1_submitter.submit_report(
                    finding, target_program, report_markdown
                )
                
                if result["success"]:
                    h1_report_id = result.get("report_id")
                    # Update validation entry with submission status
                    self.validation_workflow.update_submission_status(
                        validation_id, h1_report_id
                    )
                    
                    results["submitted"].append({
                        "validation_id": validation_id,
                        "program": target_program,
                        "h1_report_id": h1_report_id,
                    })
                    print(f"[SUBMISSION] ✓ Submitted {validation_id} -> H1 report {h1_report_id}")
                else:
                    error = result.get("error", "Unknown error")
                    # Update validation entry with error
                    self.validation_workflow.update_submission_status(
                        validation_id, None, error
                    )
                    
                    results["failed"].append({
                        "validation_id": validation_id,
                        "program": target_program,
                        "error": error,
                    })
                    print(f"[SUBMISSION] ✗ Failed to submit {validation_id}: {error}", file=sys.stderr)
            except Exception as e:
                error = str(e)
                self.validation_workflow.update_submission_status(
                    validation_id, None, error
                )
                
                results["failed"].append({
                    "validation_id": validation_id,
                    "program": target_program,
                    "error": error,
                })
                print(f"[SUBMISSION] ✗ Exception submitting {validation_id}: {e}", file=sys.stderr)
        
        return results
    
    def submit_single(
        self,
        validation_id: str,
        program_handle: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submit a single approved finding.
        
        Args:
            validation_id: Validation ID
            program_handle: Optional program handle (uses from validation if not provided)
            
        Returns:
            Result dict with success status
        """
        if not self.h1_submitter:
            return {
                "success": False,
                "error": "H1 credentials not configured",
            }
        
        validation = self.validation_workflow.get_validation(validation_id)
        if not validation:
            return {
                "success": False,
                "error": f"Validation ID not found: {validation_id}",
            }
        
        if validation.get("status") != "approved":
            return {
                "success": False,
                "error": f"Validation is not approved (status: {validation.get('status')})",
            }
        
        if validation.get("submitted"):
            return {
                "success": False,
                "error": f"Already submitted (H1 report: {validation.get('h1_report_id')})",
            }
        
        finding = validation.get("finding", {})
        report_path = validation.get("report_path")
        program_name = program_handle or validation.get("program_name")
        
        if not program_name:
            return {
                "success": False,
                "error": "No program handle specified",
            }
        
        # Read report markdown if available
        report_markdown = None
        if report_path and os.path.exists(report_path):
            try:
                with open(report_path, "r") as f:
                    report_markdown = f.read()
            except Exception as e:
                print(f"[SUBMISSION] Failed to read report {report_path}: {e}", file=sys.stderr)
        
        # Submit to H1
        try:
            result = self.h1_submitter.submit_report(finding, program_name, report_markdown)
            
            if result["success"]:
                h1_report_id = result.get("report_id")
                self.validation_workflow.update_submission_status(validation_id, h1_report_id)
                return {
                    "success": True,
                    "h1_report_id": h1_report_id,
                }
            else:
                error = result.get("error", "Unknown error")
                self.validation_workflow.update_submission_status(validation_id, None, error)
                return {
                    "success": False,
                    "error": error,
                }
        except Exception as e:
            error = str(e)
            self.validation_workflow.update_submission_status(validation_id, None, error)
            return {
                "success": False,
                "error": error,
            }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Submission Orchestrator Test")
    parser.add_argument("--program", help="Program handle")
    parser.add_argument("--validation-id", help="Single validation ID to submit")
    parser.add_argument("--dry-run", action="store_true", help="Dry run (don't actually submit)")
    
    args = parser.parse_args()
    
    orchestrator = SubmissionOrchestrator()
    
    if args.validation_id:
        result = orchestrator.submit_single(args.validation_id, args.program)
        if result["success"]:
            print(f"✓ Submitted: {result.get('h1_report_id')}")
        else:
            print(f"✗ Failed: {result.get('error')}")
            sys.exit(1)
    else:
        results = orchestrator.process_approved_findings(args.program, args.dry_run)
        print(f"\nSubmission Results:")
        print(f"  Submitted: {len(results['submitted'])}")
        print(f"  Failed: {len(results['failed'])}")
        print(f"  Skipped: {len(results['skipped'])}")

