#!/usr/bin/env python3
"""Human Validation Workflow for Bug Bounty Findings

Manages a queue of findings that require human validation before submission.
Supports approve/reject workflow with state persistence.
"""

import os
import json
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
import re


class HumanValidationWorkflow:
    """Manages human validation queue for findings."""
    
    def __init__(self, state_dir: str = "validation_queue"):
        """Initialize validation workflow.
        
        Args:
            state_dir: Directory to store validation state files
        """
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(exist_ok=True, parents=True)
        
        self.pending_file = self.state_dir / "pending_validations.json"
        self.approved_file = self.state_dir / "approved_findings.json"
        self.rejected_file = self.state_dir / "rejected_findings.json"
        
        # Initialize files if they don't exist
        if not self.pending_file.exists():
            self._save_pending({})
        if not self.approved_file.exists():
            self._save_approved({})
        if not self.rejected_file.exists():
            self._save_rejected({})
    
    def _load_pending(self) -> Dict[str, Any]:
        """Load pending validations."""
        try:
            with open(self.pending_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    
    def _save_pending(self, data: Dict[str, Any]):
        """Save pending validations."""
        with open(self.pending_file, "w") as f:
            json.dump(data, f, indent=2)
    
    def _load_approved(self) -> Dict[str, Any]:
        """Load approved findings."""
        try:
            with open(self.approved_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    
    def _save_approved(self, data: Dict[str, Any]):
        """Save approved findings."""
        with open(self.approved_file, "w") as f:
            json.dump(data, f, indent=2)
    
    def _load_rejected(self) -> Dict[str, Any]:
        """Load rejected findings."""
        try:
            with open(self.rejected_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    
    def _save_rejected(self, data: Dict[str, Any]):
        """Save rejected findings."""
        with open(self.rejected_file, "w") as f:
            json.dump(data, f, indent=2)
    
    def _generate_validation_id(self, program_name: str, title: str) -> str:
        """Generate unique validation ID.
        
        Args:
            program_name: Program identifier
            title: Finding title
            
        Returns:
            Unique validation ID
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        # Create slug from title
        title_slug = re.sub(r'[^a-zA-Z0-9]+', '_', title.lower())[:30]
        return f"{program_name}_{timestamp}_{title_slug}"
    
    def queue_for_validation(
        self,
        finding: Dict[str, Any],
        program_name: str,
        report_path: Optional[str] = None,
    ) -> str:
        """Queue a finding for human validation.
        
        Args:
            finding: Finding dict with details
            program_name: Program identifier
            report_path: Optional path to report file
            
        Returns:
            Validation ID
        """
        title = finding.get("title") or "Unknown Finding"
        validation_id = self._generate_validation_id(program_name, title)
        
        pending = self._load_pending()
        
        validation_entry = {
            "validation_id": validation_id,
            "finding": finding,
            "program_name": program_name,
            "report_path": report_path,
            "queued_at": datetime.utcnow().isoformat(),
            "status": "pending",
        }
        
        pending[validation_id] = validation_entry
        self._save_pending(pending)
        
        return validation_id
    
    def approve_finding(
        self,
        validation_id: str,
        approval_notes: Optional[str] = None,
    ) -> bool:
        """Approve a finding.
        
        Args:
            validation_id: Validation ID
            approval_notes: Optional approval notes
            
        Returns:
            True if approved successfully
        """
        pending = self._load_pending()
        
        if validation_id not in pending:
            return False
        
        validation_entry = pending.pop(validation_id)
        self._save_pending(pending)
        
        # Move to approved
        approved = self._load_approved()
        validation_entry["status"] = "approved"
        validation_entry["approved_at"] = datetime.utcnow().isoformat()
        validation_entry["approval_notes"] = approval_notes
        validation_entry["submitted"] = False
        validation_entry["submitted_at"] = None
        validation_entry["h1_report_id"] = None
        validation_entry["submission_error"] = None
        
        approved[validation_id] = validation_entry
        self._save_approved(approved)
        
        return True
    
    def reject_finding(
        self,
        validation_id: str,
        rejection_reason: str,
    ) -> bool:
        """Reject a finding.
        
        Args:
            validation_id: Validation ID
            rejection_reason: Reason for rejection
            
        Returns:
            True if rejected successfully
        """
        pending = self._load_pending()
        
        if validation_id not in pending:
            return False
        
        validation_entry = pending.pop(validation_id)
        self._save_pending(pending)
        
        # Move to rejected
        rejected = self._load_rejected()
        validation_entry["status"] = "rejected"
        validation_entry["rejected_at"] = datetime.utcnow().isoformat()
        validation_entry["rejection_reason"] = rejection_reason
        
        rejected[validation_id] = validation_entry
        self._save_rejected(rejected)
        
        return True
    
    def get_pending_validations(
        self,
        program_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get pending validations.
        
        Args:
            program_name: Optional program name filter
            
        Returns:
            List of pending validation entries
        """
        pending = self._load_pending()
        
        if program_name:
            return [
                entry for entry in pending.values()
                if entry.get("program_name") == program_name
            ]
        
        return list(pending.values())
    
    def get_validation(self, validation_id: str) -> Optional[Dict[str, Any]]:
        """Get validation entry by ID (checks all states).
        
        Args:
            validation_id: Validation ID
            
        Returns:
            Validation entry or None
        """
        # Check pending
        pending = self._load_pending()
        if validation_id in pending:
            return pending[validation_id]
        
        # Check approved
        approved = self._load_approved()
        if validation_id in approved:
            return approved[validation_id]
        
        # Check rejected
        rejected = self._load_rejected()
        if validation_id in rejected:
            return rejected[validation_id]
        
        return None
    
    def get_approved_findings(
        self,
        program_name: Optional[str] = None,
        submitted_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Get approved findings ready for submission.
        
        Args:
            program_name: Optional program name filter
            submitted_only: If True, only return already-submitted findings
            
        Returns:
            List of approved validation entries
        """
        approved = self._load_approved()
        results = []
        
        for entry in approved.values():
            if program_name and entry.get("program_name") != program_name:
                continue
            
            if submitted_only and not entry.get("submitted", False):
                continue
            
            if not submitted_only and entry.get("submitted", False):
                continue
            
            results.append(entry)
        
        return results
    
    def update_submission_status(
        self,
        validation_id: str,
        h1_report_id: Optional[str] = None,
        error: Optional[str] = None,
    ) -> bool:
        """Update submission status for an approved finding.
        
        Args:
            validation_id: Validation ID
            h1_report_id: Optional H1 report ID if submitted successfully
            error: Optional error message if submission failed
            
        Returns:
            True if updated successfully
        """
        approved = self._load_approved()
        
        if validation_id not in approved:
            return False
        
        approved[validation_id]["submitted"] = h1_report_id is not None
        approved[validation_id]["submitted_at"] = datetime.utcnow().isoformat() if h1_report_id else None
        approved[validation_id]["h1_report_id"] = h1_report_id
        approved[validation_id]["submission_error"] = error
        
        self._save_approved(approved)
        
        return True
    
    def get_stats(self) -> Dict[str, int]:
        """Get validation statistics.
        
        Returns:
            Dict with counts for pending, approved, rejected
        """
        pending = self._load_pending()
        approved = self._load_approved()
        rejected = self._load_rejected()
        
        return {
            "pending": len(pending),
            "approved": len(approved),
            "rejected": len(rejected),
            "total": len(pending) + len(approved) + len(rejected),
        }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Human Validation Workflow Test")
    parser.add_argument("--action", choices=["queue", "approve", "reject", "list", "stats"], required=True)
    parser.add_argument("--validation-id", help="Validation ID for approve/reject")
    parser.add_argument("--program", help="Program name")
    parser.add_argument("--notes", help="Approval notes or rejection reason")
    
    args = parser.parse_args()
    
    workflow = HumanValidationWorkflow()
    
    if args.action == "stats":
        stats = workflow.get_stats()
        print(f"Pending: {stats['pending']}, Approved: {stats['approved']}, Rejected: {stats['rejected']}")
    elif args.action == "list":
        validations = workflow.get_pending_validations(args.program)
        print(f"Found {len(validations)} pending validations")
        for v in validations:
            print(f"  {v['validation_id']}: {v['finding'].get('title', 'Unknown')}")
    elif args.action == "approve":
        if not args.validation_id:
            print("Error: --validation-id required for approve")
            sys.exit(1)
        success = workflow.approve_finding(args.validation_id, args.notes)
        print(f"Approved: {success}")
    elif args.action == "reject":
        if not args.validation_id or not args.notes:
            print("Error: --validation-id and --notes required for reject")
            sys.exit(1)
        success = workflow.reject_finding(args.validation_id, args.notes)
        print(f"Rejected: {success}")

