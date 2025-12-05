#!/usr/bin/env python3
"""Scan Scheduler for Continuous Bug Bounty Scanning

Supports scheduled scans with per-program configuration, idempotency checks,
and integration with the agentic runner.
"""

import os
import json
import time
import schedule
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path


class ScanScheduler:
    """Manages scheduled scans for bug bounty programs."""
    
    def __init__(self, config_dir: str = "scopes", state_dir: str = "scan_state"):
        self.config_dir = Path(config_dir)
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(exist_ok=True)
        self.running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        
    def load_program_config(self, program_name: str) -> Optional[Dict[str, Any]]:
        """Load program-specific scan configuration.
        
        Args:
            program_name: Program identifier (e.g., "23andme_bbp")
            
        Returns:
            Program config dict or None if not found
        """
        config_file = self.config_dir / f"{program_name}_config.json"
        if not config_file.exists():
            return None
        
        try:
            with open(config_file, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"[SCHEDULER] Error loading config for {program_name}: {e}")
            return None
    
    def get_scan_state(self, program_name: str) -> Dict[str, Any]:
        """Get scan state for a program.
        
        Args:
            program_name: Program identifier
            
        Returns:
            Scan state dict with last_scan_time, scan_count, etc.
        """
        state_file = self.state_dir / f"{program_name}_state.json"
        if state_file.exists():
            try:
                with open(state_file, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        
        return {
            "last_scan_time": None,
            "scan_count": 0,
            "last_scan_id": None,
            "errors": [],
        }
    
    def update_scan_state(self, program_name: str, scan_id: str, success: bool = True, error: Optional[str] = None):
        """Update scan state after a scan completes.
        
        Args:
            program_name: Program identifier
            scan_id: Unique scan identifier
            success: Whether scan succeeded
            error: Error message if failed
        """
        state = self.get_scan_state(program_name)
        state["last_scan_time"] = datetime.now().isoformat()
        state["last_scan_id"] = scan_id
        if success:
            state["scan_count"] = state.get("scan_count", 0) + 1
            # Clear errors on success
            state["errors"] = []
        else:
            state["errors"] = state.get("errors", [])[:4]  # Keep last 4 errors
            if error:
                state["errors"].append({
                    "timestamp": datetime.now().isoformat(),
                    "error": error,
                })
        
        state_file = self.state_dir / f"{program_name}_state.json"
        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
    
    def should_run_scan(self, program_name: str, config: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Check if a scan should run based on schedule and last scan time.
        
        Args:
            program_name: Program identifier
            config: Program configuration
            
        Returns:
            Tuple of (should_run, reason)
        """
        state = self.get_scan_state(program_name)
        last_scan_time = state.get("last_scan_time")
        
        # If never scanned, run it
        if not last_scan_time:
            return True, "First scan for program"
        
        # Check scan frequency
        frequency = config.get("scan_frequency", "daily")
        last_scan = datetime.fromisoformat(last_scan_time)
        now = datetime.now()
        
        if frequency == "daily":
            # Check if 24 hours have passed
            if now - last_scan >= timedelta(hours=24):
                return True, "Daily scan due"
            return False, f"Daily scan already ran {now - last_scan} ago"
        
        elif frequency == "weekly":
            # Check if 7 days have passed
            if now - last_scan >= timedelta(days=7):
                return True, "Weekly scan due"
            return False, f"Weekly scan already ran {now - last_scan} ago"
        
        elif frequency == "manual":
            return False, "Manual scan only (not scheduled)"
        
        else:
            # Custom frequency (e.g., "12h", "2d")
            try:
                if frequency.endswith("h"):
                    hours = int(frequency[:-1])
                    if now - last_scan >= timedelta(hours=hours):
                        return True, f"Custom frequency ({frequency}) scan due"
                elif frequency.endswith("d"):
                    days = int(frequency[:-1])
                    if now - last_scan >= timedelta(days=days):
                        return True, f"Custom frequency ({frequency}) scan due"
            except ValueError:
                pass
            
            return False, f"Custom frequency not met: {frequency}"
    
    def run_scheduled_scan(self, program_name: str):
        """Run a scheduled scan for a program.
        
        Args:
            program_name: Program identifier
        """
        print(f"[SCHEDULER] Starting scheduled scan for {program_name}")
        
        config = self.load_program_config(program_name)
        if not config:
            print(f"[SCHEDULER] No config found for {program_name}, skipping")
            return
        
        # Check if scan should run
        should_run, reason = self.should_run_scan(program_name, config)
        if not should_run:
            print(f"[SCHEDULER] Skipping scan for {program_name}: {reason}")
            return
        
        # Load scope
        scope_file = self.config_dir / f"{program_name}.json"
        if not scope_file.exists():
            error = f"Scope file not found: {scope_file}"
            print(f"[SCHEDULER] {error}")
            self.update_scan_state(program_name, f"error_{int(time.time())}", success=False, error=error)
            return
        
        try:
            with open(scope_file, "r") as f:
                scope = json.load(f)
        except Exception as e:
            error = f"Error loading scope: {e}"
            print(f"[SCHEDULER] {error}")
            self.update_scan_state(program_name, f"error_{int(time.time())}", success=False, error=error)
            return
        
        # Generate scan ID
        scan_id = f"{program_name}_{int(time.time())}"
        
        # Import and run agentic runner
        try:
            import sys
            sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
            from agentic_runner import run_full_scan_via_mcp, run_triage_for_findings
            
            # Run full scan
            print(f"[SCHEDULER] Running full scan for {program_name} (scan_id: {scan_id})")
            summary = run_full_scan_via_mcp(scope)
            
            # Auto-triage findings if enabled
            if config.get("auto_triage", True):
                output_dir = os.environ.get("OUTPUT_DIR", "output_zap")
                for fname in os.listdir(output_dir):
                    if fname.endswith(".json") and (
                        fname.startswith("katana_nuclei_") or 
                        fname.startswith("cloud_findings_")
                    ):
                        findings_path = os.path.join(output_dir, fname)
                        print(f"[SCHEDULER] Auto-triaging {findings_path}")
                        run_triage_for_findings(findings_path, scope, out_dir=output_dir)
            
            # Update state on success
            self.update_scan_state(program_name, scan_id, success=True)
            print(f"[SCHEDULER] Scan completed successfully for {program_name}")
            
        except Exception as e:
            error = f"Scan execution failed: {e}"
            print(f"[SCHEDULER] {error}")
            self.update_scan_state(program_name, scan_id, success=False, error=error)
    
    def schedule_program(self, program_name: str, config: Dict[str, Any]):
        """Schedule a program for recurring scans.
        
        Args:
            program_name: Program identifier
            config: Program configuration with scan_frequency
        """
        frequency = config.get("scan_frequency", "daily")
        
        if frequency == "daily":
            schedule.every().day.at(config.get("scan_time", "02:00")).do(
                self.run_scheduled_scan, program_name
            )
        elif frequency == "weekly":
            day = config.get("scan_day", "monday")
            time_str = config.get("scan_time", "02:00")
            getattr(schedule.every(), day.lower()).at(time_str).do(
                self.run_scheduled_scan, program_name
            )
        elif frequency == "manual":
            # Don't schedule, only manual runs
            pass
        else:
            # Custom frequency - use interval
            try:
                if frequency.endswith("h"):
                    hours = int(frequency[:-1])
                    schedule.every(hours).hours.do(self.run_scheduled_scan, program_name)
                elif frequency.endswith("d"):
                    days = int(frequency[:-1])
                    schedule.every(days).days.do(self.run_scheduled_scan, program_name)
            except ValueError:
                print(f"[SCHEDULER] Invalid frequency format: {frequency}")
    
    def load_all_programs(self):
        """Load and schedule all programs with config files."""
        if not self.config_dir.exists():
            return
        
        for config_file in self.config_dir.glob("*_config.json"):
            program_name = config_file.stem.replace("_config", "")
            config = self.load_program_config(program_name)
            if config and config.get("enabled", True):
                self.schedule_program(program_name, config)
                print(f"[SCHEDULER] Scheduled {program_name} with frequency: {config.get('scan_frequency', 'daily')}")
    
    def start(self):
        """Start the scheduler in a background thread."""
        if self.running:
            return
        
        self.running = True
        self.load_all_programs()
        
        def run_scheduler():
            while self.running:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        
        self.scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        self.scheduler_thread.start()
        print("[SCHEDULER] Scheduler started")
    
    def stop(self):
        """Stop the scheduler."""
        self.running = False
        schedule.clear()
        print("[SCHEDULER] Scheduler stopped")
    
    def run_now(self, program_name: str):
        """Manually trigger a scan for a program (for testing).
        
        Args:
            program_name: Program identifier
        """
        self.run_scheduled_scan(program_name)


def main():
    """CLI entry point for scan scheduler."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Scan Scheduler for Bug Bounty Programs")
    parser.add_argument("--program", help="Program name to scan")
    parser.add_argument("--run-now", action="store_true", help="Run scan immediately (don't schedule)")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon (continuous scheduling)")
    parser.add_argument("--config-dir", default="scopes", help="Directory with program configs")
    parser.add_argument("--state-dir", default="scan_state", help="Directory for scan state")
    
    args = parser.parse_args()
    
    scheduler = ScanScheduler(config_dir=args.config_dir, state_dir=args.state_dir)
    
    if args.run_now and args.program:
        # Run scan immediately
        scheduler.run_scheduled_scan(args.program)
    elif args.daemon:
        # Run as daemon
        scheduler.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            scheduler.stop()
    else:
        # Load and show scheduled jobs
        scheduler.load_all_programs()
        print("\nScheduled jobs:")
        for job in schedule.jobs:
            print(f"  {job}")


if __name__ == "__main__":
    main()

