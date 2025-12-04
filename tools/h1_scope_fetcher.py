#!/usr/bin/env python3
"""
HackerOne Scope Fetcher CLI

Fetch bug bounty program scopes from HackerOne and prepare them for 
the agentic bug bounty pipeline.

Usage:
    # Fetch a single program
    python tools/h1_scope_fetcher.py fetch 23andme_bbp
    
    # Fetch and start scanning
    python tools/h1_scope_fetcher.py fetch hackerone --run
    
    # Search for programs
    python tools/h1_scope_fetcher.py search "crypto"
    
    # List popular programs
    python tools/h1_scope_fetcher.py list --top 20
    
    # Fetch from URL
    python tools/h1_scope_fetcher.py fetch-url "https://hackerone.com/23andme_bbp"
"""

import os
import sys
import json
import argparse
from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.h1_client import H1Client, H1ClientError, H1NotFoundError
from tools.h1_models import H1Program, AssetType


# Output directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCOPES_DIR = os.path.join(BASE_DIR, "scopes")
OUTPUT_DIR = os.path.join(BASE_DIR, "output_zap")


def ensure_dirs():
    """Ensure required directories exist"""
    os.makedirs(SCOPES_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def extract_handle_from_url(url: str) -> str:
    """Extract program handle from HackerOne URL"""
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    
    # Handle various URL formats
    # https://hackerone.com/program_name
    # https://hackerone.com/program_name?type=team
    # https://hackerone.com/programs/program_name
    
    if path.startswith("programs/"):
        return path.split("/")[1]
    
    return path.split("/")[0].split("?")[0]


def format_bounty_range(program: H1Program) -> str:
    """Format bounty range for display"""
    if not program.bounty_ranges:
        return "Not specified"
    
    min_bounty = min(b.min_amount for b in program.bounty_ranges)
    max_bounty = max(b.max_amount for b in program.bounty_ranges)
    
    return f"${min_bounty:,.0f} - ${max_bounty:,.0f}"


def format_time_delta(seconds: Optional[int]) -> str:
    """Format seconds into human-readable time"""
    if seconds is None:
        return "N/A"
    
    if seconds < 3600:
        return f"{seconds // 60}m"
    elif seconds < 86400:
        return f"{seconds // 3600}h"
    else:
        return f"{seconds // 86400}d"


def print_program_summary(program: H1Program, verbose: bool = False):
    """Print a formatted summary of the program"""
    print("\n" + "=" * 60)
    print(f"  {program.name}")
    print("=" * 60)
    
    print(f"\n📋 Handle:        {program.handle}")
    print(f"🔗 URL:           {program.url}")
    print(f"💰 Bounties:      {'Yes' if program.offers_bounties else 'No'}")
    print(f"📊 State:         {program.state}")
    
    if program.bounty_ranges:
        print(f"\n💵 Bounty Range:  {format_bounty_range(program)}")
        if verbose:
            for br in program.bounty_ranges:
                print(f"   {br.severity.value.capitalize():10} ${br.min_amount:,.0f} - ${br.max_amount:,.0f}")
    
    if program.average_bounty:
        print(f"📈 Avg Bounty:    ${program.average_bounty:,.0f}")
    
    if program.top_bounty:
        print(f"🏆 Top Bounty:    ${program.top_bounty:,.0f}")
    
    # Response times
    if any([program.avg_first_response_time, program.avg_bounty_time, program.avg_resolution_time]):
        print(f"\n⏱️  Response Times:")
        print(f"   First Response:  {format_time_delta(program.avg_first_response_time)}")
        print(f"   Bounty:          {format_time_delta(program.avg_bounty_time)}")
        print(f"   Resolution:      {format_time_delta(program.avg_resolution_time)}")
    
    # Scope summary
    print(f"\n🎯 In-Scope Assets: {len(program.in_scope_assets)}")
    
    # Group by asset type
    by_type: Dict[str, List] = {}
    for asset in program.in_scope_assets:
        type_name = asset.asset_type.value
        if type_name not in by_type:
            by_type[type_name] = []
        by_type[type_name].append(asset)
    
    for type_name, assets in sorted(by_type.items()):
        print(f"\n   {type_name} ({len(assets)}):")
        for asset in assets[:5]:
            bounty_marker = "💰" if asset.eligible_for_bounty else "📝"
            print(f"     {bounty_marker} {asset.identifier}")
        if len(assets) > 5:
            print(f"     ... and {len(assets) - 5} more")
    
    if program.out_of_scope_assets:
        print(f"\n🚫 Out-of-Scope Assets: {len(program.out_of_scope_assets)}")
        if verbose:
            for asset in program.out_of_scope_assets[:10]:
                print(f"   ❌ {asset.identifier}")
            if len(program.out_of_scope_assets) > 10:
                print(f"   ... and {len(program.out_of_scope_assets) - 10} more")
    
    # Policy highlights
    if program.policy.custom_rules:
        print(f"\n📜 Policy Rules ({len(program.policy.custom_rules)}):")
        for rule in program.policy.custom_rules[:3]:
            print(f"   • {rule[:80]}{'...' if len(rule) > 80 else ''}")
    
    if program.policy.excluded_vuln_types:
        print(f"\n⚠️  Excluded Vuln Types:")
        for excl in program.policy.excluded_vuln_types[:5]:
            print(f"   • {excl}")
    
    print("\n" + "=" * 60)


def fetch_program(
    handle: str,
    output: Optional[str] = None,
    verbose: bool = False,
    full_details: bool = False,
    run_scan: bool = False,
) -> Optional[H1Program]:
    """
    Fetch a HackerOne program and save its scope.
    
    Args:
        handle: Program handle or URL
        output: Output file path (default: scopes/<handle>.json)
        verbose: Print detailed output
        full_details: Include out-of-scope and all metadata
        run_scan: Start a scan after fetching
    
    Returns:
        The fetched program or None on error
    """
    ensure_dirs()
    
    # Handle URL input
    if handle.startswith("http"):
        handle = extract_handle_from_url(handle)
    
    print(f"[*] Fetching program: {handle}")
    
    try:
        client = H1Client()
        program = client.fetch_program(handle)
    except H1NotFoundError:
        print(f"[!] Program not found: {handle}")
        return None
    except H1ClientError as e:
        print(f"[!] Error fetching program: {e}")
        return None
    
    # Determine output path
    if output is None:
        output = os.path.join(SCOPES_DIR, f"{handle}.json")
    
    # Generate and save scope
    scope = program.to_scope_json(include_out_of_scope=full_details)
    
    # Add metadata
    scope["_fetched_at"] = datetime.now().isoformat()
    scope["_source"] = "hackerone"
    
    with open(output, "w", encoding="utf-8") as f:
        json.dump(scope, f, indent=2)
    
    print(f"[+] Saved scope to: {output}")
    
    # Print summary
    print_program_summary(program, verbose=verbose)
    
    # Optionally run scan
    if run_scan:
        print("\n[*] Starting scan...")
        run_scope_scan(output)
    
    return program


def run_scope_scan(scope_path: str):
    """Run the agentic scanner with the given scope"""
    import subprocess
    
    runner_path = os.path.join(BASE_DIR, "agentic_runner.py")
    
    if not os.path.exists(runner_path):
        print("[!] agentic_runner.py not found")
        return
    
    cmd = [
        sys.executable,
        runner_path,
        "--scope_file", scope_path,
        "--mode", "full-scan",
    ]
    
    print(f"[*] Running: {' '.join(cmd)}")
    
    try:
        subprocess.run(cmd, check=False)
    except Exception as e:
        print(f"[!] Error running scan: {e}")


def search_programs(query: str, limit: int = 20):
    """Search for programs matching query"""
    print(f"[*] Searching for: {query}")
    
    client = H1Client()
    results = client.search_programs(query=query, limit=limit)
    
    if not results:
        print("[!] No programs found")
        return
    
    print(f"\n[+] Found {len(results)} programs:\n")
    
    for i, prog in enumerate(results, 1):
        bounty_marker = "💰" if prog.get("offers_bounties") else "📝"
        print(f"  {i:2}. {bounty_marker} {prog.get('name', 'Unknown')} ({prog.get('handle')})")


def list_programs(top: int = 20, bounties_only: bool = True):
    """List popular/recent programs"""
    print(f"[*] Listing top {top} programs")
    
    client = H1Client()
    results = client.search_programs(offers_bounties=bounties_only, limit=top)
    
    if not results:
        print("[!] No programs found")
        return
    
    print(f"\n[+] Top {len(results)} programs:\n")
    
    for i, prog in enumerate(results, 1):
        bounty_marker = "💰" if prog.get("offers_bounties") else "📝"
        print(f"  {i:2}. {bounty_marker} {prog.get('name', 'Unknown')} ({prog.get('handle')})")


def batch_fetch(handles: List[str], output_dir: Optional[str] = None):
    """Fetch multiple programs"""
    if output_dir is None:
        output_dir = SCOPES_DIR
    
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Fetching {len(handles)} programs...")
    
    success = 0
    failed = []
    
    for handle in handles:
        try:
            output = os.path.join(output_dir, f"{handle}.json")
            program = fetch_program(handle, output=output, verbose=False)
            if program:
                success += 1
            else:
                failed.append(handle)
        except Exception as e:
            print(f"[!] Error fetching {handle}: {e}")
            failed.append(handle)
    
    print(f"\n[+] Successfully fetched: {success}/{len(handles)}")
    if failed:
        print(f"[!] Failed: {', '.join(failed)}")


def create_combined_scope(scope_files: List[str], output: str = "scope.json"):
    """Combine multiple scope files into one"""
    combined = {
        "program_name": "combined",
        "primary_targets": [],
        "secondary_targets": [],
        "rules": {},
        "programs": [],
    }
    
    for scope_file in scope_files:
        try:
            with open(scope_file, "r") as f:
                scope = json.load(f)
            
            combined["primary_targets"].extend(scope.get("primary_targets", []))
            combined["secondary_targets"].extend(scope.get("secondary_targets", []))
            combined["programs"].append({
                "name": scope.get("program_name"),
                "handle": scope.get("program_handle"),
                "url": scope.get("program_url"),
            })
        except Exception as e:
            print(f"[!] Error loading {scope_file}: {e}")
    
    # Deduplicate targets
    combined["primary_targets"] = list(set(combined["primary_targets"]))
    combined["secondary_targets"] = list(set(combined["secondary_targets"]))
    
    with open(output, "w") as f:
        json.dump(combined, f, indent=2)
    
    print(f"[+] Combined {len(scope_files)} scopes into {output}")
    print(f"    Primary targets: {len(combined['primary_targets'])}")
    print(f"    Secondary targets: {len(combined['secondary_targets'])}")


def main():
    parser = argparse.ArgumentParser(
        description="HackerOne Scope Fetcher - Import bug bounty program scopes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s fetch 23andme_bbp              # Fetch a program by handle
  %(prog)s fetch "https://hackerone.com/github"  # Fetch by URL
  %(prog)s fetch hackerone --run          # Fetch and start scanning
  %(prog)s search "fintech"               # Search for programs
  %(prog)s list --top 20                  # List popular programs
  %(prog)s batch hackerone shopify github # Fetch multiple programs
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Fetch command
    fetch_parser = subparsers.add_parser("fetch", help="Fetch a single program")
    fetch_parser.add_argument("handle", help="Program handle or HackerOne URL")
    fetch_parser.add_argument("-o", "--output", help="Output file path")
    fetch_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    fetch_parser.add_argument("--full", action="store_true", help="Include all details")
    fetch_parser.add_argument("--run", action="store_true", help="Run scan after fetching")
    
    # Fetch from URL (alias)
    url_parser = subparsers.add_parser("fetch-url", help="Fetch from HackerOne URL")
    url_parser.add_argument("url", help="HackerOne program URL")
    url_parser.add_argument("-o", "--output", help="Output file path")
    url_parser.add_argument("-v", "--verbose", action="store_true")
    url_parser.add_argument("--run", action="store_true", help="Run scan after fetching")
    
    # Search command
    search_parser = subparsers.add_parser("search", help="Search for programs")
    search_parser.add_argument("query", help="Search query")
    search_parser.add_argument("-n", "--limit", type=int, default=20, help="Max results")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List popular programs")
    list_parser.add_argument("--top", type=int, default=20, help="Number to list")
    list_parser.add_argument("--all", action="store_true", help="Include non-bounty programs")
    
    # Batch fetch command
    batch_parser = subparsers.add_parser("batch", help="Fetch multiple programs")
    batch_parser.add_argument("handles", nargs="+", help="Program handles")
    batch_parser.add_argument("-o", "--output-dir", help="Output directory")
    
    # Combine command
    combine_parser = subparsers.add_parser("combine", help="Combine scope files")
    combine_parser.add_argument("files", nargs="+", help="Scope files to combine")
    combine_parser.add_argument("-o", "--output", default="scope.json", help="Output file")
    
    args = parser.parse_args()
    
    if args.command == "fetch":
        fetch_program(
            args.handle,
            output=args.output,
            verbose=args.verbose,
            full_details=args.full,
            run_scan=args.run,
        )
    
    elif args.command == "fetch-url":
        fetch_program(
            args.url,
            output=args.output,
            verbose=args.verbose,
            run_scan=args.run,
        )
    
    elif args.command == "search":
        search_programs(args.query, limit=args.limit)
    
    elif args.command == "list":
        list_programs(top=args.top, bounties_only=not args.all)
    
    elif args.command == "batch":
        batch_fetch(args.handles, output_dir=args.output_dir)
    
    elif args.command == "combine":
        create_combined_scope(args.files, output=args.output)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

