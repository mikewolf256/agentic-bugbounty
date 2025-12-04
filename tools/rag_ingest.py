#!/usr/bin/env python3
"""
RAG Ingestion Script - Batch ingest HackerOne reports into Supabase with OpenAI embeddings.

This script:
1. Parses reports from the local clone of bugbounty-disclosed-reports
2. Generates embeddings using OpenAI text-embedding-3-small
3. Upserts records into Supabase with pgvector

Usage:
    python rag_ingest.py --reports-dir ./bugbounty-disclosed-reports/reports
    
Environment variables:
    SUPABASE_URL - Your Supabase project URL
    SUPABASE_KEY - Your Supabase service role key (or anon key with insert permissions)
    OPENAI_API_KEY - Your OpenAI API key
"""

import os
import sys
import json
import time
import argparse
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import hashlib

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from supabase import create_client, Client
    import tiktoken
except ImportError:
    print("Missing dependencies. Install with:")
    print("  pip install supabase tiktoken")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Missing requests library. Install with: pip install requests")
    sys.exit(1)

from tools.rag_report_parser import (
    parse_reports_directory,
    generate_embedding_text,
    ParsedReport,
)


# Configuration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

EMBEDDING_MODEL = "text-embedding-3-small"
EMBEDDING_DIMENSIONS = 1536
MAX_TOKENS_PER_EMBED = 8000  # Model limit is 8191, leave buffer

# Rate limiting
EMBEDDINGS_PER_MINUTE = 3000  # OpenAI rate limit
BATCH_SIZE = 100  # Embeddings per batch
SUPABASE_BATCH_SIZE = 500  # Records per upsert batch


def check_config():
    """Validate required environment variables."""
    missing = []
    if not OPENAI_API_KEY:
        missing.append("OPENAI_API_KEY")
    if not SUPABASE_URL:
        missing.append("SUPABASE_URL")
    if not SUPABASE_KEY:
        missing.append("SUPABASE_KEY")
    
    if missing:
        print(f"Error: Missing environment variables: {', '.join(missing)}")
        print("\nSet them with:")
        for var in missing:
            print(f"  export {var}=your_value")
        sys.exit(1)


def count_tokens(text: str) -> int:
    """Count tokens in text using tiktoken."""
    try:
        enc = tiktoken.encoding_for_model("text-embedding-3-small")
        return len(enc.encode(text))
    except Exception:
        # Fallback: rough estimate
        return len(text) // 4


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Truncate text to fit within token limit."""
    try:
        enc = tiktoken.encoding_for_model("text-embedding-3-small")
        tokens = enc.encode(text)
        if len(tokens) <= max_tokens:
            return text
        truncated_tokens = tokens[:max_tokens]
        return enc.decode(truncated_tokens)
    except Exception:
        # Fallback: character-based truncation
        char_limit = max_tokens * 4
        return text[:char_limit]


def get_embeddings_batch(texts: List[str]) -> List[List[float]]:
    """Get embeddings for a batch of texts from OpenAI."""
    if not texts:
        return []
    
    # Truncate texts that are too long
    truncated_texts = [
        truncate_to_tokens(t, MAX_TOKENS_PER_EMBED) if count_tokens(t) > MAX_TOKENS_PER_EMBED else t
        for t in texts
    ]
    
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    
    payload = {
        "model": EMBEDDING_MODEL,
        "input": truncated_texts,
    }
    
    response = requests.post(
        "https://api.openai.com/v1/embeddings",
        headers=headers,
        json=payload,
        timeout=60,
    )
    
    if response.status_code != 200:
        raise Exception(f"OpenAI API error: {response.status_code} - {response.text}")
    
    data = response.json()
    
    # Sort by index to maintain order
    embeddings_data = sorted(data["data"], key=lambda x: x["index"])
    return [e["embedding"] for e in embeddings_data]


def create_supabase_client() -> Client:
    """Create and return a Supabase client."""
    return create_client(SUPABASE_URL, SUPABASE_KEY)


def report_to_db_record(report: ParsedReport, embedding: List[float]) -> Dict[str, Any]:
    """Convert a ParsedReport to a database record."""
    return {
        "report_id": report.report_id,
        "title": report.title,
        "vuln_type": report.vuln_type,
        "severity": report.severity,
        "cwe": report.cwe,
        "target_technology": report.target_technology,
        "attack_vector": report.attack_vector[:2000] if report.attack_vector else None,
        "payload": report.payload[:5000] if report.payload else None,
        "impact": report.impact[:2000] if report.impact else None,
        "steps_to_reproduce": report.steps_to_reproduce[:5000] if report.steps_to_reproduce else None,
        "source_url": report.source_url,
        "program_name": report.program_name or report.team_handle,
        "reporter_username": report.reporter_username,
        "submitted_at": report.submitted_at.isoformat() if report.submitted_at else None,
        "disclosed_at": report.disclosed_at.isoformat() if report.disclosed_at else None,
        "raw_content": report.raw_content[:50000] if report.raw_content else None,  # Limit raw content
        "embedding": embedding,
    }


def load_progress(progress_file: str) -> set:
    """Load set of already processed report IDs."""
    if os.path.exists(progress_file):
        with open(progress_file, "r") as f:
            return set(json.load(f))
    return set()


def save_progress(progress_file: str, processed_ids: set):
    """Save set of processed report IDs."""
    with open(progress_file, "w") as f:
        json.dump(list(processed_ids), f)


def upsert_batch(supabase: Client, records: List[Dict[str, Any]]) -> int:
    """Upsert a batch of records to Supabase."""
    if not records:
        return 0
    
    # Use upsert with report_id as the unique key
    result = supabase.table("vuln_reports").upsert(
        records,
        on_conflict="report_id"
    ).execute()
    
    return len(result.data) if result.data else 0


def ingest_reports(
    reports_dir: str,
    progress_file: str = "rag_ingest_progress.json",
    limit: int = 0,
    dry_run: bool = False,
):
    """Main ingestion function."""
    check_config()
    
    print(f"Starting ingestion from: {reports_dir}")
    print(f"Progress file: {progress_file}")
    
    # Parse all reports
    print("\n[1/4] Parsing reports...")
    reports = parse_reports_directory(reports_dir)
    print(f"  Found {len(reports)} valid reports")
    
    if limit > 0:
        reports = reports[:limit]
        print(f"  Limited to {limit} reports")
    
    # Load progress
    processed_ids = load_progress(progress_file)
    print(f"\n[2/4] Checking progress...")
    print(f"  Already processed: {len(processed_ids)} reports")
    
    # Filter out already processed
    reports_to_process = [r for r in reports if r.report_id not in processed_ids]
    print(f"  Remaining to process: {len(reports_to_process)} reports")
    
    if not reports_to_process:
        print("\nAll reports already processed!")
        return
    
    if dry_run:
        print("\n[DRY RUN] Would process the following reports:")
        for r in reports_to_process[:10]:
            print(f"  - {r.report_id}: {r.title[:60]}...")
        if len(reports_to_process) > 10:
            print(f"  ... and {len(reports_to_process) - 10} more")
        return
    
    # Initialize Supabase client
    supabase = create_supabase_client()
    
    # Process in batches
    print(f"\n[3/4] Generating embeddings and upserting...")
    
    total_processed = 0
    total_errors = 0
    db_records = []
    
    batch_start_time = time.time()
    
    for i in range(0, len(reports_to_process), BATCH_SIZE):
        batch = reports_to_process[i:i + BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1
        total_batches = (len(reports_to_process) + BATCH_SIZE - 1) // BATCH_SIZE
        
        print(f"\n  Batch {batch_num}/{total_batches} ({len(batch)} reports)")
        
        # Generate embedding texts
        embedding_texts = [generate_embedding_text(r) for r in batch]
        
        # Get embeddings
        try:
            embeddings = get_embeddings_batch(embedding_texts)
        except Exception as e:
            print(f"    Error getting embeddings: {e}")
            total_errors += len(batch)
            continue
        
        # Create database records
        for report, embedding in zip(batch, embeddings):
            try:
                record = report_to_db_record(report, embedding)
                db_records.append(record)
                processed_ids.add(report.report_id)
                total_processed += 1
            except Exception as e:
                print(f"    Error processing {report.report_id}: {e}")
                total_errors += 1
        
        # Upsert to database in batches
        if len(db_records) >= SUPABASE_BATCH_SIZE:
            try:
                upserted = upsert_batch(supabase, db_records)
                print(f"    Upserted {upserted} records to Supabase")
                db_records = []
            except Exception as e:
                print(f"    Error upserting to Supabase: {e}")
                # Don't clear records, try again later
        
        # Save progress periodically
        if batch_num % 5 == 0:
            save_progress(progress_file, processed_ids)
            print(f"    Progress saved ({len(processed_ids)} total)")
        
        # Rate limiting
        elapsed = time.time() - batch_start_time
        expected_time = (total_processed / EMBEDDINGS_PER_MINUTE) * 60
        if elapsed < expected_time:
            sleep_time = expected_time - elapsed
            if sleep_time > 0.5:
                print(f"    Rate limiting: sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)
    
    # Upsert remaining records
    if db_records:
        try:
            upserted = upsert_batch(supabase, db_records)
            print(f"\n  Final upsert: {upserted} records")
        except Exception as e:
            print(f"\n  Error in final upsert: {e}")
    
    # Final progress save
    save_progress(progress_file, processed_ids)
    
    # Summary
    print(f"\n[4/4] Ingestion complete!")
    print(f"  Total processed: {total_processed}")
    print(f"  Total errors: {total_errors}")
    print(f"  Progress saved: {len(processed_ids)} report IDs")


def verify_ingestion(sample_size: int = 5):
    """Verify ingestion by querying some records."""
    check_config()
    
    supabase = create_supabase_client()
    
    # Get sample records
    result = supabase.table("vuln_reports")\
        .select("report_id, title, vuln_type, severity")\
        .limit(sample_size)\
        .execute()
    
    print(f"\nSample of {len(result.data)} records in database:")
    for record in result.data:
        print(f"  [{record['severity']}] {record['vuln_type']}: {record['title'][:60]}...")
    
    # Get counts by vulnerability type
    all_records = supabase.table("vuln_reports")\
        .select("vuln_type")\
        .execute()
    
    vuln_counts = {}
    for r in all_records.data:
        vt = r["vuln_type"] or "unknown"
        vuln_counts[vt] = vuln_counts.get(vt, 0) + 1
    
    print(f"\nTotal records: {len(all_records.data)}")
    print("\nTop vulnerability types:")
    for vt, count in sorted(vuln_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  {vt}: {count}")


def test_search(query: str, top_k: int = 5):
    """Test semantic search functionality."""
    check_config()
    
    print(f"\nSearching for: '{query}'")
    
    # Generate query embedding
    embeddings = get_embeddings_batch([query])
    if not embeddings:
        print("Error generating query embedding")
        return
    
    query_embedding = embeddings[0]
    
    # Search using the Supabase function
    supabase = create_supabase_client()
    
    result = supabase.rpc(
        "search_similar_vulns",
        {
            "query_embedding": query_embedding,
            "match_threshold": 0.3,
            "match_count": top_k,
        }
    ).execute()
    
    print(f"\nFound {len(result.data)} similar reports:")
    for r in result.data:
        print(f"\n  [{r['severity']}] {r['vuln_type']}")
        print(f"  Title: {r['title'][:80]}...")
        print(f"  Similarity: {r['similarity']:.3f}")
        if r.get("source_url"):
            print(f"  URL: {r['source_url']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ingest HackerOne reports into Supabase RAG database"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Ingest command
    ingest_parser = subparsers.add_parser("ingest", help="Ingest reports into database")
    ingest_parser.add_argument(
        "--reports-dir",
        required=True,
        help="Directory containing report markdown files",
    )
    ingest_parser.add_argument(
        "--progress-file",
        default="rag_ingest_progress.json",
        help="File to track ingestion progress",
    )
    ingest_parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit number of reports to process (0 = all)",
    )
    ingest_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be processed without making changes",
    )
    
    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify ingestion status")
    verify_parser.add_argument(
        "--sample-size",
        type=int,
        default=5,
        help="Number of sample records to show",
    )
    
    # Search command
    search_parser = subparsers.add_parser("search", help="Test semantic search")
    search_parser.add_argument(
        "query",
        help="Search query",
    )
    search_parser.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="Number of results to return",
    )
    
    args = parser.parse_args()
    
    if args.command == "ingest":
        ingest_reports(
            args.reports_dir,
            args.progress_file,
            args.limit,
            args.dry_run,
        )
    elif args.command == "verify":
        verify_ingestion(args.sample_size)
    elif args.command == "search":
        test_search(args.query, args.top_k)
    else:
        parser.print_help()

