#!/usr/bin/env python3
"""
Job Results Poller - Poll for completed scan job results from SQS

This runs alongside the MCP server to receive results from distributed workers
and integrate them back into the local pipeline (triage, reporting, etc.).

Usage:
    # Run as a background service
    python job_results_poller.py
    
    # Run with callback to MCP server
    python job_results_poller.py --mcp-url http://localhost:8000

Environment Variables:
    AWS_REGION - AWS region
    RESULTS_QUEUE_URL - SQS queue for job completion notifications
    S3_BUCKET - S3 bucket where results are stored
    MCP_SERVER_URL - MCP server URL for callbacks
"""

import os
import sys
import json
import time
import signal
from datetime import datetime
from typing import Dict, Any, Optional

try:
    import boto3
    import requests
except ImportError:
    print("Missing dependencies. Install with: pip install boto3 requests")
    sys.exit(1)


# Configuration
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
RESULTS_QUEUE_URL = os.environ.get("RESULTS_QUEUE_URL")
S3_BUCKET = os.environ.get("S3_BUCKET")
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8000")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "./output_zap")

# AWS clients
sqs = boto3.client("sqs", region_name=AWS_REGION)
s3 = boto3.client("s3", region_name=AWS_REGION)

# Graceful shutdown
running = True


def signal_handler(signum, frame):
    global running
    print("\n[POLLER] Shutting down...")
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def download_results(s3_path: str) -> Dict[str, Any]:
    """Download results from S3."""
    # Parse s3://bucket/key format
    if s3_path.startswith("s3://"):
        s3_path = s3_path[5:]
    
    bucket, key = s3_path.split("/", 1)
    
    response = s3.get_object(Bucket=bucket, Key=key)
    content = response["Body"].read().decode("utf-8")
    return json.loads(content)


def save_results_locally(tool: str, job_id: str, results: Dict[str, Any]) -> str:
    """Save results to local output directory."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    filename = f"{tool}_{job_id}_{int(time.time())}.json"
    filepath = os.path.join(OUTPUT_DIR, filename)
    
    with open(filepath, "w") as f:
        json.dump(results, f, indent=2)
    
    return filepath


def notify_mcp(tool: str, results: Dict[str, Any], local_path: str):
    """Notify MCP server about completed job."""
    # Map tool to appropriate MCP endpoint
    tool_endpoints = {
        "whatweb": "/mcp/ingest_whatweb_results",
        "nuclei": "/mcp/ingest_nuclei_results",
        "katana": "/mcp/ingest_katana_results",
    }
    
    endpoint = tool_endpoints.get(tool)
    if not endpoint:
        print(f"[POLLER] No MCP endpoint for tool: {tool}")
        return
    
    try:
        url = f"{MCP_SERVER_URL.rstrip('/')}{endpoint}"
        response = requests.post(
            url,
            json={
                "results": results,
                "local_path": local_path,
            },
            timeout=30,
        )
        if response.status_code == 200:
            print(f"[POLLER] Notified MCP: {endpoint}")
        else:
            print(f"[POLLER] MCP notification failed: {response.status_code}")
    except Exception as e:
        print(f"[POLLER] MCP notification error: {e}")


def process_message(message: Dict[str, Any]) -> bool:
    """Process a single result message."""
    try:
        body = json.loads(message["Body"])
        
        job_id = body.get("job_id")
        tool = body.get("tool")
        s3_path = body.get("s3_path")
        
        print(f"[POLLER] Processing {tool} job {job_id}")
        
        # Download results from S3
        results = download_results(s3_path)
        
        # Save locally
        local_path = save_results_locally(tool, job_id, results)
        print(f"[POLLER] Saved to {local_path}")
        
        # Notify MCP server
        notify_mcp(tool, results, local_path)
        
        return True
        
    except Exception as e:
        print(f"[POLLER] Error processing message: {e}")
        return False


def poll_results():
    """Main polling loop."""
    if not RESULTS_QUEUE_URL:
        print("[POLLER] ERROR: RESULTS_QUEUE_URL not set")
        return
    
    print(f"[POLLER] Starting results poller...")
    print(f"[POLLER] Queue: {RESULTS_QUEUE_URL}")
    print(f"[POLLER] Output: {OUTPUT_DIR}")
    
    while running:
        try:
            response = sqs.receive_message(
                QueueUrl=RESULTS_QUEUE_URL,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=20,
                VisibilityTimeout=60,
            )
            
            messages = response.get("Messages", [])
            
            for message in messages:
                if process_message(message):
                    # Delete successfully processed message
                    sqs.delete_message(
                        QueueUrl=RESULTS_QUEUE_URL,
                        ReceiptHandle=message["ReceiptHandle"],
                    )
                    
        except Exception as e:
            print(f"[POLLER] Poll error: {e}")
            time.sleep(5)
    
    print("[POLLER] Stopped")


if __name__ == "__main__":
    poll_results()

