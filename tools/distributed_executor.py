#!/usr/bin/env python3
"""
Distributed Executor - Helper to dispatch jobs to AWS workers from MCP server

This module provides integration between the MCP server and the distributed
worker cluster running in EKS. It allows the MCP server to optionally dispatch
CPU-intensive scans to the cloud instead of running them locally.

Usage in MCP server:
    from tools.distributed_executor import DistributedExecutor, is_distributed_mode
    
    if is_distributed_mode():
        executor = DistributedExecutor()
        result = executor.submit_and_wait("whatweb", target_url)
    else:
        # Run locally
        result = run_whatweb_local(target_url)

Environment Variables:
    DISTRIBUTED_MODE - "true" to enable distributed execution
    AWS_REGION - AWS region
    SQS_QUEUE_URL - Job queue URL
    SQS_PRIORITY_QUEUE_URL - Priority queue URL
    RESULTS_QUEUE_URL - Results notification queue
    S3_BUCKET - Results storage bucket
"""

import os
import sys
import json
import time
from typing import Dict, Any, Optional, Callable
from uuid import uuid4

# Check if boto3 is available (optional dependency)
try:
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


# Configuration
DISTRIBUTED_MODE = os.environ.get("DISTRIBUTED_MODE", "false").lower() in ("true", "1", "yes")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SQS_QUEUE_URL = os.environ.get("SQS_QUEUE_URL")
SQS_PRIORITY_QUEUE_URL = os.environ.get("SQS_PRIORITY_QUEUE_URL")
RESULTS_QUEUE_URL = os.environ.get("RESULTS_QUEUE_URL")
S3_BUCKET = os.environ.get("S3_BUCKET")

# Default timeouts per tool (seconds)
TOOL_TIMEOUTS = {
    "whatweb": 300,
    "nuclei": 1800,
    "katana": 900,
    "dalfox": 600,
    "ffuf": 1200,
}


def is_distributed_mode() -> bool:
    """Check if distributed execution is enabled."""
    return DISTRIBUTED_MODE and BOTO3_AVAILABLE and bool(SQS_QUEUE_URL)


class DistributedExecutor:
    """
    Execute scan jobs on distributed AWS workers.
    
    This class provides two modes of operation:
    1. Fire-and-forget: Submit job and return immediately
    2. Submit-and-wait: Submit job and poll for results
    """
    
    def __init__(
        self,
        queue_url: Optional[str] = None,
        priority_queue_url: Optional[str] = None,
        results_queue_url: Optional[str] = None,
        s3_bucket: Optional[str] = None,
        region: str = AWS_REGION,
    ):
        if not BOTO3_AVAILABLE:
            raise ImportError("boto3 is required for distributed execution")
        
        self.queue_url = queue_url or SQS_QUEUE_URL
        self.priority_queue_url = priority_queue_url or SQS_PRIORITY_QUEUE_URL
        self.results_queue_url = results_queue_url or RESULTS_QUEUE_URL
        self.s3_bucket = s3_bucket or S3_BUCKET
        self.region = region
        
        if not self.queue_url:
            raise ValueError("SQS queue URL is required")
        
        self.sqs = boto3.client("sqs", region_name=region)
        self.s3 = boto3.client("s3", region_name=region)
    
    def submit(
        self,
        tool: str,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        priority: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Submit a job and return immediately.
        
        Returns:
            job_id for tracking
        """
        job_id = str(uuid4())
        
        job_payload = {
            "job_id": job_id,
            "tool": tool,
            "target": target,
            "options": options or {},
            "metadata": metadata or {},
            "submitted_at": time.time(),
        }
        
        queue_url = self.priority_queue_url if priority and self.priority_queue_url else self.queue_url
        
        self.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(job_payload),
            MessageAttributes={
                "tool": {"DataType": "String", "StringValue": tool},
                "job_id": {"DataType": "String", "StringValue": job_id},
            },
        )
        
        return job_id
    
    def submit_and_wait(
        self,
        tool: str,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        priority: bool = False,
        poll_interval: int = 5,
    ) -> Optional[Dict[str, Any]]:
        """
        Submit a job and wait for results.
        
        This polls S3 for results until timeout.
        
        Returns:
            Results dict or None if timeout
        """
        timeout = timeout or TOOL_TIMEOUTS.get(tool, 600)
        job_id = self.submit(tool, target, options, priority)
        
        start_time = time.time()
        s3_key_prefix = f"{tool}/"
        
        while time.time() - start_time < timeout:
            # Check S3 for results
            try:
                # List objects with job_id in the key
                response = self.s3.list_objects_v2(
                    Bucket=self.s3_bucket,
                    Prefix=s3_key_prefix,
                )
                
                for obj in response.get("Contents", []):
                    if job_id in obj["Key"]:
                        # Found results
                        result = self.s3.get_object(
                            Bucket=self.s3_bucket,
                            Key=obj["Key"],
                        )
                        return json.loads(result["Body"].read().decode("utf-8"))
            except Exception as e:
                print(f"[DISTRIBUTED] Error checking results: {e}", file=sys.stderr)
            
            time.sleep(poll_interval)
        
        print(f"[DISTRIBUTED] Timeout waiting for job {job_id}", file=sys.stderr)
        return None
    
    def get_job_status(self, job_id: str, tool: str) -> Optional[Dict[str, Any]]:
        """Check if a job has completed and return results if available."""
        s3_key_prefix = f"{tool}/"
        
        try:
            response = self.s3.list_objects_v2(
                Bucket=self.s3_bucket,
                Prefix=s3_key_prefix,
            )
            
            for obj in response.get("Contents", []):
                if job_id in obj["Key"]:
                    result = self.s3.get_object(
                        Bucket=self.s3_bucket,
                        Key=obj["Key"],
                    )
                    return json.loads(result["Body"].read().decode("utf-8"))
        except Exception:
            pass
        
        return None


def run_with_fallback(
    tool: str,
    target: str,
    local_runner: Callable[[str], Dict[str, Any]],
    options: Optional[Dict[str, Any]] = None,
    prefer_distributed: bool = True,
) -> Dict[str, Any]:
    """
    Run a scan with automatic fallback between distributed and local execution.
    
    Args:
        tool: Tool name
        target: Target URL
        local_runner: Function to run the tool locally
        options: Tool options
        prefer_distributed: Try distributed first if available
    
    Returns:
        Scan results
    """
    if prefer_distributed and is_distributed_mode():
        try:
            executor = DistributedExecutor()
            result = executor.submit_and_wait(tool, target, options)
            if result:
                return result
            print(f"[DISTRIBUTED] Falling back to local execution for {tool}", file=sys.stderr)
        except Exception as e:
            print(f"[DISTRIBUTED] Error: {e}, falling back to local", file=sys.stderr)
    
    # Run locally
    return local_runner(target)


# Example usage and testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test distributed executor")
    parser.add_argument("--tool", default="whatweb", help="Tool to test")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--wait", action="store_true", help="Wait for results")
    parser.add_argument("--timeout", type=int, default=300, help="Wait timeout")
    
    args = parser.parse_args()
    
    if not is_distributed_mode():
        print("Distributed mode not enabled. Set DISTRIBUTED_MODE=true and configure AWS.")
        sys.exit(1)
    
    executor = DistributedExecutor()
    
    if args.wait:
        print(f"Submitting {args.tool} job for {args.target} (waiting for results)...")
        result = executor.submit_and_wait(args.tool, args.target, timeout=args.timeout)
        if result:
            print(json.dumps(result, indent=2))
        else:
            print("No results (timeout)")
    else:
        job_id = executor.submit(args.tool, args.target)
        print(f"Submitted job: {job_id}")

