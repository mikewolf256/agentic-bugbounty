#!/usr/bin/env python3
"""
Job Submitter - Submit scan jobs to the AWS SQS queue for processing

This tool is used by the MCP server to dispatch jobs to the distributed
worker cluster. Workers automatically scale based on queue depth.

Usage:
    # Submit a WhatWeb job
    python job_submitter.py --tool whatweb --target http://example.com
    
    # Submit a Nuclei job with options
    python job_submitter.py --tool nuclei --target http://example.com \
        --options '{"templates": ["http/cves/"], "severity": ["critical", "high"]}'
    
    # Submit with high priority
    python job_submitter.py --tool whatweb --target http://example.com --priority

Environment Variables:
    AWS_REGION - AWS region (default: us-east-1)
    SQS_QUEUE_URL - Main job queue URL
    SQS_PRIORITY_QUEUE_URL - Priority job queue URL (optional)
"""

import os
import sys
import json
import argparse
from datetime import datetime
from typing import Dict, Any, Optional
from uuid import uuid4

try:
    import boto3
except ImportError:
    print("Missing boto3. Install with: pip install boto3")
    sys.exit(1)


# Configuration
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SQS_QUEUE_URL = os.environ.get("SQS_QUEUE_URL")
SQS_PRIORITY_QUEUE_URL = os.environ.get("SQS_PRIORITY_QUEUE_URL")

# Tool configurations (timeouts, etc.)
TOOL_CONFIGS = {
    "whatweb": {
        "visibility_timeout": 300,  # 5 min
        "default_options": {"aggression": 3, "timeout": 120},
    },
    "nuclei": {
        "visibility_timeout": 1800,  # 30 min
        "default_options": {"timeout": 1800, "rate_limit": 150},
    },
    "katana": {
        "visibility_timeout": 900,  # 15 min
        "default_options": {"timeout": 900, "depth": 3},
    },
    "dalfox": {
        "visibility_timeout": 600,  # 10 min
        "default_options": {"timeout": 600},
    },
    "ffuf": {
        "visibility_timeout": 1200,  # 20 min
        "default_options": {"timeout": 1200, "rate": 100},
    },
}


class JobSubmitter:
    """Submit scan jobs to SQS for distributed processing."""
    
    def __init__(
        self,
        queue_url: Optional[str] = None,
        priority_queue_url: Optional[str] = None,
        region: str = AWS_REGION,
    ):
        self.queue_url = queue_url or SQS_QUEUE_URL
        self.priority_queue_url = priority_queue_url or SQS_PRIORITY_QUEUE_URL
        self.region = region
        
        if not self.queue_url:
            raise ValueError("SQS_QUEUE_URL environment variable or queue_url parameter required")
        
        self.sqs = boto3.client("sqs", region_name=region)
    
    def submit(
        self,
        tool: str,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        priority: bool = False,
        callback_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Submit a scan job to the queue.
        
        Args:
            tool: Tool name (whatweb, nuclei, katana, etc.)
            target: Target URL or host
            options: Tool-specific options
            priority: Use priority queue for faster processing
            callback_url: URL to POST results when complete
            metadata: Additional metadata to include in job
        
        Returns:
            Dict with job_id and message_id
        """
        if tool not in TOOL_CONFIGS:
            raise ValueError(f"Unknown tool: {tool}. Supported: {list(TOOL_CONFIGS.keys())}")
        
        tool_config = TOOL_CONFIGS[tool]
        
        # Merge default options with provided options
        merged_options = {**tool_config.get("default_options", {})}
        if options:
            merged_options.update(options)
        
        # Build job payload
        job_id = str(uuid4())
        job_payload = {
            "job_id": job_id,
            "tool": tool,
            "target": target,
            "options": merged_options,
            "submitted_at": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
        }
        
        if callback_url:
            job_payload["callback_url"] = callback_url
        
        # Select queue
        queue_url = self.priority_queue_url if priority and self.priority_queue_url else self.queue_url
        
        # Send message
        response = self.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(job_payload),
            MessageAttributes={
                "tool": {
                    "DataType": "String",
                    "StringValue": tool,
                },
                "priority": {
                    "DataType": "String",
                    "StringValue": "high" if priority else "normal",
                },
            },
        )
        
        return {
            "job_id": job_id,
            "message_id": response["MessageId"],
            "queue_url": queue_url,
            "tool": tool,
            "target": target,
        }
    
    def submit_batch(
        self,
        tool: str,
        targets: list,
        options: Optional[Dict[str, Any]] = None,
        priority: bool = False,
    ) -> list:
        """Submit multiple jobs for the same tool."""
        results = []
        for target in targets:
            result = self.submit(tool, target, options, priority)
            results.append(result)
        return results
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics (message counts)."""
        stats = {}
        
        for name, url in [("main", self.queue_url), ("priority", self.priority_queue_url)]:
            if not url:
                continue
            
            response = self.sqs.get_queue_attributes(
                QueueUrl=url,
                AttributeNames=[
                    "ApproximateNumberOfMessages",
                    "ApproximateNumberOfMessagesNotVisible",
                    "ApproximateNumberOfMessagesDelayed",
                ],
            )
            
            attrs = response.get("Attributes", {})
            stats[name] = {
                "pending": int(attrs.get("ApproximateNumberOfMessages", 0)),
                "in_flight": int(attrs.get("ApproximateNumberOfMessagesNotVisible", 0)),
                "delayed": int(attrs.get("ApproximateNumberOfMessagesDelayed", 0)),
            }
        
        return stats


def main():
    parser = argparse.ArgumentParser(
        description="Submit scan jobs to AWS SQS for distributed processing"
    )
    
    parser.add_argument(
        "--tool",
        required=True,
        choices=list(TOOL_CONFIGS.keys()),
        help="Scan tool to use",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL or host",
    )
    parser.add_argument(
        "--options",
        type=json.loads,
        default={},
        help="Tool options as JSON string",
    )
    parser.add_argument(
        "--priority",
        action="store_true",
        help="Use priority queue for faster processing",
    )
    parser.add_argument(
        "--callback-url",
        help="URL to POST results when complete",
    )
    parser.add_argument(
        "--queue-url",
        help="Override SQS queue URL",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show queue statistics instead of submitting",
    )
    
    args = parser.parse_args()
    
    try:
        submitter = JobSubmitter(queue_url=args.queue_url)
        
        if args.stats:
            stats = submitter.get_queue_stats()
            print(json.dumps(stats, indent=2))
            return 0
        
        result = submitter.submit(
            tool=args.tool,
            target=args.target,
            options=args.options,
            priority=args.priority,
            callback_url=args.callback_url,
        )
        
        print(f"Job submitted successfully!")
        print(json.dumps(result, indent=2))
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

