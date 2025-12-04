#!/usr/bin/env python3
"""
WhatWeb Worker - Processes fingerprinting jobs from SQS

This worker:
1. Polls SQS for a job message
2. Runs WhatWeb against the target
3. Uploads results to S3
4. Sends completion notification to results queue
5. Deletes the processed message
6. Exits (container terminates)
"""

import os
import sys
import json
import subprocess
import tempfile
from datetime import datetime
from typing import Optional, Dict, Any

import boto3

# Configuration from environment
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SQS_QUEUE_URL = os.environ["SQS_QUEUE_URL"]
S3_BUCKET = os.environ["S3_BUCKET"]
RESULTS_QUEUE_URL = os.environ.get("RESULTS_QUEUE_URL")

# AWS clients
sqs = boto3.client("sqs", region_name=AWS_REGION)
s3 = boto3.client("s3", region_name=AWS_REGION)


def receive_job() -> Optional[Dict[str, Any]]:
    """Receive a single job from SQS."""
    response = sqs.receive_message(
        QueueUrl=SQS_QUEUE_URL,
        MaxNumberOfMessages=1,
        WaitTimeSeconds=10,
        VisibilityTimeout=300,  # 5 min to process
        MessageAttributeNames=["All"],
    )
    
    messages = response.get("Messages", [])
    if not messages:
        return None
    
    message = messages[0]
    return {
        "receipt_handle": message["ReceiptHandle"],
        "body": json.loads(message["Body"]),
        "message_id": message["MessageId"],
    }


def run_whatweb(target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """Run WhatWeb against a target."""
    options = options or {}
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        output_file = f.name
    
    cmd = [
        "whatweb",
        "-a", str(options.get("aggression", 3)),
        "--log-json", output_file,
        target,
    ]
    
    print(f"[WHATWEB] Running: {' '.join(cmd)}")
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=options.get("timeout", 120),
    )
    
    # Parse JSON output
    technologies = []
    plugins = {}
    raw_output = ""
    
    try:
        with open(output_file, "r") as f:
            raw_output = f.read()
            for line in raw_output.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    for plugin_name, plugin_data in data.get("plugins", {}).items():
                        technologies.append(plugin_name)
                        plugins[plugin_name] = plugin_data
                except json.JSONDecodeError:
                    continue
    finally:
        os.unlink(output_file)
    
    return {
        "target": target,
        "technologies": list(set(technologies)),
        "plugins": plugins,
        "raw_output": raw_output,
        "exit_code": result.returncode,
        "stderr": result.stderr,
    }


def upload_results(job_id: str, results: Dict[str, Any]) -> str:
    """Upload results to S3."""
    key = f"whatweb/{datetime.utcnow().strftime('%Y/%m/%d')}/{job_id}.json"
    
    s3.put_object(
        Bucket=S3_BUCKET,
        Key=key,
        Body=json.dumps(results, indent=2),
        ContentType="application/json",
    )
    
    return f"s3://{S3_BUCKET}/{key}"


def send_completion(job_id: str, s3_path: str, results: Dict[str, Any]):
    """Send completion notification to results queue."""
    if not RESULTS_QUEUE_URL:
        return
    
    message = {
        "job_id": job_id,
        "tool": "whatweb",
        "status": "completed",
        "s3_path": s3_path,
        "target": results.get("target"),
        "technologies_count": len(results.get("technologies", [])),
        "timestamp": datetime.utcnow().isoformat(),
    }
    
    sqs.send_message(
        QueueUrl=RESULTS_QUEUE_URL,
        MessageBody=json.dumps(message),
    )


def delete_message(receipt_handle: str):
    """Delete processed message from queue."""
    sqs.delete_message(
        QueueUrl=SQS_QUEUE_URL,
        ReceiptHandle=receipt_handle,
    )


def main():
    print("[WORKER] WhatWeb worker starting...")
    
    # Receive job
    job = receive_job()
    if not job:
        print("[WORKER] No jobs available, exiting")
        return 0
    
    job_id = job["message_id"]
    job_body = job["body"]
    receipt_handle = job["receipt_handle"]
    
    print(f"[WORKER] Processing job {job_id}")
    print(f"[WORKER] Target: {job_body.get('target')}")
    
    try:
        # Run WhatWeb
        results = run_whatweb(
            target=job_body["target"],
            options=job_body.get("options", {}),
        )
        
        # Add job metadata
        results["job_id"] = job_id
        results["processed_at"] = datetime.utcnow().isoformat()
        
        # Upload to S3
        s3_path = upload_results(job_id, results)
        print(f"[WORKER] Results uploaded to {s3_path}")
        
        # Send completion notification
        send_completion(job_id, s3_path, results)
        
        # Delete from queue
        delete_message(receipt_handle)
        print(f"[WORKER] Job {job_id} completed successfully")
        
        return 0
        
    except Exception as e:
        print(f"[WORKER] Error processing job {job_id}: {e}")
        # Don't delete message - it will become visible again for retry
        return 1


if __name__ == "__main__":
    sys.exit(main())

