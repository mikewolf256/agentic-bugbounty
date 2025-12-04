#!/usr/bin/env python3
"""
WhatWeb Worker (Local) - Processes fingerprinting jobs from Redis

This worker:
1. Polls Redis list for a job message
2. Runs WhatWeb against the target
3. Saves results to mounted PVC
4. Sends completion notification to Redis results list
5. Exits (container terminates)
"""

import os
import sys
import json
import subprocess
import tempfile
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path

import redis

# Configuration from environment
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_QUEUE_NAME = os.environ.get("REDIS_QUEUE_NAME", "whatweb-jobs")
RESULTS_QUEUE_NAME = os.environ.get("RESULTS_QUEUE_NAME", "scan-results")
RESULTS_PATH = os.environ.get("RESULTS_PATH", "/mnt/scan-results")

# Redis client
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def receive_job() -> Optional[Dict[str, Any]]:
    """Receive a single job from Redis list (blocking)."""
    try:
        # Block for up to 10 seconds waiting for a job
        result = redis_client.blpop(REDIS_QUEUE_NAME, timeout=10)
        if not result:
            return None
        
        # result is a tuple: (list_name, message)
        _, message_json = result
        job_data = json.loads(message_json)
        
        # Generate a job_id if not present
        job_id = job_data.get("job_id", f"job-{datetime.utcnow().timestamp()}")
        job_data["job_id"] = job_id
        
        return job_data
    except redis.exceptions.ConnectionError as e:
        print(f"[WORKER] Redis connection error: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"[WORKER] Invalid JSON in job message: {e}")
        return None


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


def save_results(job_id: str, results: Dict[str, Any]) -> str:
    """Save results to PVC."""
    # Create directory structure: results/whatweb/YYYY/MM/DD/
    now = datetime.utcnow()
    result_dir = Path(RESULTS_PATH) / "whatweb" / now.strftime("%Y/%m/%d")
    result_dir.mkdir(parents=True, exist_ok=True)
    
    # Write results file
    result_file = result_dir / f"{job_id}.json"
    with open(result_file, "w") as f:
        json.dump(results, f, indent=2)
    
    return str(result_file)


def send_completion(job_id: str, result_path: str, results: Dict[str, Any]):
    """Send completion notification to Redis results list."""
    message = {
        "job_id": job_id,
        "tool": "whatweb",
        "status": "completed",
        "result_path": result_path,
        "target": results.get("target"),
        "technologies_count": len(results.get("technologies", [])),
        "timestamp": datetime.utcnow().isoformat(),
    }
    
    try:
        redis_client.rpush(RESULTS_QUEUE_NAME, json.dumps(message))
    except Exception as e:
        print(f"[WORKER] Failed to send completion notification: {e}")


def main():
    print("[WORKER] WhatWeb worker (local) starting...")
    print(f"[WORKER] Redis: {REDIS_HOST}:{REDIS_PORT}")
    print(f"[WORKER] Queue: {REDIS_QUEUE_NAME}")
    print(f"[WORKER] Results path: {RESULTS_PATH}")
    
    # Test Redis connection
    try:
        redis_client.ping()
        print("[WORKER] Redis connection successful")
    except Exception as e:
        print(f"[WORKER] Redis connection failed: {e}")
        return 1
    
    # Receive job
    job = receive_job()
    if not job:
        print("[WORKER] No jobs available, exiting")
        return 0
    
    job_id = job.get("job_id", "unknown")
    target = job.get("target")
    options = job.get("options", {})
    
    print(f"[WORKER] Processing job {job_id}")
    print(f"[WORKER] Target: {target}")
    
    try:
        # Run WhatWeb
        results = run_whatweb(target=target, options=options)
        
        # Add job metadata
        results["job_id"] = job_id
        results["processed_at"] = datetime.utcnow().isoformat()
        
        # Save to PVC
        result_path = save_results(job_id, results)
        print(f"[WORKER] Results saved to {result_path}")
        
        # Send completion notification
        send_completion(job_id, result_path, results)
        
        print(f"[WORKER] Job {job_id} completed successfully")
        return 0
        
    except Exception as e:
        print(f"[WORKER] Error processing job {job_id}: {e}")
        import traceback
        traceback.print_exc()
        # Push job back to queue for retry (optional)
        return 1


if __name__ == "__main__":
    sys.exit(main())

