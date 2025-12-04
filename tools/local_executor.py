#!/usr/bin/env python3
"""
Local Executor - Helper to dispatch jobs to local K8s workers from MCP server

This module provides integration between the MCP server and the local Kubernetes
worker cluster. It allows the MCP server to dispatch CPU-intensive scans to
local K8s workers instead of running them in local Docker.

Usage in MCP server:
    from tools.local_executor import LocalExecutor, is_local_k8s_mode
    
    if is_local_k8s_mode():
        executor = LocalExecutor()
        result = executor.submit_and_wait("whatweb", target_url)
    else:
        # Run locally
        result = run_whatweb_local(target_url)

Environment Variables:
    LOCAL_K8S_MODE - "true" to enable local K8s execution
    REDIS_HOST - Redis host (default: localhost)
    REDIS_PORT - Redis port (default: 6379)
    RESULTS_PATH - Path to results PVC mount (default: /tmp/agentic-bugbounty-results)
"""

import os
import sys
import json
import time
from typing import Dict, Any, Optional, Callable
from uuid import uuid4
from pathlib import Path

# Check if redis is available (optional dependency)
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


# Configuration - Note: LOCAL_K8S_MODE is checked at runtime, not import time
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
RESULTS_PATH = os.environ.get("RESULTS_PATH", "/tmp/agentic-bugbounty-results")

# Default timeouts per tool (seconds)
TOOL_TIMEOUTS = {
    "whatweb": 300,
    "nuclei": 1800,
    "katana": 900,
    "dalfox": 600,
    "ffuf": 1200,
}

# Queue names per tool
TOOL_QUEUES = {
    "whatweb": "whatweb-jobs",
    "nuclei": "nuclei-jobs",
    "katana": "katana-jobs",
    "dalfox": "dalfox-jobs",
    "ffuf": "ffuf-jobs",
}


def is_local_k8s_mode() -> bool:
    """Check if local K8s execution is enabled.
    
    Reads environment variable at call time, not import time,
    so it can be set via command-line flags.
    """
    local_k8s_mode = os.environ.get("LOCAL_K8S_MODE", "false").lower() in ("true", "1", "yes")
    return local_k8s_mode and REDIS_AVAILABLE


class LocalExecutor:
    """
    Execute scan jobs on local Kubernetes workers.
    
    This class provides two modes of operation:
    1. Fire-and-forget: Submit job and return immediately
    2. Submit-and-wait: Submit job and poll for results
    """
    
    def __init__(
        self,
        redis_host: Optional[str] = None,
        redis_port: Optional[int] = None,
        results_path: Optional[str] = None,
    ):
        if not REDIS_AVAILABLE:
            raise ImportError("redis is required for local K8s execution. Install with: pip install redis")
        
        self.redis_host = redis_host or REDIS_HOST
        self.redis_port = redis_port or REDIS_PORT
        self.results_path = Path(results_path or RESULTS_PATH)
        
        try:
            self.redis_client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                decode_responses=True,
                socket_connect_timeout=5,
            )
            # Test connection
            self.redis_client.ping()
        except redis.exceptions.ConnectionError as e:
            raise ConnectionError(f"Failed to connect to Redis at {self.redis_host}:{self.redis_port}: {e}")
    
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
        
        queue_name = TOOL_QUEUES.get(tool)
        if not queue_name:
            raise ValueError(f"Unknown tool: {tool}. Supported tools: {list(TOOL_QUEUES.keys())}")
        
        # Push to Redis list (left push for priority, right push for normal)
        if priority:
            self.redis_client.lpush(queue_name, json.dumps(job_payload))
        else:
            self.redis_client.rpush(queue_name, json.dumps(job_payload))
        
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
        
        This polls the results queue and file system for results until timeout.
        
        Returns:
            Results dict or None if timeout
        """
        timeout = timeout or TOOL_TIMEOUTS.get(tool, 600)
        job_id = self.submit(tool, target, options, priority)
        
        start_time = time.time()
        results_queue = "scan-results"
        
        while time.time() - start_time < timeout:
            # Check Redis results queue
            try:
                # Pop from results queue (non-blocking)
                result_json = self.redis_client.lpop(results_queue)
                if result_json:
                    result = json.loads(result_json)
                    result_job_id = result.get("job_id")
                    
                    if result_job_id == job_id:
                        # Found our result, now read the actual file
                        result_path = result.get("result_path")
                        if result_path and Path(result_path).exists():
                            with open(result_path, "r") as f:
                                return json.load(f)
                        # If file doesn't exist, continue waiting
                    else:
                        # This result belongs to a different job - put it back in the queue
                        # Use rpush to add it back at the end (FIFO order)
                        self.redis_client.rpush(results_queue, result_json)
            except json.JSONDecodeError:
                # Invalid JSON - can't put it back, just skip it
                pass
            except Exception as e:
                print(f"[LOCAL_K8S] Error checking results: {e}", file=sys.stderr)
            
            # Also check file system directly (fallback)
            try:
                tool_dir = self.results_path / tool
                if tool_dir.exists():
                    # Look for files with job_id in name
                    for result_file in tool_dir.rglob(f"*{job_id}*.json"):
                        with open(result_file, "r") as f:
                            return json.load(f)
            except Exception as e:
                pass
            
            time.sleep(poll_interval)
        
        print(f"[LOCAL_K8S] Timeout waiting for job {job_id}", file=sys.stderr)
        return None
    
    def get_job_status(self, job_id: str, tool: str) -> Optional[Dict[str, Any]]:
        """Check if a job has completed and return results if available."""
        # Check file system
        try:
            tool_dir = self.results_path / tool
            if tool_dir.exists():
                for result_file in tool_dir.rglob(f"*{job_id}*.json"):
                    with open(result_file, "r") as f:
                        return json.load(f)
        except Exception:
            pass
        
        return None


def run_with_fallback(
    tool: str,
    target: str,
    local_runner: Callable[[str], Dict[str, Any]],
    options: Optional[Dict[str, Any]] = None,
    prefer_local_k8s: bool = True,
) -> Dict[str, Any]:
    """
    Run a scan with automatic fallback between local K8s and local Docker execution.
    
    Args:
        tool: Tool name
        target: Target URL
        local_runner: Function to run the tool locally
        options: Tool options
        prefer_local_k8s: Try local K8s first if available
    
    Returns:
        Scan results
    """
    if prefer_local_k8s and is_local_k8s_mode():
        try:
            executor = LocalExecutor()
            result = executor.submit_and_wait(tool, target, options)
            if result:
                return result
            print(f"[LOCAL_K8S] Falling back to local Docker execution for {tool}", file=sys.stderr)
        except Exception as e:
            print(f"[LOCAL_K8S] Error: {e}, falling back to local Docker", file=sys.stderr)
    
    # Run locally
    return local_runner(target)


# Example usage and testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test local executor")
    parser.add_argument("--tool", default="whatweb", help="Tool to test")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--wait", action="store_true", help="Wait for results")
    parser.add_argument("--timeout", type=int, default=300, help="Wait timeout")
    
    args = parser.parse_args()
    
    if not is_local_k8s_mode():
        print("Local K8s mode not enabled. Set LOCAL_K8S_MODE=true and ensure Redis is running.")
        sys.exit(1)
    
    executor = LocalExecutor()
    
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

