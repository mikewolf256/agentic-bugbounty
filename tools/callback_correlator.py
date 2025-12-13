#!/usr/bin/env python3
"""Callback Correlator

Client library for validators to register jobs and poll for callback hits.
Provides easy integration with SSRF, XXE, and other out-of-band validators.
"""

import os
import time
from typing import Dict, List, Optional, Any

import requests  # Always import for Session/exceptions support

# Import stealth HTTP client for WAF evasion
try:
    from tools.http_client import safe_get, safe_post, get_stealth_session
    USE_STEALTH = True
except ImportError:
    import requests
    USE_STEALTH = False
    
    def safe_get(url, **kwargs):
        return requests.get(url, **kwargs)
    
    def safe_post(url, **kwargs):
        return requests.post(url, **kwargs)



class CallbackCorrelator:
    """Client for interacting with the centralized callback server"""
    
    def __init__(self, callback_server_url: str):
        """Initialize callback correlator
        
        Args:
            callback_server_url: Base URL of callback server (e.g., http://localhost:8080)
        """
        self.callback_server_url = callback_server_url.rstrip('/')
        self.session = requests.Session()
        self.session.timeout = 10
    
    def register_job(self, job_id: str, tool: str, target: str, timeout: int = 300) -> str:
        """Register a new scan job and get callback token
        
        Args:
            job_id: Unique job identifier
            tool: Tool name (e.g., "ssrf", "xxe")
            target: Target URL being tested
            timeout: Timeout in seconds for polling
            
        Returns:
            Callback token
            
        Raises:
            requests.RequestException: If registration fails
        """
        url = f"{self.callback_server_url}/api/register"
        payload = {
            "job_id": job_id,
            "tool": tool,
            "target": target,
            "timeout": timeout
        }
        
        resp = self.session.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["token"]
    
    def get_callback_url(self, token: str) -> str:
        """Get full callback URL for use in payloads
        
        Args:
            token: Callback token
            
        Returns:
            Full callback URL
        """
        return f"{self.callback_server_url}/hit/{token}"
    
    def poll_hits(self, job_id: str, timeout: int = 300, interval: int = 2) -> List[Dict[str, Any]]:
        """Poll for callback hits, return when found or timeout
        
        Args:
            job_id: Job identifier
            timeout: Maximum time to poll in seconds
            interval: Polling interval in seconds
            
        Returns:
            List of callback hits (empty if none found)
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            hits = self.get_hits(job_id)
            if hits:
                return hits
            time.sleep(interval)
        return []
    
    def get_hits(self, job_id: str) -> List[Dict[str, Any]]:
        """Get all hits for a job_id
        
        Args:
            job_id: Job identifier
            
        Returns:
            List of callback hits
            
        Raises:
            requests.RequestException: If request fails
        """
        url = f"{self.callback_server_url}/api/hits/{job_id}"
        resp = self.session.get(url)
        resp.raise_for_status()
        data = resp.json()
        return data.get("hits", [])
    
    def wait_for_hit(self, job_id: str, timeout: int = 300, interval: int = 2) -> Optional[Dict[str, Any]]:
        """Wait for first callback hit
        
        Args:
            job_id: Job identifier
            timeout: Maximum time to wait in seconds
            interval: Polling interval in seconds
            
        Returns:
            First hit if found, None otherwise
        """
        hits = self.poll_hits(job_id, timeout, interval)
        return hits[0] if hits else None


def get_callback_correlator() -> Optional[CallbackCorrelator]:
    """Get callback correlator instance if callback server is configured
    
    Returns:
        CallbackCorrelator instance or None if not configured
    """
    callback_url = os.environ.get("CALLBACK_SERVER_URL")
    if callback_url:
        try:
            return CallbackCorrelator(callback_url)
        except Exception as e:
            print(f"[CALLBACK] Failed to initialize correlator: {e}")
            return None
    return None

