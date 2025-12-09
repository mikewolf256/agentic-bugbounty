#!/usr/bin/env python3
"""ngrok Helper

Helper for managing ngrok tunnels for callback server.
Provides public URL that tunnels to local callback server.
"""

import os
import subprocess
import time
from typing import Optional

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



class NgrokHelper:
    """Helper for managing ngrok tunnels"""
    
    def __init__(self, local_port: int = 8080, ngrok_api_url: str = "http://localhost:4040"):
        """Initialize ngrok helper
        
        Args:
            local_port: Local port to tunnel
            ngrok_api_url: ngrok API URL (default: http://localhost:4040)
        """
        self.local_port = local_port
        self.ngrok_api_url = ngrok_api_url.rstrip('/')
        self.process = None
        self.public_url = None
    
    def start_tunnel(self) -> str:
        """Start ngrok tunnel and return public URL
        
        Returns:
            Public URL (HTTPS preferred, HTTP fallback)
            
        Raises:
            RuntimeError: If ngrok is not found or fails to start
        """
        # Check if ngrok is installed
        try:
            subprocess.run(
                ["ngrok", "version"],
                check=True,
                capture_output=True,
                timeout=5
            )
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            raise RuntimeError(
                "ngrok not found. Install from https://ngrok.com/download\n"
                "Or set USE_NGROK=false to disable ngrok integration"
            )
        
        # Check if ngrok is already running
        existing_url = self._get_existing_tunnel_url()
        if existing_url:
            self.public_url = existing_url
            print(f"[NGROK] Using existing tunnel: {self.public_url}")
            return self.public_url
        
        # Start ngrok process
        print(f"[NGROK] Starting tunnel for port {self.local_port}...")
        self.process = subprocess.Popen(
            ["ngrok", "http", str(self.local_port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for ngrok to start
        time.sleep(3)
        
        # Get public URL
        self.public_url = self._get_public_url()
        if not self.public_url:
            if self.process:
                self.process.terminate()
                self.process.wait()
            raise RuntimeError("Failed to get ngrok public URL")
        
        print(f"[NGROK] Tunnel started: {self.public_url}")
        return self.public_url
    
    def _get_existing_tunnel_url(self) -> Optional[str]:
        """Check if ngrok is already running and return URL if available"""
        try:
            resp = safe_get(f"{self.ngrok_api_url}/api/tunnels", timeout=2)
            if resp.status_code == 200:
                tunnels = resp.json().get("tunnels", [])
                for tunnel in tunnels:
                    config = tunnel.get("config", {})
                    addr = config.get("addr", "")
                    if f":{self.local_port}" in addr:
                        public_url = tunnel.get("public_url")
                        if public_url:
                            return public_url
        except Exception:
            pass
        return None
    
    def _get_public_url(self) -> Optional[str]:
        """Get public URL from ngrok API
        
        Returns:
            Public URL (HTTPS preferred, HTTP fallback) or None
        """
        max_retries = 10
        for _ in range(max_retries):
            try:
                resp = safe_get(f"{self.ngrok_api_url}/api/tunnels", timeout=2)
                resp.raise_for_status()
                tunnels = resp.json().get("tunnels", [])
                
                # Prefer HTTPS
                for tunnel in tunnels:
                    if tunnel.get("proto") == "https":
                        public_url = tunnel.get("public_url")
                        if public_url:
                            return public_url
                
                # Fallback to HTTP
                for tunnel in tunnels:
                    if tunnel.get("proto") == "http":
                        public_url = tunnel.get("public_url")
                        if public_url:
                            return public_url
                
                # If no tunnels yet, wait and retry
                time.sleep(1)
            except Exception:
                time.sleep(1)
        
        return None
    
    def stop_tunnel(self):
        """Stop ngrok tunnel"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            except Exception:
                pass
            finally:
                self.process = None
        self.public_url = None
    
    def get_public_url(self) -> Optional[str]:
        """Get current public URL without starting tunnel
        
        Returns:
            Public URL or None if not available
        """
        if self.public_url:
            return self.public_url
        return self._get_existing_tunnel_url()


if __name__ == "__main__":
    # Test ngrok helper
    helper = NgrokHelper(local_port=8080)
    try:
        url = helper.start_tunnel()
        print(f"Public URL: {url}")
        print("Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping tunnel...")
        helper.stop_tunnel()
    except Exception as e:
        print(f"Error: {e}")
        helper.stop_tunnel()

