#!/usr/bin/env python3
"""Subdomain Enumeration Helper

Simple subdomain enumeration using DNS resolution and common wordlists.
Can be extended to use subfinder/amass via Docker for more comprehensive results.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from typing import List, Set


def enumerate_subdomains(domain: str, use_docker: bool = True) -> List[str]:
    """
    Enumerate subdomains for a given domain.
    
    Args:
        domain: Base domain (e.g., "example.com")
        use_docker: If True, try to use subfinder via Docker
    
    Returns:
        List of discovered subdomains
    """
    subdomains: Set[str] = []
    
    # Try subfinder via Docker first (if available)
    if use_docker:
        try:
            cmd = [
                "docker", "run", "--rm",
                "projectdiscovery/subfinder:latest",
                "-d", domain,
                "-silent",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    sub = line.strip()
                    if sub and sub.endswith(domain):
                        subdomains.add(sub)
                print(f"[SUBDOMAIN_ENUM] Found {len(subdomains)} subdomains via subfinder", file=sys.stderr)
                return sorted(subdomains)
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
            print(f"[SUBDOMAIN_ENUM] subfinder failed: {e}, falling back to basic enumeration", file=sys.stderr)
    
    # Fallback: Basic DNS brute force with common subdomains
    common_subs = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
        "webdisk", "admin", "email", "sites", "cdn", "m", "forum", "forums",
        "store", "support", "app", "apps", "blog", "blogs", "shop", "wiki",
        "api", "www2", "test", "mx", "static", "media", "portal", "vpn",
        "ns", "sftp", "web", "dev", "staging", "stage", "demo", "backup",
        "backups", "beta", "old", "new", "secure", "vps", "ns2", "cpanel",
        "whm", "autodiscover", "autoconfig", "imap", "pop3", "webmail",
        "exchange", "owa", "activesync", "git", "svn", "cvs", "hg",
    ]
    
    import socket
    for sub in common_subs:
        try:
            full_sub = f"{sub}.{domain}"
            socket.gethostbyname(full_sub)
            subdomains.add(full_sub)
        except socket.gaierror:
            continue
        except Exception:
            continue
    
    print(f"[SUBDOMAIN_ENUM] Found {len(subdomains)} subdomains via DNS brute force", file=sys.stderr)
    return sorted(subdomains)


def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Helper")
    parser.add_argument("--domain", required=True, help="Base domain to enumerate")
    parser.add_argument("--no-docker", action="store_true", help="Skip Docker/subfinder, use DNS brute force only")
    parser.add_argument("--output", help="Output file (default: stdout)")
    
    args = parser.parse_args()
    
    subdomains = enumerate_subdomains(args.domain, use_docker=not args.no_docker)
    
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for sub in subdomains:
                f.write(sub + "\n")
        print(f"[SUBDOMAIN_ENUM] Wrote {len(subdomains)} subdomains to {args.output}", file=sys.stderr)
    else:
        for sub in subdomains:
            print(sub)


if __name__ == "__main__":
    main()

