#!/usr/bin/env python3
"""Stealth HTTP Client for WAF Evasion

Provides browser-like HTTP requests with:
- Realistic User-Agent rotation
- Browser-like headers (Accept, Accept-Language, etc.)
- Rate limiting with jitter
- Proxy support (single or rotating)
- WAF detection and handling
- Automatic retry with backoff
"""

import os
import random
import time
import logging
from typing import Dict, Any, Optional, List, Union
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logger = logging.getLogger(__name__)

# ============================================================================
# User-Agent Pool - Realistic browser UAs (updated Dec 2024)
# ============================================================================

USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

# ============================================================================
# Browser-like Headers
# ============================================================================

def get_browser_headers(
    referer: Optional[str] = None,
    origin: Optional[str] = None,
    content_type: Optional[str] = None,
    accept: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, str]:
    """Generate browser-like headers.
    
    Args:
        referer: Optional Referer header
        origin: Optional Origin header
        content_type: Optional Content-Type (default for forms/JSON)
        accept: Optional Accept header (defaults to browser-like)
        user_agent: Optional specific UA (defaults to random from pool)
        
    Returns:
        Dict of headers mimicking a real browser
    """
    headers = {
        "User-Agent": user_agent or random.choice(USER_AGENTS),
        "Accept": accept or "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    
    if referer:
        headers["Referer"] = referer
        headers["Sec-Fetch-Site"] = "same-origin"
        
    if origin:
        headers["Origin"] = origin
        
    if content_type:
        headers["Content-Type"] = content_type
        # Adjust Accept for API requests
        if "json" in content_type.lower():
            headers["Accept"] = "application/json, text/plain, */*"
            headers["Sec-Fetch-Dest"] = "empty"
            headers["Sec-Fetch-Mode"] = "cors"
            
    return headers


def get_api_headers(
    user_agent: Optional[str] = None,
    auth_token: Optional[str] = None,
    content_type: str = "application/json",
) -> Dict[str, str]:
    """Generate headers for API requests.
    
    Args:
        user_agent: Optional specific UA
        auth_token: Optional Bearer token
        content_type: Content-Type header
        
    Returns:
        Dict of headers for API calls
    """
    headers = {
        "User-Agent": user_agent or random.choice(USER_AGENTS),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": content_type,
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }
    
    if auth_token:
        if not auth_token.startswith("Bearer "):
            auth_token = f"Bearer {auth_token}"
        headers["Authorization"] = auth_token
        
    return headers


# ============================================================================
# WAF Detection
# ============================================================================

# WAF signatures for detection
WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "body": ["cloudflare", "attention required", "cf-browser-verification", "checking your browser"],
        "cookies": ["__cf_bm", "__cfruid", "cf_clearance"],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn"],
        "body": ["akamai", "access denied", "reference #"],
        "cookies": ["ak_bmsc", "bm_sv"],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "body": ["aws waf", "request blocked", "automated access"],
        "cookies": ["awsalb", "awsalbcors"],
    },
    "imperva": {
        "headers": ["x-iinfo", "x-cdn"],
        "body": ["incapsula", "imperva", "incident id"],
        "cookies": ["incap_ses", "visid_incap"],
    },
    "f5_big_ip": {
        "headers": ["x-wa-info"],
        "body": ["f5 networks", "big-ip", "the requested url was rejected"],
        "cookies": ["TS", "BIGipServer"],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body": ["sucuri", "access denied", "sucuri website firewall"],
        "cookies": ["sucuri_cloudproxy"],
    },
    "wordfence": {
        "headers": [],
        "body": ["wordfence", "a potentially unsafe operation", "your access to this site"],
        "cookies": ["wfwaf-authcookie"],
    },
    "modsecurity": {
        "headers": ["x-mod-sec-log"],
        "body": ["mod_security", "modsecurity", "not acceptable"],
        "cookies": [],
    },
}


def detect_waf(response: requests.Response) -> Optional[str]:
    """Detect if response indicates WAF blocking.
    
    Args:
        response: requests.Response object
        
    Returns:
        WAF name if detected, None otherwise
    """
    # Quick check - common WAF status codes
    if response.status_code not in [403, 406, 429, 503, 520, 521, 522, 523, 524]:
        return None
    
    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
    body_lower = response.text.lower() if response.text else ""
    cookies = {c.name.lower(): c.value for c in response.cookies}
    
    for waf_name, signatures in WAF_SIGNATURES.items():
        # Check headers
        for header in signatures["headers"]:
            if header.lower() in headers_lower:
                logger.debug(f"WAF detected via header: {waf_name} ({header})")
                return waf_name
        
        # Check body
        for pattern in signatures["body"]:
            if pattern.lower() in body_lower:
                logger.debug(f"WAF detected via body: {waf_name} ({pattern})")
                return waf_name
        
        # Check cookies
        for cookie in signatures["cookies"]:
            if cookie.lower() in cookies:
                logger.debug(f"WAF detected via cookie: {waf_name} ({cookie})")
                return waf_name
    
    # Generic WAF detection for unknown WAFs
    generic_indicators = [
        "access denied",
        "forbidden",
        "blocked",
        "security check",
        "bot detection",
        "automated request",
    ]
    
    for indicator in generic_indicators:
        if indicator in body_lower and len(response.text) < 5000:  # Short error pages
            logger.debug(f"Possible WAF detected via generic indicator: {indicator}")
            return "unknown"
    
    return None


def is_cloudflare_challenge(response: requests.Response) -> bool:
    """Check if response is a Cloudflare JS challenge.
    
    Args:
        response: requests.Response object
        
    Returns:
        True if CF challenge detected
    """
    if response.status_code != 403:
        return False
    
    cf_ray = response.headers.get("cf-ray")
    if not cf_ray:
        return False
    
    body_lower = response.text.lower()
    challenge_indicators = [
        "checking your browser",
        "cf-browser-verification",
        "enable javascript",
        "ray id:",
    ]
    
    return any(indicator in body_lower for indicator in challenge_indicators)


# ============================================================================
# Stealth Session Class
# ============================================================================

class StealthSession:
    """HTTP session with WAF evasion capabilities.
    
    Features:
    - Rate limiting with jitter
    - User-Agent rotation
    - Browser-like headers
    - Proxy support
    - WAF detection and handling
    - Automatic retry with backoff
    """
    
    def __init__(
        self,
        rate_limit: float = 2.0,
        jitter: float = 0.5,
        proxy: Optional[str] = None,
        proxies: Optional[List[str]] = None,
        rotate_ua: bool = True,
        rotate_ua_per_request: bool = False,
        timeout: int = 30,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        verify_ssl: bool = True,
    ):
        """Initialize stealth session.
        
        Args:
            rate_limit: Max requests per second (default 2.0)
            jitter: Random delay variance in seconds (default 0.5)
            proxy: Single proxy URL (http://user:pass@host:port)
            proxies: List of proxy URLs for rotation
            rotate_ua: Whether to rotate User-Agent
            rotate_ua_per_request: Rotate UA every request (vs per session)
            timeout: Default request timeout in seconds
            max_retries: Max retry attempts on failure
            backoff_factor: Exponential backoff multiplier
            verify_ssl: Whether to verify SSL certificates
        """
        self.rate_limit = rate_limit
        self.jitter = jitter
        self.proxy = proxy
        self.proxies = proxies or []
        self.rotate_ua = rotate_ua
        self.rotate_ua_per_request = rotate_ua_per_request
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.verify_ssl = verify_ssl
        
        self._last_request_time = 0.0
        self._request_count = 0
        self._proxy_index = 0
        self._session_ua = random.choice(USER_AGENTS) if rotate_ua else USER_AGENTS[0]
        
        # Create session with retry adapter
        self.session = requests.Session()
        
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set proxy if provided
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        
        # Stats tracking
        self.stats = {
            "requests": 0,
            "waf_blocks": 0,
            "retries": 0,
            "errors": 0,
        }
    
    def _get_current_proxy(self) -> Optional[Dict[str, str]]:
        """Get current proxy for rotation."""
        if self.proxy:
            return {"http": self.proxy, "https": self.proxy}
        
        if self.proxies:
            proxy = self.proxies[self._proxy_index % len(self.proxies)]
            return {"http": proxy, "https": proxy}
        
        return None
    
    def _rotate_proxy(self):
        """Rotate to next proxy in list."""
        if self.proxies:
            self._proxy_index = (self._proxy_index + 1) % len(self.proxies)
            proxy = self._get_current_proxy()
            if proxy:
                self.session.proxies = proxy
                logger.debug(f"Rotated to proxy index {self._proxy_index}")
    
    def _get_user_agent(self) -> str:
        """Get User-Agent for request."""
        if not self.rotate_ua:
            return self._session_ua
        
        if self.rotate_ua_per_request:
            return random.choice(USER_AGENTS)
        
        return self._session_ua
    
    def _rate_limit_wait(self):
        """Wait to respect rate limiting with jitter."""
        if self.rate_limit <= 0:
            return
        
        now = time.time()
        min_interval = 1.0 / self.rate_limit
        elapsed = now - self._last_request_time
        
        if elapsed < min_interval:
            delay = min_interval - elapsed
            # Add random jitter
            delay += random.uniform(0, self.jitter)
            time.sleep(delay)
        elif self.jitter > 0:
            # Even if we're under rate limit, add some jitter
            time.sleep(random.uniform(0, self.jitter * 0.5))
        
        self._last_request_time = time.time()
    
    def _prepare_headers(
        self,
        headers: Optional[Dict[str, str]] = None,
        referer: Optional[str] = None,
        is_api: bool = False,
    ) -> Dict[str, str]:
        """Prepare headers for request."""
        if is_api:
            base_headers = get_api_headers(user_agent=self._get_user_agent())
        else:
            base_headers = get_browser_headers(
                user_agent=self._get_user_agent(),
                referer=referer,
            )
        
        if headers:
            base_headers.update(headers)
        
        return base_headers
    
    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        referer: Optional[str] = None,
        is_api: bool = False,
        detect_waf_block: bool = True,
        **kwargs,
    ) -> requests.Response:
        """Make HTTP request with WAF evasion.
        
        Args:
            method: HTTP method
            url: Target URL
            headers: Additional headers
            referer: Referer header
            is_api: Whether this is an API request
            detect_waf_block: Whether to detect and handle WAF blocks
            **kwargs: Additional requests arguments
            
        Returns:
            requests.Response
        """
        self._rate_limit_wait()
        
        # Prepare headers
        request_headers = self._prepare_headers(headers, referer, is_api)
        
        # Set defaults
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)
        
        # Make request
        try:
            response = self.session.request(
                method,
                url,
                headers=request_headers,
                **kwargs,
            )
            
            self.stats["requests"] += 1
            self._request_count += 1
            
            # Check for WAF block
            if detect_waf_block:
                waf = detect_waf(response)
                if waf:
                    self.stats["waf_blocks"] += 1
                    logger.warning(f"WAF block detected ({waf}): {url}")
                    
                    # Rotate proxy if available
                    if self.proxies:
                        self._rotate_proxy()
            
            return response
            
        except requests.exceptions.RequestException as e:
            self.stats["errors"] += 1
            logger.error(f"Request error for {url}: {e}")
            raise
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """HTTP GET request."""
        return self.request("GET", url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """HTTP POST request."""
        return self.request("POST", url, **kwargs)
    
    def put(self, url: str, **kwargs) -> requests.Response:
        """HTTP PUT request."""
        return self.request("PUT", url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> requests.Response:
        """HTTP DELETE request."""
        return self.request("DELETE", url, **kwargs)
    
    def head(self, url: str, **kwargs) -> requests.Response:
        """HTTP HEAD request."""
        return self.request("HEAD", url, **kwargs)
    
    def options(self, url: str, **kwargs) -> requests.Response:
        """HTTP OPTIONS request."""
        return self.request("OPTIONS", url, **kwargs)
    
    def get_stats(self) -> Dict[str, int]:
        """Get session statistics."""
        return self.stats.copy()
    
    def reset_stats(self):
        """Reset session statistics."""
        self.stats = {
            "requests": 0,
            "waf_blocks": 0,
            "retries": 0,
            "errors": 0,
        }


# ============================================================================
# Global Session Management
# ============================================================================

# Global session instance (lazily initialized)
_global_session: Optional[StealthSession] = None

# Global configuration (can be set by MCP server)
_global_config: Dict[str, Any] = {
    "enabled": True,
    "rate_limit": 2.0,
    "jitter": 0.5,
    "rotate_ua": True,
    "proxy": None,
    "proxies": [],
    "timeout": 30,
    "verify_ssl": True,
}


def configure_global_session(
    enabled: bool = True,
    rate_limit: float = 2.0,
    jitter: float = 0.5,
    rotate_ua: bool = True,
    proxy: Optional[str] = None,
    proxies: Optional[List[str]] = None,
    timeout: int = 30,
    verify_ssl: bool = True,
):
    """Configure global stealth session settings.
    
    Call this from MCP server to set evasion config.
    """
    global _global_config, _global_session
    
    _global_config = {
        "enabled": enabled,
        "rate_limit": rate_limit,
        "jitter": jitter,
        "rotate_ua": rotate_ua,
        "proxy": proxy or os.environ.get("SCAN_PROXY"),
        "proxies": proxies or [],
        "timeout": timeout,
        "verify_ssl": verify_ssl,
    }
    
    # Reset global session so it gets recreated with new config
    _global_session = None
    
    logger.info(f"Global stealth session configured: rate_limit={rate_limit}, jitter={jitter}")


def get_stealth_session() -> StealthSession:
    """Get or create global stealth session.
    
    Returns:
        Configured StealthSession instance
    """
    global _global_session
    
    if _global_session is None:
        # Check for environment overrides
        rate_limit = float(os.environ.get("SCAN_RATE_LIMIT", _global_config["rate_limit"]))
        proxy = os.environ.get("SCAN_PROXY", _global_config["proxy"])
        
        _global_session = StealthSession(
            rate_limit=rate_limit,
            jitter=_global_config["jitter"],
            rotate_ua=_global_config["rotate_ua"],
            proxy=proxy,
            proxies=_global_config["proxies"],
            timeout=_global_config["timeout"],
            verify_ssl=_global_config["verify_ssl"],
        )
    
    return _global_session


# ============================================================================
# Convenience Functions (Drop-in replacements for requests)
# ============================================================================

def safe_get(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    **kwargs,
) -> requests.Response:
    """Rate-limited GET request with browser headers.
    
    Drop-in replacement for requests.get() with WAF evasion.
    """
    session = get_stealth_session()
    return session.get(url, headers=headers, timeout=timeout, **kwargs)


def safe_post(
    url: str,
    data: Optional[Any] = None,
    json: Optional[Any] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    **kwargs,
) -> requests.Response:
    """Rate-limited POST request with browser headers.
    
    Drop-in replacement for requests.post() with WAF evasion.
    """
    session = get_stealth_session()
    is_api = json is not None
    return session.post(url, data=data, json=json, headers=headers, timeout=timeout, is_api=is_api, **kwargs)


def safe_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    **kwargs,
) -> requests.Response:
    """Rate-limited request with browser headers.
    
    Drop-in replacement for requests.request() with WAF evasion.
    """
    session = get_stealth_session()
    return session.request(method, url, headers=headers, timeout=timeout, **kwargs)


# ============================================================================
# Cloudscraper Integration (Optional)
# ============================================================================

def get_cloudscraper_session() -> Optional[Any]:
    """Get cloudscraper session for Cloudflare bypass.
    
    Returns:
        cloudscraper session if available, None otherwise
    """
    try:
        import cloudscraper
        return cloudscraper.create_scraper(
            browser={
                'browser': 'chrome',
                'platform': 'windows',
                'desktop': True,
            }
        )
    except ImportError:
        logger.warning("cloudscraper not installed. Install with: pip install cloudscraper")
        return None


def safe_get_with_cf_bypass(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    **kwargs,
) -> requests.Response:
    """GET request with Cloudflare bypass fallback.
    
    First tries normal stealth request, falls back to cloudscraper if CF detected.
    """
    session = get_stealth_session()
    
    try:
        response = session.get(url, headers=headers, timeout=timeout, **kwargs)
        
        # Check for Cloudflare challenge
        if is_cloudflare_challenge(response):
            logger.info(f"Cloudflare challenge detected for {url}, trying cloudscraper")
            scraper = get_cloudscraper_session()
            
            if scraper:
                # Merge headers
                merged_headers = get_browser_headers()
                if headers:
                    merged_headers.update(headers)
                
                response = scraper.get(url, headers=merged_headers, timeout=timeout, **kwargs)
        
        return response
        
    except Exception as e:
        logger.error(f"Request failed for {url}: {e}")
        raise


# ============================================================================
# Testing / Debug
# ============================================================================

if __name__ == "__main__":
    # Test the stealth session
    logging.basicConfig(level=logging.DEBUG)
    
    session = StealthSession(rate_limit=1.0, jitter=0.3)
    
    print("Testing stealth session...")
    print(f"User-Agent: {session._get_user_agent()}")
    
    # Test request
    try:
        resp = session.get("https://httpbin.org/headers")
        print(f"Status: {resp.status_code}")
        print(f"Headers sent: {resp.json()['headers']}")
    except Exception as e:
        print(f"Error: {e}")
    
    print(f"\nStats: {session.get_stats()}")

