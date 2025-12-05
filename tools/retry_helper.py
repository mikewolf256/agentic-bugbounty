#!/usr/bin/env python3
"""Retry helper with exponential backoff for resilient API calls and tool execution.

Provides decorators and context managers for retrying operations with configurable
retry counts, delays, and exception handling.
"""

import time
import functools
from typing import Callable, TypeVar, Optional, List, Tuple, Any
from requests.exceptions import RequestException, Timeout, ConnectionError

T = TypeVar('T')


def retry_with_backoff(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    retryable_exceptions: Tuple[type, ...] = (Exception,),
    on_retry: Optional[Callable[[int, Exception], None]] = None,
):
    """Decorator for retrying functions with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts (default: 3)
        initial_delay: Initial delay in seconds (default: 1.0)
        max_delay: Maximum delay in seconds (default: 60.0)
        exponential_base: Base for exponential backoff (default: 2.0)
        retryable_exceptions: Tuple of exception types to retry on
        on_retry: Optional callback function called on each retry (attempt_num, exception)
    
    Returns:
        Decorated function that retries on failure
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None
            delay = initial_delay
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e
                    
                    if attempt < max_retries:
                        if on_retry:
                            on_retry(attempt + 1, e)
                        
                        # Calculate delay with exponential backoff
                        delay = min(initial_delay * (exponential_base ** attempt), max_delay)
                        time.sleep(delay)
                    else:
                        # Final attempt failed
                        break
                except Exception as e:
                    # Non-retryable exception - re-raise immediately
                    raise
            
            # All retries exhausted
            raise last_exception
        
        return wrapper
    return decorator


def retry_mcp_call(
    max_retries: int = 3,
    initial_delay: float = 1.0,
):
    """Specialized retry decorator for MCP API calls.
    
    Retries on network errors, timeouts, and HTTP 5xx errors.
    """
    return retry_with_backoff(
        max_retries=max_retries,
        initial_delay=initial_delay,
        retryable_exceptions=(RequestException, Timeout, ConnectionError, Exception),
    )


class RetryContext:
    """Context manager for retrying operations with exponential backoff."""
    
    def __init__(
        self,
        max_retries: int = 3,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        retryable_exceptions: Tuple[type, ...] = (Exception,),
    ):
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.retryable_exceptions = retryable_exceptions
        self.attempt = 0
        self.last_exception = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            return False  # No exception, don't suppress
        
        if not isinstance(exc_val, self.retryable_exceptions):
            return False  # Not a retryable exception, don't suppress
        
        self.attempt += 1
        self.last_exception = exc_val
        
        if self.attempt <= self.max_retries:
            # Calculate delay
            delay = min(
                self.initial_delay * (self.exponential_base ** (self.attempt - 1)),
                self.max_delay
            )
            time.sleep(delay)
            return True  # Suppress exception, retry
        
        # All retries exhausted
        return False  # Don't suppress, let exception propagate
    
    def should_retry(self) -> bool:
        """Check if we should retry based on current attempt count."""
        return self.attempt < self.max_retries


def retry_tool_execution(
    tool_name: str,
    max_retries: int = 3,
    timeout: Optional[int] = None,
) -> Callable:
    """Create a retry wrapper for tool execution (subprocess calls).
    
    Args:
        tool_name: Name of the tool (for logging)
        max_retries: Maximum retry attempts
        timeout: Timeout in seconds (optional)
    
    Returns:
        Decorator function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    if timeout and 'timeout' not in kwargs:
                        kwargs['timeout'] = timeout
                    return func(*args, **kwargs)
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
                    last_exception = e
                    
                    if attempt < max_retries:
                        delay = 1.0 * (2.0 ** attempt)  # 1s, 2s, 4s
                        print(f"[RETRY] {tool_name} failed (attempt {attempt + 1}/{max_retries + 1}), retrying in {delay}s...", file=sys.stderr)
                        time.sleep(delay)
                    else:
                        break
                except Exception as e:
                    # Non-retryable exception
                    raise
            
            # All retries exhausted
            if last_exception:
                raise last_exception
            raise RuntimeError(f"{tool_name} failed after {max_retries + 1} attempts")
        
        return wrapper
    
    return decorator

