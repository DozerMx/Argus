"""
Rate Limiter v3.5 — Smart Policy Separation
Key insight: target hosts (scan targets) need NO rate limiting.
Only external APIs (crt.sh, HackerTarget, DoH) need throttling.

Changes:
- Target host detection: bypass token bucket entirely for scan targets
- RetryHandler: 0 retries for target probes, 3 retries for external APIs
- Faster default: 20 req/s burst for unknown hosts (was 3 req/s)
- uvloop integration: auto-detected and installed if available
"""
import asyncio
import time
import random
from collections import defaultdict
from typing import Dict, Optional, Set
import logging

logger = logging.getLogger("argus.ratelimiter")

EXTERNAL_API_HOSTS: Set[str] = {
    "crt.sh",
    "api.certspotter.io",
    "search.censys.io",
    "api.securitytrails.com",
    "urlscan.io",
    "web.archive.org",
    "api.hackertarget.com",
    "rdap.arin.net",
    "rdap.db.ripe.net",
    "rdap.lacnic.net",
    "rdap.apnic.net",
    "rdap.afrinic.net",
    "bgp.tools",
}

DOH_HOSTS: Set[str] = {
    "dns.google",
    "cloudflare-dns.com",
    "1.1.1.1",
    "8.8.8.8",
}

def is_external_api(host: str) -> bool:
    """Check if host is an external API that needs rate limiting."""
    return host in EXTERNAL_API_HOSTS or host in DOH_HOSTS

class TokenBucket:
    def __init__(self, rate: float, capacity: float):
        self.rate      = rate
        self.capacity  = capacity
        self._tokens   = capacity
        self._last_refill = time.monotonic()
        self._lock     = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0):
        async with self._lock:
            await self._refill()
            while self._tokens < tokens:
                wait = (tokens - self._tokens) / self.rate
                await asyncio.sleep(wait)
                await self._refill()
            self._tokens -= tokens

    async def _refill(self):
        now           = time.monotonic()
        elapsed       = now - self._last_refill
        self._tokens  = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_refill = now

class PerHostRateLimiter:
    """
    Smart rate limiter:
    - External APIs: strict per-host token bucket
    - Target hosts: NO throttling (they're our scan targets)
    - DoH resolvers: high-rate token bucket
    """

    EXTERNAL_POLICIES: Dict[str, tuple] = {
        "crt.sh":                  (2.0,  5),
        "api.certspotter.io":      (1.0,  3),
        "search.censys.io":        (0.5,  2),
        "api.securitytrails.com":  (1.0,  3),
        "urlscan.io":              (2.0,  5),
        "web.archive.org":         (2.0,  5),
        "api.hackertarget.com":    (1.0,  3),
        "rdap.arin.net":           (2.0,  5),
        "rdap.db.ripe.net":        (2.0,  5),
        "rdap.lacnic.net":         (2.0,  5),
        "rdap.apnic.net":          (2.0,  5),
        "rdap.afrinic.net":        (2.0,  5),
    }

    DOH_POLICIES: Dict[str, tuple] = {
        "dns.google":         (30.0, 60),
        "cloudflare-dns.com": (30.0, 60),
    }

    def __init__(self, global_delay: float = 0.0):
        self._buckets: Dict[str, TokenBucket] = {}
        self._global_delay = global_delay

    def _get_bucket(self, host: str) -> Optional[TokenBucket]:
        """Return bucket for external APIs, None for target hosts."""
        if host not in self._buckets:
            if host in self.EXTERNAL_POLICIES:
                rate, burst = self.EXTERNAL_POLICIES[host]
                self._buckets[host] = TokenBucket(rate, burst)
            elif host in self.DOH_POLICIES:
                rate, burst = self.DOH_POLICIES[host]
                self._buckets[host] = TokenBucket(rate, burst)
            elif host in DOH_HOSTS:
                self._buckets[host] = TokenBucket(30.0, 60)
            elif is_external_api(host):
                self._buckets[host] = TokenBucket(2.0, 5)
            else:

                self._buckets[host] = None
        return self._buckets[host]

    async def throttle(self, host: str):
        bucket = self._get_bucket(host)
        if bucket is not None:
            await bucket.acquire()

        if self._global_delay > 0 and is_external_api(host):
            jitter = self._global_delay * random.uniform(0.8, 1.2)
            await asyncio.sleep(jitter)

class RetryHandler:
    """
    Smart retry: target hosts get 1 retry max, external APIs get 3.
    Avoids wasting time retrying dead target hosts.
    """

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        jitter: bool = True,
    ):
        self.max_retries = max_retries
        self.base_delay  = base_delay
        self.max_delay   = max_delay
        self.jitter      = jitter
        self._backoff_until: Dict[str, float] = defaultdict(float)
        self._rate_logged:   set = set()

    def reset(self) -> None:
        """Clear all state between scans."""
        self._backoff_until.clear()
        self._rate_logged.clear()

    def backoff_delay(self, attempt: int) -> float:
        delay = min(self.base_delay * (2 ** attempt), self.max_delay)
        if self.jitter:
            delay *= random.uniform(0.5, 1.5)
        return delay

    def set_host_backoff(self, host: str, seconds: float):
        self._backoff_until[host] = time.monotonic() + seconds

    async def wait_if_backed_off(self, host: str):
        remaining = self._backoff_until.get(host, 0) - time.monotonic()
        if remaining > 0:
            await asyncio.sleep(remaining)

    async def execute(self, coro_factory, host: str = "default"):
        await self.wait_if_backed_off(host)

        retries   = self.max_retries if is_external_api(host) else 1
        last_exc  = None

        for attempt in range(retries + 1):
            try:
                return await coro_factory()
            except RateLimitError as e:
                retry_after = getattr(e, "retry_after", None) or self.backoff_delay(attempt)
                self.set_host_backoff(host, retry_after)

                if host not in self._rate_logged:
                    self._rate_logged.add(host)
                    logger.warning(f"[{host}] Rate limited — waiting {retry_after:.1f}s")
                await asyncio.sleep(retry_after)
                last_exc = e
            except TransientError as e:
                if attempt == retries:

                    raise
                delay = self.backoff_delay(attempt)
                await asyncio.sleep(delay)
                last_exc = e
            except Exception:
                raise

        if last_exc:
            raise last_exc

class RateLimitError(Exception):
    def __init__(self, msg="", retry_after: Optional[float] = None):
        super().__init__(msg)
        self.retry_after = retry_after

class TransientError(Exception):
    pass

def install_uvloop() -> bool:
    """
    Install uvloop as event loop if available.
    uvloop is 2-4x faster than Python's default selector for I/O.
    """
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        logger.info("uvloop installed as event loop — 2-4x faster I/O")
        return True
    except ImportError:
        logger.debug("uvloop not available — using default event loop (pip install uvloop for speedup)")
        return False
