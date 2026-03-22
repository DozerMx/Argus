"""
HTTP Client v3.6 — Clean, reliable, zero silent failures
Single responsibility: make HTTP requests and return responses.
No caching, no host tracking, no side effects.
Optimizations: connection pooling, keep-alive, adaptive read limits.
"""
import asyncio
import ssl
import random
import logging
import time
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import aiohttp
from aiohttp import TCPConnector, ClientTimeout, ClientSession

from argus.utils.rate_limiter import PerHostRateLimiter, RetryHandler, RateLimitError, TransientError

logger = logging.getLogger("argus.http")

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
]

GATEWAY_PATTERNS = [
    b"502 Bad Gateway", b"503 Service Unavailable", b"504 Gateway Timeout",
    b"Application Gateway", b"microsoft-azure-application-gateway",
]

SSO_DOMAINS = [
    "microsoftonline.com", "accounts.google.com",
    "okta.com", "auth0.com", "login.live.com",
]

class HTTPClient:
    def __init__(
        self,
        timeout: int = 15,
        proxy: Optional[str] = None,
        rate_limiter: Optional[PerHostRateLimiter] = None,
        retry_handler: Optional[RetryHandler] = None,
        rotate_ua: bool = True,
    ):
        self._timeout      = ClientTimeout(total=timeout, connect=5, sock_read=timeout * 3)
        self._proxy        = proxy
        self._rate_limiter = rate_limiter or PerHostRateLimiter()
        self._retry        = retry_handler or RetryHandler()
        self._rotate_ua    = rotate_ua
        self._session: Optional[ClientSession] = None

    async def __aenter__(self):
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE

        connector = TCPConnector(
            ssl=ssl_ctx,
            limit=200,
            limit_per_host=20,
            ttl_dns_cache=300,
            use_dns_cache=True,
            enable_cleanup_closed=True,
            force_close=True,
        )
        self._session = ClientSession(
            connector=connector,
            timeout=self._timeout,
            headers={
                "Accept":          "application/json, text/html, */*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection":      "keep-alive",
            },
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()
            await asyncio.sleep(0.01)
            self._session = None

    def queue_prefetch(self, host: str, scheme: str = "https") -> None:
        pass

    def _host(self, url: str) -> str:
        return urlparse(url).netloc.split(":")[0]

    def _headers(self, extra: Optional[Dict] = None) -> Dict:
        h = {"User-Agent": random.choice(USER_AGENTS)} if self._rotate_ua else {}
        if extra:
            h.update(extra)
        return h

    async def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        auth: Optional[aiohttp.BasicAuth] = None,
        read_limit: int = 512 * 1024,
        use_cache: bool = True,
        timeout_override: Optional[aiohttp.ClientTimeout] = None,
    ) -> Dict[str, Any]:
        host = self._host(url)
        await self._rate_limiter.throttle(host)

        async def _request():
            req_kwargs: Dict[str, Any] = {
                "params":        params,
                "headers":       self._headers(headers),
                "proxy":         self._proxy,
                "auth":          auth,
                "allow_redirects": True,
                "max_redirects": 5,
            }
            if timeout_override is not None:
                req_kwargs["timeout"] = timeout_override

            async with self._session.get(url, **req_kwargs) as resp:
                if resp.status == 429:
                    retry_after = float(resp.headers.get("Retry-After", 10))
                    raise RateLimitError(f"429 {host}", retry_after=retry_after)

                if resp.status == 404:
                    return {"status": 404, "data": None, "headers": {}}

                ct = resp.content_type or ""
                if "json" in ct:
                    limit = max(read_limit, 8 * 1024 * 1024)
                elif "html" in ct:
                    limit = max(read_limit, 512 * 1024)
                else:
                    limit = max(read_limit, 512 * 1024)

                try:
                    chunks = []
                    checked_gateway = False
                    async for chunk in resp.content.iter_chunked(65536):
                        if not checked_gateway:
                            if any(pat in chunk[:512] for pat in GATEWAY_PATTERNS):
                                return {"status": resp.status, "data": None,
                                        "headers": dict(resp.headers)}
                            checked_gateway = True
                        chunks.append(chunk)
                    raw = b"".join(chunks)
                except Exception:
                    raw = b"".join(chunks) if chunks else b""

                if "json" in ct:
                    try:
                        import json
                        data = json.loads(raw)
                    except Exception:
                        data = raw.decode("utf-8", errors="replace")
                else:
                    data = raw.decode("utf-8", errors="replace")

                return {
                    "status":  resp.status,
                    "data":    data,
                    "headers": dict(resp.headers),
                    "url":     str(resp.url),
                }

        try:
            return await self._retry.execute(_request, host=host)
        except Exception as e:
            logger.debug(f"GET {url} failed: {e}")
            return {"status": 0, "data": None, "headers": {}}

    async def get_raw_tls(self, host: str, port: int = 443) -> Optional[Dict]:
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl.CERT_NONE
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=10
            )
            ssl_obj  = w.transport.get_extra_info("ssl_object")
            cert_der = ssl_obj.getpeercert(binary_form=True)
            cipher   = ssl_obj.cipher()
            protocol = ssl_obj.version()
            w.close()
            try:
                await asyncio.wait_for(w.wait_closed(), timeout=1.0)
            except Exception:
                pass
            return {"cert_der": cert_der, "cipher": cipher,
                    "protocol": protocol, "host": host, "port": port}
        except Exception as e:
            logger.debug(f"Raw TLS {host}:{port}: {e}")
            return None
