"""
Shared Request Cache + Host Fingerprint Cache

CRITICAL: No asyncio objects (Lock, Queue, Semaphore) at module level.
All asyncio objects created lazily inside async context to avoid
event loop binding issues on Python 3.10+.
"""
from __future__ import annotations
import time
from typing import Any, Dict, Optional, Tuple

_RESPONSE_CACHE: Dict[str, Tuple[Dict, float]] = {}
_RESPONSE_CACHE_TTL = 300.0
_RESPONSE_LOCK = None

class HostStatus:
    UNKNOWN       = "unknown"
    ALIVE         = "alive"
    DEAD          = "dead"
    GATEWAY_ERROR = "gateway_error"
    AUTH_REDIRECT = "auth_redirect"
    RATE_LIMITED  = "rate_limited"

_HOST_STATUS: Dict[str, str] = {}
_HOST_RTT:    Dict[str, float] = {}
_HOST_LOCK    = None

_GLOBAL_REQUEST_SEM = None

def _get_response_lock():
    global _RESPONSE_LOCK
    if _RESPONSE_LOCK is None:
        import asyncio
        _RESPONSE_LOCK = asyncio.Lock()
    return _RESPONSE_LOCK

def _get_host_lock():
    global _HOST_LOCK
    if _HOST_LOCK is None:
        import asyncio
        _HOST_LOCK = asyncio.Lock()
    return _HOST_LOCK

async def get_cached_response(url: str) -> Optional[Dict]:
    async with _get_response_lock():
        entry = _RESPONSE_CACHE.get(url)
        if entry:
            resp, ts = entry
            if time.monotonic() - ts < _RESPONSE_CACHE_TTL:
                return resp
    return None

async def set_cached_response(url: str, response: Dict) -> None:
    async with _get_response_lock():
        _RESPONSE_CACHE[url] = (response, time.monotonic())

async def get_host_status(host: str) -> str:
    async with _get_host_lock():
        return _HOST_STATUS.get(host, HostStatus.UNKNOWN)

async def set_host_status(host: str, status: str) -> None:
    async with _get_host_lock():
        _HOST_STATUS[host] = status

async def set_host_rtt(host: str, rtt: float) -> None:
    async with _get_host_lock():
        existing = _HOST_RTT.get(host)
        _HOST_RTT[host] = (existing + rtt) / 2 if existing else rtt

async def get_host_rtt(host: str) -> float:
    async with _get_host_lock():
        return _HOST_RTT.get(host, 1.0)

def is_host_skippable(host: str) -> bool:
    """
    Sync check — safe to call from anywhere.
    External APIs are NEVER skipped regardless of status.
    """
    try:
        from argus.utils.rate_limiter import is_external_api
        if is_external_api(host):
            return False
    except ImportError:
        pass
    return _HOST_STATUS.get(host) in (HostStatus.DEAD, HostStatus.GATEWAY_ERROR)

def get_global_sem(limit: int = 200):
    global _GLOBAL_REQUEST_SEM
    if _GLOBAL_REQUEST_SEM is None:
        import asyncio
        _GLOBAL_REQUEST_SEM = asyncio.Semaphore(limit)
    return _GLOBAL_REQUEST_SEM

def reset_global_sem(limit: int = 200) -> None:
    global _GLOBAL_REQUEST_SEM
    _GLOBAL_REQUEST_SEM = None

def clear_all() -> None:
    """Reset all caches. Call at start of each scan."""
    global _RESPONSE_CACHE, _HOST_STATUS, _HOST_RTT
    global _RESPONSE_LOCK, _HOST_LOCK, _GLOBAL_REQUEST_SEM
    _RESPONSE_CACHE     = {}
    _HOST_STATUS        = {}
    _HOST_RTT           = {}

    _RESPONSE_LOCK      = None
    _HOST_LOCK          = None
    _GLOBAL_REQUEST_SEM = None
