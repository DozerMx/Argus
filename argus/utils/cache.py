"""
DiskCache v3.5 — Non-blocking with in-memory L1 layer
Two-level cache:
  L1: in-memory dict (instant, zero I/O)
  L2: disk (persistent across runs)

Writes go to L1 immediately and flush to disk in background.
Reads check L1 first — disk only on miss.
This eliminates blocking I/O on the critical async path.
"""
import json
import hashlib
import time
import asyncio
import logging
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from collections import OrderedDict

logger = logging.getLogger("argus.cache")
CACHE_DIR = Path.home() / ".argus" / "cache"

_L1: OrderedDict = OrderedDict()
_L1_MAX = 2000
_L1_LOCK = threading.Lock()

_FLUSH_QUEUE: list = []
_FLUSH_LOCK  = threading.Lock()
_FLUSH_THREAD: Optional[threading.Thread] = None

def _flush_worker():
    """Background thread that flushes L1 writes to disk."""
    while True:
        time.sleep(0.5)
        with _FLUSH_LOCK:
            items = list(_FLUSH_QUEUE)
            _FLUSH_QUEUE.clear()
        for path, data in items:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(data)
            except Exception as e:
                logger.debug(f"Cache flush error: {e}")

def _start_flush_thread():
    global _FLUSH_THREAD
    if _FLUSH_THREAD is None or not _FLUSH_THREAD.is_alive():
        _FLUSH_THREAD = threading.Thread(target=_flush_worker, daemon=True)
        _FLUSH_THREAD.start()

class DiskCache:
    def __init__(self, ttl: int = 3600, enabled: bool = True):
        self.ttl     = ttl
        self.enabled = enabled
        if enabled:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            _start_flush_thread()

    def _key_path(self, key: str) -> Path:
        h = hashlib.sha256(key.encode()).hexdigest()
        return CACHE_DIR / h[:2] / h[2:4] / h

    def get(self, key: str) -> Optional[Any]:
        if not self.enabled:
            return None

        with _L1_LOCK:
            entry = _L1.get(key)
            if entry is not None:
                value, ts = entry
                if time.time() - ts <= self.ttl:
                    _L1.move_to_end(key)
                    return value
                else:
                    del _L1[key]

        path = self._key_path(key)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            if time.time() - data["ts"] > self.ttl:
                path.unlink(missing_ok=True)
                return None
            value = data["value"]

            self._l1_set(key, value)
            return value
        except Exception as e:
            logger.debug(f"Cache read error: {e}")
            return None

    def set(self, key: str, value: Any):
        if not self.enabled:
            return

        self._l1_set(key, value)

        try:
            path     = self._key_path(key)
            payload  = json.dumps({"ts": time.time(), "value": value}, default=str)
            with _FLUSH_LOCK:
                _FLUSH_QUEUE.append((path, payload))
        except Exception as e:
            logger.debug(f"Cache queue error: {e}")

    def _l1_set(self, key: str, value: Any):
        with _L1_LOCK:
            _L1[key] = (value, time.time())
            _L1.move_to_end(key)

            while len(_L1) > _L1_MAX:
                _L1.popitem(last=False)

    def invalidate(self, key: str):
        with _L1_LOCK:
            _L1.pop(key, None)
        self._key_path(key).unlink(missing_ok=True)

    def clear_all(self):
        import shutil
        with _L1_LOCK:
            _L1.clear()
        if CACHE_DIR.exists():
            shutil.rmtree(CACHE_DIR)
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
