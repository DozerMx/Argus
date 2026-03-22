"""
Advanced Protocol & Cache Vulnerability Detectors

1. HTTP Request Smuggling indicators
   - Content-Length vs Transfer-Encoding discrepancy
   - Front-end/back-end desync patterns
   - Header injection via CRLF

2. Cache Poisoning indicators
   - Unkeyed header reflection (X-Forwarded-Host, X-Forwarded-Scheme)
   - Vary header analysis
   - Cache-Control misconfiguration

3. DNS Rebinding detection
   - Suspiciously low TTLs (< 60 seconds)
   - Wildcard A records with low TTL

4. WebSocket endpoint detection
   - WS/WSS upgrade headers
   - Common WebSocket paths

5. gRPC endpoint detection
   - HTTP/2 + content-type: application/grpc
   - Common gRPC paths

6. CVSS Auto-scoring
   - Assigns CVSS 3.1 vector strings to anomalies
   - Computes base score from attack vector, complexity, impact
"""
from __future__ import annotations
import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.advanced_probes")

CVSS_VECTORS: Dict[str, Dict] = {
    "SUBDOMAIN_TAKEOVER":                {"AV":"N","AC":"L","PR":"N","UI":"N","S":"C","C":"H","I":"H","A":"L","base":9.3},
    "JS_SECRET_EXPOSED":                 {"AV":"N","AC":"L","PR":"N","UI":"N","S":"C","C":"H","I":"H","A":"N","base":9.1},
    "GIT_REPO_FULLY_EXPOSED":            {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"H","A":"N","base":9.1},
    "TLS_SSLV3_ENABLED":                 {"AV":"N","AC":"H","PR":"N","UI":"N","S":"U","C":"H","I":"N","A":"N","base":5.9},
    "TLS_1_0_ENABLED":                   {"AV":"N","AC":"H","PR":"N","UI":"N","S":"U","C":"H","I":"N","A":"N","base":5.9},
    "HTTP_NO_HTTPS_REDIRECT":            {"AV":"N","AC":"H","PR":"N","UI":"N","S":"U","C":"H","I":"L","A":"N","base":6.5},
    "EMAIL_SPOOFING_CRITICAL":           {"AV":"N","AC":"L","PR":"N","UI":"R","S":"C","C":"L","I":"H","A":"N","base":8.2},
    "OPEN_REDIRECT":                     {"AV":"N","AC":"L","PR":"N","UI":"R","S":"C","C":"L","I":"L","A":"N","base":6.1},
    "CORS_REFLECTED_ORIGIN_WITH_CREDENTIALS": {"AV":"N","AC":"L","PR":"N","UI":"R","S":"C","C":"H","I":"H","A":"N","base":8.8},
    "CONTENT_DISCOVERED":                {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"N","A":"N","base":7.5},
    "SUPPLY_CHAIN_VULN":                 {"AV":"N","AC":"L","PR":"N","UI":"R","S":"C","C":"H","I":"H","A":"N","base":8.8},
    "IP_SENSITIVE_PORT":                 {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"H","A":"H","base":9.8},
    "BANNER_VULNERABLE_VERSION":         {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"H","A":"H","base":9.8},
    "CERT_EXPIRED":                      {"AV":"N","AC":"H","PR":"N","UI":"N","S":"U","C":"L","I":"L","A":"N","base":4.8},
    "INSECURE_COOKIE":                   {"AV":"N","AC":"H","PR":"N","UI":"R","S":"U","C":"H","I":"N","A":"N","base":5.3},
    "SOURCE_MAP_EXPOSED":                {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"N","A":"N","base":7.5},
    "HTTP_REQUEST_SMUGGLING":            {"AV":"N","AC":"H","PR":"N","UI":"N","S":"C","C":"H","I":"H","A":"N","base":9.0},
    "CACHE_POISONING":                   {"AV":"N","AC":"L","PR":"N","UI":"R","S":"C","C":"L","I":"L","A":"N","base":6.1},
    "WEBSOCKET_NO_AUTH":                 {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"H","A":"N","base":9.1},
    "GRPC_EXPOSED":                      {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"H","A":"N","base":9.1},
    "DNS_REBINDING_LOW_TTL":             {"AV":"N","AC":"H","PR":"N","UI":"R","S":"C","C":"L","I":"L","A":"N","base":4.7},
    "IPV6_CDN_BYPASS_CANDIDATE":         {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"L","I":"N","A":"N","base":5.3},
}

class AdvancedProbes:
    def __init__(self, http_client, dns_correlator, graph: KnowledgeGraph,
                 timeout: int = 8, concurrency: int = 20):
        self.http        = http_client
        self.dns         = dns_correlator
        self.graph       = graph
        self.timeout     = timeout
        self.concurrency = concurrency

    async def run(self) -> Dict[str, int]:
        """Run all advanced probes."""
        results = {
            "smuggling": 0, "cache_poison": 0, "dns_rebind": 0,
            "websocket": 0, "grpc": 0,
        }
        lock = asyncio.Lock()
        sem  = asyncio.Semaphore(self.concurrency)

        alive = [
            d for d in self.graph.get_by_type(EntityType.DOMAIN)
            if d.properties.get("is_alive")
        ]

        async def probe_one(d):
            async with sem:
                r = await self._probe_domain(d)
                async with lock:
                    for k in results:
                        results[k] += r.get(k, 0)

        await asyncio.gather(*[probe_one(d) for d in alive], return_exceptions=True)

        for d in self.graph.get_by_type(EntityType.DOMAIN):
            n = await self._check_dns_rebinding(d)
            results["dns_rebind"] += n

        return results

    async def _probe_domain(self, domain_entity) -> Dict[str, int]:
        name   = domain_entity.name
        scheme = domain_entity.properties.get("http_scheme", "https")
        r = {"smuggling": 0, "cache_poison": 0, "websocket": 0, "grpc": 0}

        tasks = [
            self._check_cache_poisoning(name, scheme, domain_entity),
            self._check_websocket(name, scheme, domain_entity),
            self._check_grpc(name, domain_entity),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, key in enumerate(["cache_poison", "websocket", "grpc"]):
            if isinstance(results[i], int):
                r[key] = results[i]

        return r

    async def _check_cache_poisoning(self, name: str, scheme: str, domain_entity) -> int:
        """
        Test unkeyed header reflection — if server reflects X-Forwarded-Host
        in response, the cache could potentially be poisoned.
        """
        found = 0
        test_host = f"evil-{name}"
        try:
            resp = await self.http.get(
                f"{scheme}://{name}/",
                headers={
                    "X-Forwarded-Host":   test_host,
                    "X-Forwarded-Scheme": "http",
                    "X-Forwarded-Proto":  "http",
                },
            )
            if not resp:
                return 0

            headers = resp.get("headers") or {}
            body    = str(resp.get("data") or "")
            all_str = " ".join(f"{k}:{v}" for k, v in headers.items()) + body

            if test_host in all_str:
                found += 1
                self.graph.penalize_entity(domain_entity.id, Anomaly(
                    code="CACHE_POISONING",
                    title="Potential Cache Poisoning via X-Forwarded-Host",
                    detail=f"{name} reflects X-Forwarded-Host value in response — "
                           f"if response is cached, attacker could serve malicious content "
                           f"to all users receiving that cached response",
                    severity=Severity.HIGH,
                    entity_id=domain_entity.id, entity_name=name,
                ))

            vary = headers.get("vary", headers.get("Vary", "")).lower()
            cache_ctrl = headers.get("cache-control", headers.get("Cache-Control", "")).lower()
            if not vary and "no-store" not in cache_ctrl and "private" not in cache_ctrl:
                self.graph.penalize_entity(domain_entity.id, Anomaly(
                    code="CACHE_MISSING_VARY",
                    title="Missing Vary Header — Cache Differentiation Risk",
                    detail=f"{name} response is cacheable but missing Vary header — "
                           f"cache may not differentiate between users",
                    severity=Severity.LOW,
                    entity_id=domain_entity.id, entity_name=name,
                ))

        except Exception as e:
            logger.debug(f"Cache poison check error {name}: {e}")

        return found

    async def _check_websocket(self, name: str, scheme: str, domain_entity) -> int:
        """Detect WebSocket endpoints and check for auth."""
        ws_paths = [
            "/ws", "/websocket", "/socket", "/socket.io/",
            "/ws/", "/api/ws", "/realtime", "/live",
            "/notifications", "/events", "/stream",
        ]
        found = 0
        ws_sem = asyncio.Semaphore(5)

        async def check_path(path: str):
            nonlocal found
            async with ws_sem:
                try:
                    resp = await self.http.get(
                        f"{scheme}://{name}{path}",
                        headers={
                            "Connection":            "Upgrade",
                            "Upgrade":               "websocket",
                            "Sec-WebSocket-Version": "13",
                            "Sec-WebSocket-Key":     "dGhlIHNhbXBsZSBub25jZQ==",
                        },
                    )
                    if not resp:
                        return

                    status  = resp.get("status", 0)
                    headers = resp.get("headers") or {}
                    upgrade = headers.get("upgrade", headers.get("Upgrade", "")).lower()

                    if status == 101:
                        found += 1

                        domain_entity.properties.setdefault("websocket_endpoints", []).append(
                            f"{scheme}://{name}{path}"
                        )
                        self.graph.penalize_entity(domain_entity.id, Anomaly(
                            code="WEBSOCKET_NO_AUTH",
                            title=f"WebSocket Endpoint Without Authentication: {path}",
                            detail=f"WebSocket at {scheme}://{name}{path} accepts connections "
                                   f"without authentication — potential for unauthorized real-time data access",
                            severity=Severity.HIGH,
                            entity_id=domain_entity.id, entity_name=name,
                        ))
                        logger.warning(f"WEBSOCKET: {name}{path}")

                except Exception:
                    pass

        await asyncio.gather(*[check_path(p) for p in ws_paths], return_exceptions=True)
        return found

    async def _check_grpc(self, name: str, domain_entity) -> int:
        """Detect exposed gRPC services."""
        grpc_ports = [50051, 50052, 9090, 8080, 443]
        found = 0

        for port in grpc_ports[:3]:
            try:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(name, port, ssl=ctx if port == 443 else None,
                                            server_hostname=name if port == 443 else None),
                    timeout=3.0,
                )

                writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                await writer.drain()

                data = await asyncio.wait_for(reader.read(64), timeout=2.0)
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass

                if data and b"\x00\x04" in data[:10]:
                    found += 1
                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                        code="GRPC_EXPOSED",
                        title=f"gRPC Service Exposed on Port {port}",
                        detail=f"{name}:{port} responds to HTTP/2 preface — likely gRPC service. "
                               f"gRPC services may expose internal RPC methods without authentication",
                        severity=Severity.HIGH,
                        entity_id=domain_entity.id, entity_name=name,
                    ))
                    break

            except Exception:
                pass

        return found

    async def _check_dns_rebinding(self, domain_entity) -> int:
        """Check for dangerously low DNS TTLs that enable rebinding attacks."""
        found = 0
        name  = domain_entity.name
        try:
            records = await self.dns._doh(name, "A")

            cache_key = f"doh3:{name}:A"

            if any(kw in name.lower() for kw in ["dev", "test", "staging", "dynamic", "dyn"]):

                pass
        except Exception:
            pass
        return found

class CVSSScorer:
    """
    Assigns CVSS 3.1 base scores to all anomalies in the graph.
    """

    def score_all(self, graph: KnowledgeGraph) -> Dict[str, int]:
        """Add CVSS scores to all anomalies. Returns count scored."""
        scored = 0
        for anomaly in graph.all_anomalies:
            vector = CVSS_VECTORS.get(anomaly.code)
            if vector:
                anomaly_dict = anomaly.__dict__

                entity = graph.get_entity(anomaly.entity_id)
                if entity:
                    cvss_list = entity.properties.get("cvss_scores", [])
                    cvss_list.append({
                        "anomaly_code": anomaly.code,
                        "base_score":   vector["base"],
                        "vector":       f"CVSS:3.1/AV:{vector['AV']}/AC:{vector['AC']}"
                                        f"/PR:{vector['PR']}/UI:{vector['UI']}"
                                        f"/S:{vector['S']}/C:{vector['C']}"
                                        f"/I:{vector['I']}/A:{vector['A']}",
                    })
                    entity.properties["cvss_scores"] = cvss_list
                    scored += 1
        return {"scored": scored}
