"""
CDN Bypass Engine — Graph-Aware
Discovers origin IPs behind CDN/WAF. Adds ORIGIN_BEHIND and
HISTORICALLY_AT relationships to the graph.

Techniques (all self-contained, zero external APIs):
1. SPF record IP extraction
2. MX server IP correlation
3. Certificate SAN staging host resolution
4. Historical PTR correlation
5. Direct origin verification with Host header injection
"""
from __future__ import annotations
import asyncio
import ipaddress
import logging
from typing import Dict, List, Optional, Set

from argus.ontology.entities import Anomaly, EntityType, RelationType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.correlators.cdn_bypass")

class CDNBypassEngine:
    def __init__(self, http_client, dns_correlator, graph: KnowledgeGraph):
        self.http = http_client
        self.dns = dns_correlator
        self.graph = graph

    async def run(self, domain: str) -> int:
        """
        Run all CDN bypass techniques for a domain.
        Returns count of origin IPs confirmed.
        """

        cdn_domains = [
            d for d in self.graph.get_by_type(EntityType.DOMAIN)
            if self._is_behind_cdn(d)
        ]

        if not cdn_domains:
            logger.info("No CDN-protected domains detected")
            return 0

        logger.info(f"CDN bypass: {len(cdn_domains)} CDN-protected domains")

        candidate_sources = await asyncio.gather(
            self.dns.spf_ips(domain),
            self.dns.mx_ips(domain),
            self._from_cert_sans(domain),
            return_exceptions=True,
        )

        candidates: Set[str] = set()
        for source in candidate_sources:
            if isinstance(source, list):
                candidates.update(ip for ip in source if self._is_routable(ip))

        if not candidates:
            logger.info("No origin IP candidates found")
            return 0

        cdn_ips: Set[str] = set()
        for d in cdn_domains:
            for ip_entity in self.graph.successors(d.id, RelationType.RESOLVES_TO):
                cdn_ips.add(ip_entity.name)

        origin_candidates = [ip for ip in candidates if ip not in cdn_ips]

        confirmed = 0
        sem = asyncio.Semaphore(8)

        async def verify_one(ip: str, domain_entity) -> None:
            nonlocal confirmed
            async with sem:
                result = await self._verify_origin(ip, domain_entity.name)
                if result and result.get("confirmed"):
                    confirmed += 1

                    origin_entity = self.graph.find_or_create(
                        EntityType.IP, name=ip,
                        properties={
                            "role":          "origin",
                            "http_status":   result.get("status"),
                            "server_header": result.get("server", ""),
                            "port":          result.get("port"),
                        },
                        source="cdn_bypass",
                    )

                    for cdn_ip in cdn_ips:
                        cdn_ip_entity = self.graph.get_by_name(cdn_ip)
                        if cdn_ip_entity:
                            self.graph.link(
                                cdn_ip_entity.id, origin_entity.id,
                                RelationType.ORIGIN_BEHIND,
                                properties={"technique": result.get("technique", "direct_probe")},
                                source="cdn_bypass",
                            )

                    self.graph.link(
                        domain_entity.id, origin_entity.id,
                        RelationType.HISTORICALLY_AT,
                        properties={"via": "cdn_bypass"},
                        source="cdn_bypass",
                    )
                    self.graph.index_ip_domain(ip, domain_entity.name)

                    anomaly = Anomaly(
                        code="ORIGIN_IP_LEAKED",
                        title="Origin IP Discovered Behind CDN",
                        detail=f"Real origin IP {ip} found via {result.get('technique', 'direct_probe')} "
                               f"(HTTP {result.get('status')}, server: {result.get('server', 'unknown')})",
                        severity=Severity.HIGH,
                        entity_id=domain_entity.id,
                        entity_name=domain_entity.name,
                    )
                    self.graph.penalize_entity(domain_entity.id, anomaly)
                    logger.warning(f"CDN BYPASS: {domain_entity.name} → origin {ip} [{result.get('technique')}]")

        for d in cdn_domains:
            await asyncio.gather(
                *[verify_one(ip, d) for ip in origin_candidates],
                return_exceptions=True,
            )

        return confirmed

    async def _from_cert_sans(self, domain: str) -> List[str]:
        """Find staging/dev subdomains in cert SANs and resolve them."""
        ips: List[str] = []
        staging_kw = {"staging", "stage", "stg", "dev", "old", "legacy",
                      "backup", "test", "qa", "preprod", "internal"}

        for cert in self.graph.get_by_type(EntityType.CERTIFICATE):
            for san in cert.properties.get("sans", []):
                san = san.lstrip("*.")
                label = san.split(".")[0].lower()
                if any(kw in label for kw in staging_kw):
                    resolved = await self.dns.resolve_a(san)
                    ips.extend(ip for ip in resolved if self._is_routable(ip))

        return list(set(ips))

    async def _verify_origin(self, ip: str, domain: str) -> Optional[Dict]:
        """Direct HTTP connection to IP with Host header injection."""
        for port in [443, 80, 8443, 8080]:
            try:
                scheme = "https" if port in (443, 8443) else "http"
                resp = await self.http.get(
                    f"{scheme}://{ip}:{port}/",
                    headers={"Host": domain, "X-Forwarded-For": "127.0.0.1"},
                )
                if resp and 100 <= (resp.get("status") or 0) < 500:
                    headers = resp.get("headers") or {}
                    server = headers.get("Server", "") or headers.get("server", "")
                    via = headers.get("Via", "") or headers.get("via", "")

                    cdns = {"cloudflare", "fastly", "akamai", "cloudfront", "sucuri"}
                    if any(c in (server + via).lower() for c in cdns):
                        continue
                    return {
                        "ip":        ip,
                        "port":      port,
                        "status":    resp["status"],
                        "server":    server[:60],
                        "confirmed": resp["status"] in (200, 301, 302, 401, 403),
                        "technique": "host_header_injection",
                    }
            except Exception:
                continue
        return None

    def _is_behind_cdn(self, domain_entity) -> bool:
        for ip_entity in self.graph.successors(domain_entity.id, RelationType.RESOLVES_TO):
            if ip_entity.properties.get("is_cdn"):
                return True
        return False

    @staticmethod
    def _is_routable(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return not (addr.is_private or addr.is_loopback or addr.is_link_local
                        or addr.is_multicast or addr.is_reserved or addr.is_unspecified)
        except ValueError:
            return False
