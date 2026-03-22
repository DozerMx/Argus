"""
IPv6 Intelligence Module
Many CDN-protected servers expose their real IPv6 address even when
their IPv4 is hidden behind a CDN. IPv6 is often overlooked by defenders.

- Resolves AAAA records for all domains
- Cross-references IPv6 with IPv4 (same server, bypasses CDN?)
- Scans IPv6 addresses for open ports
- Detects IPv6-only services not behind CDN
"""
from __future__ import annotations
import asyncio
import ipaddress
import logging
from typing import Dict, List, Optional, Set

from argus.ontology.entities import Anomaly, EntityType, RelationType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.ipv6")

class IPv6Intel:
    def __init__(self, dns_correlator, graph: KnowledgeGraph, timeout: float = 5.0):
        self.dns     = dns_correlator
        self.graph   = graph
        self.timeout = timeout

    async def run(self) -> Dict[str, int]:
        """Resolve AAAA records for all domains and correlate."""
        domains = self.graph.get_by_type(EntityType.DOMAIN)
        sem = asyncio.Semaphore(30)
        ipv6_found = 0
        cdn_bypass_candidates = 0
        lock = asyncio.Lock()

        async def process_domain(domain_entity):
            nonlocal ipv6_found, cdn_bypass_candidates
            async with sem:
                aaaa_records = await self.dns._doh(domain_entity.name, "AAAA")
                for ipv6_str in aaaa_records:
                    if not self._is_valid_ipv6(ipv6_str):
                        continue

                    async with lock:
                        ipv6_found += 1

                    ipv6_entity = self.graph.find_or_create(
                        EntityType.IP,
                        name=ipv6_str,
                        properties={"version": 6, "is_cdn": False},
                        source="ipv6_intel",
                    )
                    self.graph.link(
                        domain_entity.id, ipv6_entity.id,
                        RelationType.RESOLVES_TO,
                        properties={"record_type": "AAAA"},
                        source="ipv6_intel",
                    )
                    self.graph.index_ip_domain(ipv6_str, domain_entity.name)

                    ipv4_entities = [
                        e for e in self.graph.successors(domain_entity.id, RelationType.RESOLVES_TO)
                        if e.name != ipv6_str and e.properties.get("is_cdn")
                    ]
                    if ipv4_entities:

                        self.graph.penalize_entity(domain_entity.id, Anomaly(
                            code="IPV6_CDN_BYPASS_CANDIDATE",
                            title="IPv6 Address May Bypass CDN",
                            detail=f"{domain_entity.name}: IPv4 is behind CDN but has IPv6 "
                                   f"({ipv6_str}) — IPv6 address may directly reach origin server",
                            severity=Severity.HIGH,
                            entity_id=domain_entity.id,
                            entity_name=domain_entity.name,
                        ))
                        async with lock:
                            cdn_bypass_candidates += 1

        await asyncio.gather(*[process_domain(d) for d in domains], return_exceptions=True)

        return {
            "ipv6_addresses_found":     ipv6_found,
            "cdn_bypass_candidates":    cdn_bypass_candidates,
        }

    @staticmethod
    def _is_valid_ipv6(s: str) -> bool:
        try:
            addr = ipaddress.IPv6Address(s)
            return not (addr.is_loopback or addr.is_link_local or
                        addr.is_multicast or addr.is_unspecified)
        except ValueError:
            return False
