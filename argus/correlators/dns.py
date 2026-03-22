"""
DNS Resolver & Correlator v3.5
- Shared in-memory cache across all modules
- Prefetch trigger: queues GET / as soon as domain resolves alive
- DNS pipeline: resolve → enrich → process overlapped
- Cooperative cancellation: dead hosts immediately propagated
"""
from __future__ import annotations
import asyncio
import ipaddress
import logging
import re
from typing import Dict, List, Optional, Set

from argus.ontology.entities import EntityType, RelationType
from argus.ontology.graph import KnowledgeGraph
from argus.utils.cache import DiskCache
from argus.utils.http_client import HTTPClient

logger = logging.getLogger("argus.correlators.dns")

DOH_RESOLVERS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
]
RTYPE_NUM = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2, "TXT": 16, "PTR": 12}

_SCAN_DNS_CACHE: Dict[str, List[str]] = {}

def clear_scan_dns_cache() -> None:
    global _SCAN_DNS_CACHE
    _SCAN_DNS_CACHE = {}

class DNSCorrelator:
    def __init__(self, client: HTTPClient, cache: DiskCache, graph: KnowledgeGraph, timeout: int = 8):
        self.http    = client
        self.cache   = cache
        self.graph   = graph
        self.timeout = timeout

    async def resolve_all_domains(self, concurrency: int = 40) -> int:
        """
        Pipeline: resolve → enrich → prefetch all overlapped.
        DNS resolution triggers HTTP prefetch immediately on alive hosts.
        """
        domains   = self.graph.get_by_type(EntityType.DOMAIN)
        sem       = asyncio.Semaphore(concurrency)
        alive     = 0
        lock      = asyncio.Lock()
        _infra_tasks: list = []

        async def resolve_one(domain_entity):
            nonlocal alive
            async with sem:
                ips = await self.resolve_a(domain_entity.name)
                if ips:
                    domain_entity.properties["is_alive"] = True
                    async with lock:
                        alive += 1

                    for ip in ips:
                        ip_entity = self.graph.find_or_create(
                            EntityType.IP, name=ip,
                            properties={"is_cdn": False},
                            source="dns_live",
                        )
                        self.graph.link(
                            domain_entity.id, ip_entity.id,
                            RelationType.RESOLVES_TO, source="dns_live",
                        )
                        self.graph.index_ip_domain(ip, domain_entity.name)

                    scheme = "https"
                    self.http.queue_prefetch(domain_entity.name, scheme)

                else:
                    domain_entity.properties["is_alive"] = False

                    try:
                        from argus.utils.request_cache import set_host_status, HostStatus
                        await set_host_status(domain_entity.name, HostStatus.DEAD)
                    except ImportError:
                        pass

                async def _safe_infra(entity=domain_entity):
                    try:
                        await self._resolve_infra(entity)
                    except Exception:
                        pass
                _task = asyncio.create_task(_safe_infra())
                _infra_tasks.append(_task)

        await asyncio.gather(*[resolve_one(d) for d in domains], return_exceptions=True)

        if _infra_tasks:
            await asyncio.gather(*_infra_tasks, return_exceptions=True)

        logger.info(f"DNS: {alive}/{len(domains)} alive")
        return alive

    async def _resolve_infra(self, domain_entity) -> None:
        name = domain_entity.name
        try:
            ns_records = await self._doh(name, "NS")
            for ns_val in ns_records:
                ns_name = ns_val.rstrip(".")
                if ns_name:
                    ns_e = self.graph.find_or_create(EntityType.NAMESERVER, name=ns_name, source="dns")
                    self.graph.link(domain_entity.id, ns_e.id, RelationType.SERVED_BY_NS, source="dns")

            mx_records = await self._doh(name, "MX")
            for mx_val in mx_records:
                parts   = mx_val.split()
                mx_host = (parts[-1] if parts else mx_val).rstrip(".")
                if not mx_host:
                    continue
                mx_e = self.graph.find_or_create(EntityType.MAIL_SERVER, name=mx_host, source="dns")
                self.graph.link(domain_entity.id, mx_e.id, RelationType.MAIL_HANDLED_BY, source="dns")
                for ip in await self.resolve_a(mx_host):
                    if self._is_routable(ip):
                        ip_e = self.graph.find_or_create(
                            EntityType.IP, name=ip, properties={"role": "mail"}, source="dns"
                        )
                        self.graph.link(mx_e.id, ip_e.id, RelationType.RESOLVES_TO, source="dns")
                        self.graph.index_ip_domain(ip, name)
        except Exception as e:
            logger.debug(f"Infra resolve error {name}: {e}")

    async def resolve_a(self, name: str) -> List[str]:
        vals = await self._doh(name, "A")
        return [v for v in vals if self._is_ip(v)]

    async def spf_ips(self, domain: str) -> List[str]:
        ips: List[str] = []
        for record in await self._doh(domain, "TXT"):
            if "v=spf1" not in record.lower():
                continue
            for m in re.finditer(r"ip4:([^\s]+)", record, re.IGNORECASE):
                ip = m.group(1).split("/")[0]
                if self._is_routable(ip):
                    ips.append(ip)
            for m in re.finditer(r"include:([^\s]+)", record, re.IGNORECASE):
                for sr in await self._doh(m.group(1), "TXT"):
                    if "v=spf1" in sr.lower():
                        for m2 in re.finditer(r"ip4:([^\s]+)", sr, re.IGNORECASE):
                            ip2 = m2.group(1).split("/")[0]
                            if self._is_routable(ip2):
                                ips.append(ip2)
        return list(set(ips))

    async def mx_ips(self, domain: str) -> List[str]:
        ips: List[str] = []
        for record in await self._doh(domain, "MX"):
            parts   = record.split()
            mx_host = (parts[-1] if parts else record).rstrip(".")
            if mx_host:
                ips.extend(ip for ip in await self.resolve_a(mx_host) if self._is_routable(ip))
        return list(set(ips))

    async def _doh(self, name: str, rtype: str) -> List[str]:
        mem_key   = f"{name}:{rtype}"
        if mem_key in _SCAN_DNS_CACHE:
            return _SCAN_DNS_CACHE[mem_key]

        cache_key = f"doh3:{name}:{rtype}"
        cached    = self.cache.get(cache_key)
        if cached is not None:
            _SCAN_DNS_CACHE[mem_key] = cached
            return cached

        rtype_num = RTYPE_NUM.get(rtype.upper(), 1)
        for resolver in DOH_RESOLVERS:
            try:
                resp = await self.http.get(
                    resolver,
                    params={"name": name, "type": rtype},
                    headers={"Accept": "application/dns-json"},
                    read_limit=64*1024,
                    use_cache=False,
                )
                if resp.get("status") == 200 and isinstance(resp.get("data"), dict):
                    answers = resp["data"].get("Answer", [])
                    values  = [
                        a.get("data", "").rstrip(".")
                        for a in answers
                        if a.get("type") == rtype_num and a.get("data")
                    ]
                    if values:
                        _SCAN_DNS_CACHE[mem_key] = values
                        self.cache.set(cache_key, values)
                        return values
            except Exception as e:
                logger.debug(f"DoH error {resolver} {name}/{rtype}: {e}")

        _SCAN_DNS_CACHE[mem_key] = []
        self.cache.set(cache_key, [])
        return []

    @staticmethod
    def _is_ip(s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_routable(s: str) -> bool:
        try:
            a = ipaddress.ip_address(s)
            return not (a.is_private or a.is_loopback or a.is_link_local
                        or a.is_multicast or a.is_reserved or a.is_unspecified)
        except ValueError:
            return False
