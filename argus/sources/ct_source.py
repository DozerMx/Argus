"""
Certificate Transparency Log Source
Queries crt.sh (free, public, RFC 6962 compliant aggregator).
Parses results directly into the Knowledge Graph.
"""
from __future__ import annotations
import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Optional, Set

from argus.ontology.entities import EntityType, RelationType
from argus.ontology.graph import KnowledgeGraph
from argus.utils.cache import DiskCache
from argus.utils.http_client import HTTPClient

logger = logging.getLogger("argus.sources.ct_source")

CRTSH_URL = "https://crt.sh"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"

class CTLogSource:
    def __init__(self, client: HTTPClient, cache: DiskCache, graph: KnowledgeGraph):
        self.http = client
        self.cache = cache
        self.graph = graph

    async def collect(self, domain: str) -> int:
        """
        Query CT logs for all certificates covering domain.
        Populates the Knowledge Graph with Certificate, Organization entities
        and ISSUED_BY, SECURED_BY, OWNED_BY_ORG relationships.
        Returns count of unique certificates found.
        """
        entries = await self._fetch_all(domain)
        return self._ingest(domain, entries)

    async def _fetch_all(self, domain: str) -> List[dict]:
        cache_key = f"crtsh_v3:{domain}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        queries = [domain, f"%.{domain}"]
        results = await asyncio.gather(
            *[self._fetch_one(q) for q in queries],
            return_exceptions=True,
        )

        seen_ids: Set[int] = set()
        all_entries = []
        for batch in results:
            if isinstance(batch, list):
                for entry in batch:
                    cert_id = entry.get("id")
                    if cert_id and cert_id not in seen_ids:
                        seen_ids.add(cert_id)
                        all_entries.append(entry)

        self.cache.set(cache_key, all_entries)
        logger.info(f"CT: {len(all_entries)} unique certs for {domain}")
        return all_entries

    async def _fetch_one(self, query: str) -> List[dict]:
        """
        Fetch CT entries directly via aiohttp — bypasses http_client wrapper
        which has issues with large streaming responses on some networks.
        """
        import aiohttp as _aiohttp
        import json as _json
        import asyncio as _asyncio
        import ssl as _ssl

        ssl_ctx = _ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = _ssl.CERT_NONE
        timeout = _aiohttp.ClientTimeout(total=90, connect=10, sock_read=90)

        for attempt in range(3):
            try:
                async with _aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(
                        CRTSH_URL,
                        params={"q": query, "output": "json"},
                        ssl=ssl_ctx,
                    ) as resp:
                        status = resp.status
                        if status == 503:
                            wait = (attempt + 1) * 10
                            logger.warning(f"crt.sh 503 — retry {attempt+2}/3 in {wait}s")
                            await _asyncio.sleep(wait)
                            continue
                        if status != 200:
                            logger.warning(f"crt.sh status {status}")
                            break
                        raw  = await resp.read()
                        data = _json.loads(raw)
                        if isinstance(data, list):
                            logger.debug(f"crt.sh: {len(data)} entries for '{query}'")
                            return data
            except (_json.JSONDecodeError, Exception) as e:
                logger.warning(f"crt.sh attempt {attempt+1} error: {e}")
                if attempt < 2:
                    await _asyncio.sleep(5)

        logger.info("crt.sh unavailable — trying certspotter")
        try:
            async with _aiohttp.ClientSession(timeout=timeout) as session:
                domain_query = query.lstrip("%.")
                async with session.get(
                    CERTSPOTTER_URL,
                    params={
                        "domain":             domain_query,
                        "include_subdomains": "true",
                        "expand":             "dns_names",
                        "after":              "0",
                    },
                    ssl=ssl_ctx,
                ) as resp:
                    if resp.status == 200:
                        entries = await resp.json(content_type=None)
                        if isinstance(entries, list):
                            converted = []
                            for entry in entries:
                                dns_names  = entry.get("dns_names", [])
                                not_before = entry.get("not_before", "")
                                not_after  = entry.get("not_after",  "")
                                issuer_cn  = entry.get("issuer", {}).get("common_name", "")
                                for name in dns_names:
                                    converted.append({
                                        "name_value":  name,
                                        "common_name": dns_names[0] if dns_names else name,
                                        "not_before":  not_before,
                                        "not_after":   not_after,
                                        "issuer_name": f"CN={issuer_cn}",
                                        "id":          hash(name + not_before),
                                    })
                            logger.info(f"certspotter: {len(converted)} entries")
                            return converted
        except Exception as e:
            logger.warning(f"certspotter error: {e}")

        return []

    def _ingest(self, domain: str, entries: List[dict]) -> int:
        count = 0
        for entry in entries:
            try:
                self._ingest_entry(domain, entry)
                count += 1
            except Exception as e:
                logger.debug(f"Entry ingest error: {e}")
        return count

    def _ingest_entry(self, target_domain: str, entry: dict) -> None:
        g = self.graph
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        not_before = self._parse_dt(entry.get("not_before"))
        not_after  = self._parse_dt(entry.get("not_after"))
        is_expired = bool(not_after and not_after < now)

        name_value   = (entry.get("name_value") or "").strip()
        common_name  = (entry.get("common_name") or "").strip().lower()
        issuer_name  = entry.get("issuer_name") or ""
        issuer_cn    = self._dn_field(issuer_name, "CN")
        issuer_o     = self._dn_field(issuer_name, "O")

        all_names: Set[str] = set()
        for n in name_value.split("\n"):
            n = n.strip().lower()
            if n:
                all_names.add(n)
        if common_name:
            all_names.add(common_name)

        relevant_names = {
            n.lstrip("*.") for n in all_names
            if n.lstrip("*.") == target_domain or n.lstrip("*.").endswith(f".{target_domain}")
        }
        if not relevant_names:
            return

        is_wildcard = any("*" in n for n in all_names)

        cert_name = common_name or list(relevant_names)[0]
        cert_entity = g.find_or_create(
            EntityType.CERTIFICATE,
            name=f"cert:{entry.get('id', cert_name)}",
            properties={
                "id":          entry.get("id"),
                "common_name": common_name,
                "issuer_cn":   issuer_cn,
                "issuer_o":    issuer_o,
                "not_before":  not_before.isoformat() if not_before else None,
                "not_after":   not_after.isoformat() if not_after else None,
                "is_expired":  is_expired,
                "is_wildcard": is_wildcard,
                "sans":        list(relevant_names),
            },
            source="crt.sh",
        )
        if not_before and (not cert_entity.first_seen or not_before < cert_entity.first_seen):
            cert_entity.first_seen = not_before
        if not_after:
            cert_entity.last_seen = not_after

        if issuer_o or issuer_cn:
            ca_name = issuer_o or issuer_cn
            ca_entity = g.find_or_create(
                EntityType.ORGANIZATION,
                name=ca_name,
                properties={"type": "CA", "cn": issuer_cn, "o": issuer_o},
                source="crt.sh",
            )
            g.link(cert_entity.id, ca_entity.id, RelationType.ISSUED_BY, source="crt.sh")

        for san in relevant_names:
            domain_entity = g.find_or_create(
                EntityType.DOMAIN,
                name=san,
                source="crt.sh",
            )
            if not_before and (not domain_entity.first_seen or not_before < domain_entity.first_seen):
                domain_entity.first_seen = not_before

            g.link(
                domain_entity.id,
                cert_entity.id,
                RelationType.SECURED_BY,
                properties={"not_before": not_before.isoformat() if not_before else None,
                            "is_expired": is_expired},
                source="crt.sh",
            )

    @staticmethod
    def _parse_dt(s: Optional[str]) -> Optional[datetime]:
        if not s:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(s[:19], fmt)
            except ValueError:
                continue
        return None

    @staticmethod
    def _dn_field(dn: str, field: str) -> str:
        for part in dn.split(","):
            p = part.strip()
            if p.startswith(f"{field}="):
                return p[len(field) + 1:].strip()
        return ""
