"""
ASN and IP enrichment module
Team Cymru DNS lookup + embedded CDN IP ranges.
Enriches IP entities in the graph with ASN, org, country, CDN info.
"""
from __future__ import annotations
import ipaddress
import logging
from typing import Dict, List, Optional, Tuple

from argus.ontology.entities import EntityType, RelationType
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.asn")

_CDN_RANGES: Dict[str, List[str]] = {
    "Cloudflare": [
        "103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","104.16.0.0/13",
        "104.24.0.0/14","108.162.192.0/18","131.0.72.0/22","141.101.64.0/18",
        "162.158.0.0/15","172.64.0.0/13","173.245.48.0/20","188.114.96.0/20",
        "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17",
    ],
    "Fastly": [
        "23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","104.156.80.0/20",
        "140.248.64.0/18","140.248.128.0/17","146.75.0.0/17","151.101.0.0/16",
        "157.52.64.0/18","167.82.0.0/17","172.111.64.0/18","185.31.16.0/22",
        "199.27.72.0/21","199.232.0.0/16",
    ],
    "Amazon CloudFront": [
        "13.32.0.0/15","13.35.0.0/16","13.224.0.0/14","52.46.0.0/18",
        "52.84.0.0/15","54.182.0.0/16","54.192.0.0/16","64.252.64.0/18",
        "70.132.0.0/18","99.84.0.0/16","130.176.0.0/17","143.204.0.0/16",
        "205.251.192.0/19","216.137.32.0/19",
    ],
    "Akamai": [
        "23.32.0.0/11","23.64.0.0/14","23.72.0.0/13","72.246.0.0/15",
        "92.122.0.0/15","95.100.0.0/15","96.6.0.0/15","96.16.0.0/15",
        "173.222.0.0/15","184.24.0.0/13","184.50.0.0/15","184.84.0.0/14",
    ],
    "Azure CDN": [
        "13.107.246.0/24","13.107.213.0/24","20.21.0.0/17","40.82.0.0/22",
        "40.119.0.0/18","51.104.0.0/15",
    ],
    "Imperva": [
        "45.64.64.0/22","149.126.72.0/21","185.11.124.0/22",
        "192.230.64.0/18","199.83.128.0/21",
    ],
    "Sucuri": [
        "66.248.200.0/22","185.93.228.0/22","192.88.134.0/23",
        "192.88.135.0/24","198.143.32.0/21",
    ],
}

_CDN_ASN_KEYWORDS: Dict[str, str] = {
    "CLOUDFLARENET": "Cloudflare",
    "FASTLY":        "Fastly",
    "AMAZON":        "Amazon CloudFront",
    "AKAMAI":        "Akamai",
    "MICROSOFT":     "Azure CDN",
    "IMPERVA":       "Imperva",
    "SUCURI":        "Sucuri",
    "STACKPATH":     "StackPath",
    "LIMELIGHT":     "Limelight Networks",
}

_COMPILED: Optional[List[Tuple[ipaddress.IPv4Network, str]]] = None

def _get_cdn_networks() -> List[Tuple[ipaddress.IPv4Network, str]]:
    global _COMPILED
    if _COMPILED is None:
        _COMPILED = []
        for cdn, ranges in _CDN_RANGES.items():
            for cidr in ranges:
                try:
                    _COMPILED.append((ipaddress.ip_network(cidr, strict=False), cdn))
                except ValueError:
                    pass
    return _COMPILED

class ASNIntel:
    CYMRU_HOST = "origin.asn.cymru.com"
    CYMRU_INFO = "asn.cymru.com"

    def __init__(self, dns_correlator, graph: KnowledgeGraph):
        self.dns = dns_correlator
        self.graph = graph
        self._cache: Dict[str, Dict] = {}

    async def enrich_all_ips(self) -> None:
        """
        Enrich all IP entities in graph with ASN, org, CDN info.
        Adds ASN and Organization entities + relationships.
        """
        ip_entities = self.graph.get_by_type(EntityType.IP)
        import asyncio
        sem = asyncio.Semaphore(20)

        async def enrich_one(ip_entity):
            async with sem:
                await self._enrich_ip(ip_entity)

        await asyncio.gather(*[enrich_one(ip) for ip in ip_entities], return_exceptions=True)

    async def _enrich_ip(self, ip_entity) -> None:
        ip = ip_entity.name
        if not ip or ip in self._cache:
            data = self._cache.get(ip, {})
        else:
            data = await self._lookup(ip)
            self._cache[ip] = data

        if not data:
            return

        ip_entity.properties.update({k: v for k, v in data.items() if v})

        cdn = data.get("cdn_provider")
        if cdn:
            ip_entity.properties["is_cdn"] = True
            ip_entity.properties["cdn_provider"] = cdn

        asn_num = data.get("asn")
        asn_name = data.get("asn_name", "")
        if asn_num:
            asn_label = f"AS{asn_num}" + (f" {asn_name}" if asn_name else "")
            asn_entity = self.graph.find_or_create(
                EntityType.ASN,
                name=f"AS{asn_num}",
                properties={"number": asn_num, "name": asn_name,
                            "country": data.get("country"), "rir": data.get("rir")},
                source="cymru",
            )
            self.graph.link(ip_entity.id, asn_entity.id, RelationType.BELONGS_TO_ASN, source="cymru")

            if asn_name:
                org_entity = self.graph.find_or_create(
                    EntityType.ORGANIZATION,
                    name=asn_name,
                    properties={"type": "hosting", "country": data.get("country")},
                    source="cymru",
                )
                self.graph.link(asn_entity.id, org_entity.id, RelationType.ASN_OWNED_BY, source="cymru")

    async def _lookup(self, ip: str) -> Dict:
        result: Dict = {"ip": ip}

        cdn = self._check_cdn_ranges(ip)
        if cdn:
            result["is_cdn"] = True
            result["cdn_provider"] = cdn

        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
            query = f"{reversed_ip}.{self.CYMRU_HOST}"
            txt_values = await self.dns._doh(query, "TXT")
            for txt in txt_values:
                parsed = self._parse_cymru(txt)
                if parsed:
                    result.update(parsed)

                    if not result.get("cdn_provider") and parsed.get("asn_name"):
                        cdn_by_asn = self._check_cdn_asn(parsed["asn_name"])
                        if cdn_by_asn:
                            result["is_cdn"] = True
                            result["cdn_provider"] = cdn_by_asn
                    break
        except Exception as e:
            logger.debug(f"Cymru lookup error for {ip}: {e}")

        return result

    def _parse_cymru(self, txt: str) -> Optional[Dict]:
        txt = txt.strip().strip('"')
        parts = [p.strip() for p in txt.split("|")]
        if len(parts) < 4:
            return None
        return {
            "asn":     parts[0].strip(),
            "prefix":  parts[1].strip() if len(parts) > 1 else None,
            "country": parts[2].strip() if len(parts) > 2 else None,
            "rir":     parts[3].strip() if len(parts) > 3 else None,
            "asn_name": parts[4].strip().strip('"') if len(parts) > 4 else None,
        }

    def _check_cdn_ranges(self, ip: str) -> Optional[str]:
        try:
            addr = ipaddress.ip_address(ip)
            for network, cdn_name in _get_cdn_networks():
                if addr in network:
                    return cdn_name
        except ValueError:
            pass
        return None

    def _check_cdn_asn(self, asn_name: str) -> Optional[str]:
        upper = asn_name.upper()
        for keyword, cdn in _CDN_ASN_KEYWORDS.items():
            if keyword in upper:
                return cdn
        return None
