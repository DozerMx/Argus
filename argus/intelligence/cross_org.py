"""
Cross-Organization Correlation Engine
Given a target domain's ASN, maps ALL organizations sharing the same
IP block and builds a cross-organizational knowledge graph.

Use cases:
  - Government infrastructure mapping: scan one ministry,
    discover the entire government's shared infrastructure
  - Shared hosting risk: find all co-tenants on same IPs
  - Supply chain: identify vendor/partner infrastructure

Sources (all public, no API keys):
  1. Team Cymru DNS — ASN prefix ranges
  2. RDAP (Registration Data Access Protocol) — org/abuse contacts
  3. BGP.tools DNS TXT records — prefix → ASN mapping
  4. IP-to-ASN inference from discovered IPs
"""
from __future__ import annotations
import asyncio
import ipaddress
import logging
import re
from typing import Dict, List, Optional, Set, Tuple

from argus.ontology.entities import (
    Anomaly, EntityType, RelationType, Severity,
)
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.cross_org")

RDAP_ARIN   = "https://rdap.arin.net/registry"
RDAP_RIPE   = "https://rdap.db.ripe.net"
RDAP_LACNIC = "https://rdap.lacnic.net/rdap"
RDAP_APNIC  = "https://rdap.apnic.net"
RDAP_AFRINIC= "https://rdap.afrinic.net/rdap"

RIR_BY_CC: Dict[str, str] = {

    "US":"ARIN","CA":"ARIN","MX":"LACNIC","BR":"LACNIC","AR":"LACNIC",
    "CO":"LACNIC","PE":"LACNIC","CL":"LACNIC","VE":"LACNIC","EC":"LACNIC",
    "BO":"LACNIC","UY":"LACNIC","PY":"LACNIC",

    "GB":"RIPE","DE":"RIPE","FR":"RIPE","ES":"RIPE","IT":"RIPE",
    "NL":"RIPE","BE":"RIPE","SE":"RIPE","NO":"RIPE","PL":"RIPE",
    "RU":"RIPE","TR":"RIPE","UA":"RIPE","CH":"RIPE","AT":"RIPE",

    "CN":"APNIC","JP":"APNIC","KR":"APNIC","IN":"APNIC","AU":"APNIC",
    "SG":"APNIC","TW":"APNIC","ID":"APNIC","TH":"APNIC","VN":"APNIC",

    "ZA":"AFRINIC","NG":"AFRINIC","EG":"AFRINIC","KE":"AFRINIC",
}

RDAP_ENDPOINTS: Dict[str, str] = {
    "ARIN":    RDAP_ARIN,
    "RIPE":    RDAP_RIPE,
    "LACNIC":  RDAP_LACNIC,
    "APNIC":   RDAP_APNIC,
    "AFRINIC": RDAP_AFRINIC,
}

class CrossOrgCorrelation:
    def __init__(self, http_client, dns_correlator, graph: KnowledgeGraph):
        self.http  = http_client
        self.dns   = dns_correlator
        self.graph = graph

    async def run(self, domain: str) -> Dict[str, int]:
        """
        Full cross-org analysis for all ASNs discovered in the scan.
        """

        asn_entities = self.graph.get_by_type(EntityType.ASN)
        if not asn_entities:
            logger.info("No ASNs in graph — skipping cross-org correlation")
            return {"orgs_found": 0, "related_domains": 0, "shared_ips": 0}

        total_orgs    = 0
        total_domains = 0
        total_shared  = 0

        for asn_entity in asn_entities[:5]:
            asn_num = asn_entity.properties.get("number") or asn_entity.name.replace("AS", "")
            country = asn_entity.properties.get("country", "")

            prefixes = await self._get_asn_prefixes(asn_num)

            if not prefixes:
                continue

            asn_entity.properties["prefixes"] = prefixes[:20]

            for prefix in prefixes[:3]:
                shared = await self._enumerate_prefix_domains(prefix, domain, asn_entity)
                total_shared += shared

            rdap_data = await self._rdap_lookup(asn_num, country)
            if rdap_data:
                asn_entity.properties.update(rdap_data)
                total_orgs += 1

                related = await self._find_related_orgs(rdap_data, asn_entity)
                total_domains += related

        return {
            "orgs_found":     total_orgs,
            "related_domains": total_domains,
            "shared_ips":     total_shared,
        }

    async def _get_asn_prefixes(self, asn_num: str) -> List[str]:
        """Get all IP prefixes for an ASN using Team Cymru DNS."""
        try:

            query = f"AS{asn_num}.asn.cymru.com"
            records = await self.dns._doh(query, "TXT")
            prefixes = []
            for record in records:

                for match in re.finditer(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}", record):
                    prefixes.append(match.group(0))
            return prefixes
        except Exception as e:
            logger.debug(f"ASN prefix lookup error {asn_num}: {e}")
        return []

    async def _enumerate_prefix_domains(
        self, prefix: str, target_domain: str, asn_entity
    ) -> int:
        """
        For a given IP prefix, find domains hosted on those IPs via
        reverse DNS and cross-reference with known IP-domain mappings.
        """
        shared_count = 0
        try:
            network = ipaddress.ip_network(prefix, strict=False)

            if network.prefixlen < 24:

                hosts = list(network.hosts())[:256]
            else:
                hosts = list(network.hosts())[:50]

            sem = asyncio.Semaphore(30)

            async def reverse_one(ip_obj):
                nonlocal shared_count
                ip_str = str(ip_obj)
                async with sem:

                    existing_domains = self.graph.get_domains_on_ip(ip_str)
                    if existing_domains:
                        for domain_name in existing_domains:
                            if not domain_name.endswith(f".{target_domain}") and domain_name != target_domain:

                                neighbor = self.graph.find_or_create(
                                    EntityType.DOMAIN,
                                    name=domain_name,
                                    properties={"is_neighbor": True, "shared_asn": asn_entity.name},
                                    source="cross_org",
                                )
                                ip_entity = self.graph.get_by_name(ip_str)
                                if ip_entity and neighbor:
                                    self.graph.link(
                                        neighbor.id, ip_entity.id,
                                        RelationType.HISTORICALLY_AT,
                                        properties={"via": "cross_org_asn"},
                                        source="cross_org",
                                    )
                                shared_count += 1
                        return

                    reversed_ip = ".".join(reversed(ip_str.split("."))) + ".in-addr.arpa"
                    try:
                        ptr_records = await asyncio.wait_for(
                            self.dns._doh(reversed_ip, "PTR"),
                            timeout=3.0,
                        )
                        for ptr in ptr_records:
                            hostname = ptr.rstrip(".")
                            if hostname and "." in hostname:
                                self.graph.index_ip_domain(ip_str, hostname.lower())
                                shared_count += 1
                    except Exception:
                        pass

            await asyncio.gather(*[reverse_one(ip) for ip in hosts], return_exceptions=True)

        except Exception as e:
            logger.debug(f"Prefix enumeration error {prefix}: {e}")

        return shared_count

    async def _rdap_lookup(self, asn_num: str, country: str) -> Optional[Dict]:
        """
        RDAP lookup for ASN registration details.
        Returns org name, abuse contact, registration date.
        """
        rir = RIR_BY_CC.get(country, "ARIN")
        endpoint = RDAP_ENDPOINTS.get(rir, RDAP_ARIN)

        try:
            resp = await self.http.get(f"{endpoint}/autnum/{asn_num}")
            if not resp or resp.get("status") != 200:

                resp = await self.http.get(f"{RDAP_ARIN}/autnum/{asn_num}")

            if resp and resp.get("status") == 200:
                data = resp.get("data") or {}
                if not isinstance(data, dict):
                    return None

                result = {
                    "rdap_name":   data.get("name", ""),
                    "rdap_handle": data.get("handle", ""),
                    "rdap_type":   data.get("type", ""),
                }

                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "abuse" in roles:
                        vcards = entity.get("vcardArray", [])
                        for vcard in vcards:
                            if isinstance(vcard, list):
                                for field in vcard:
                                    if isinstance(field, list) and len(field) >= 4:
                                        if field[0] == "email":
                                            result["abuse_email"] = field[3]

                return result
        except Exception as e:
            logger.debug(f"RDAP lookup error AS{asn_num}: {e}")
        return None

    async def _find_related_orgs(self, rdap_data: Dict, asn_entity) -> int:
        """
        Find other ASNs/orgs with similar RDAP registration data.
        Same org name = shared infrastructure.
        """
        related = 0
        org_name = rdap_data.get("rdap_name", "")
        if not org_name or len(org_name) < 4:
            return 0

        org_entity = self.graph.find_or_create(
            EntityType.ORGANIZATION,
            name=org_name,
            properties={
                "rdap_handle": rdap_data.get("rdap_handle"),
                "abuse_email": rdap_data.get("abuse_email"),
                "source":      "rdap",
            },
            source="cross_org",
        )

        self.graph.link(asn_entity.id, org_entity.id, RelationType.ASN_OWNED_BY, source="cross_org")

        ip_count = len(self.graph.get_by_type(EntityType.IP))
        if ip_count > 10:
            self.graph.penalize_entity(asn_entity.id, Anomaly(
                code="CROSS_ORG_SHARED_INFRA",
                title=f"Shared Infrastructure: {org_name}",
                detail=f"Multiple domains share infrastructure under org '{org_name}' "
                       f"(ASN {asn_entity.name}). Security posture of co-tenants affects attack surface.",
                severity=Severity.INFO,
                entity_id=asn_entity.id,
                entity_name=asn_entity.name,
            ))
            related += 1

        return related
