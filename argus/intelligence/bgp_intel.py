"""
BGP + AS Path Intelligence Module
- BGP prefix analysis via RIPEstat and BGPView APIs
- AS relationship mapping (peer, upstream, downstream)
- Cloud provider correlation by ASN
- BGP hijack/route leak detection
- IP space enumeration from ASN
- IXP (Internet Exchange Point) detection
"""
from __future__ import annotations
import asyncio
import logging
from typing import Dict, List, Optional, Set, Tuple

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.bgp")

RIPESTAT_BASE  = "https://stat.ripe.net/data"
BGPVIEW_BASE   = "https://api.bgpview.io"
IPINFO_BASE    = "https://ipinfo.io"

CLOUD_ASN_MAP = {
    "AS16509":  "AWS",          "AS14618":  "AWS",
    "AS8075":   "Azure",        "AS8069":   "Azure",
    "AS15169":  "GCP",          "AS396982": "GCP",
    "AS54113":  "Fastly",       "AS13335":  "Cloudflare",
    "AS209242": "Cloudflare",   "AS20940":  "Akamai",
    "AS16625":  "Akamai",       "AS32934":  "Meta",
    "AS2906":   "Netflix",      "AS15133":  "Edgio",
    "AS22822":  "Limelight",    "AS30675":  "Limelight",
    "AS46489":  "Twitch",       "AS36351":  "SoftLayer/IBM",
    "AS14061":  "DigitalOcean", "AS63949":  "Linode/Akamai",
    "AS24940":  "Hetzner",      "AS16276":  "OVH",
    "AS12876":  "Scaleway",     "AS45102":  "Alibaba",
    "AS37963":  "Alibaba",      "AS55967":  "Baidu",
    "AS9808":   "Huawei Cloud",
}

HOSTING_KEYWORDS = [
    "hosting", "cloud", "datacenter", "data center",
    "colocation", "colo", "cdn", "content delivery",
    "amazon", "google", "microsoft", "azure", "digital ocean",
]

class BGPIntelligence:
    def __init__(self, http_client, graph: KnowledgeGraph):
        self.http   = http_client
        self.graph  = graph
        self._seen_asns: Set[str] = set()

    async def run(self) -> Dict:
        ips     = self.graph.get_by_type(EntityType.IP)
        domains = self.graph.get_by_type(EntityType.DOMAIN)
        sem     = asyncio.Semaphore(5)
        results = {
            "asns_analyzed":     0,
            "prefixes_found":    0,
            "peers_found":       0,
            "hijack_candidates": 0,
            "cloud_mapped":      0,
            "ixp_found":         0,
        }
        lock = asyncio.Lock()

        async def analyze_ip(entity):
            async with sem:
                r = await self._analyze_ip(entity)
                async with lock:
                    for k, v in r.items():
                        results[k] = results.get(k, 0) + v

        await asyncio.gather(*[analyze_ip(e) for e in ips],
                             return_exceptions=True)

        await self._cross_correlate_asns(domains, results, lock)
        return results

    async def _analyze_ip(self, entity) -> Dict:
        ip      = entity.name
        counts  = {"asns_analyzed": 0, "prefixes_found": 0,
                   "peers_found": 0, "hijack_candidates": 0,
                   "cloud_mapped": 0, "ixp_found": 0}

        prefix_data = await self._get_prefix_overview(ip)
        if not prefix_data:
            return counts

        asn  = prefix_data.get("asn", "")
        org  = prefix_data.get("holder", "")
        pfx  = prefix_data.get("prefix", "")

        if not asn:
            return counts

        asn_str = f"AS{asn}" if not str(asn).startswith("AS") else asn

        entity.properties["bgp_asn"]    = asn_str
        entity.properties["bgp_org"]    = org
        entity.properties["bgp_prefix"] = pfx
        counts["asns_analyzed"] += 1
        counts["prefixes_found"] += 1

        cloud = CLOUD_ASN_MAP.get(asn_str, "")
        if not cloud:
            for kw in HOSTING_KEYWORDS:
                if kw in org.lower():
                    cloud = "Hosting"
                    break
        if cloud:
            entity.properties["cloud_provider"] = cloud
            counts["cloud_mapped"] += 1

        if asn_str in self._seen_asns:
            return counts
        self._seen_asns.add(asn_str)

        peers = await self._get_asn_peers(asn_str)
        if peers:
            entity.properties["bgp_peers"] = peers[:20]
            counts["peers_found"] += len(peers)

        routes = await self._get_asn_routes(asn_str)
        if routes:
            entity.properties["bgp_routes"] = len(routes)
            hijack = await self._detect_route_anomalies(asn_str, pfx, routes)
            if hijack:
                counts["hijack_candidates"] += 1
                self.graph.penalize_entity(entity.id, Anomaly(
                    code="BGP_ROUTE_ANOMALY",
                    title="BGP Route Anomaly Detected",
                    detail=f"Unexpected route origin for {pfx} via {asn_str}: {hijack}",
                    severity=Severity.HIGH,
                    entity_id=entity.id, entity_name=ip,
                ))

        ixp = await self._detect_ixp(asn_str)
        if ixp:
            entity.properties["ixp_present"] = ixp
            counts["ixp_found"] += 1
            self.graph.penalize_entity(entity.id, Anomaly(
                code="IXP_PEERING_DETECTED",
                title="Internet Exchange Point Peering",
                detail=f"{org} ({asn_str}) peers at {ixp} — maps physical infrastructure location",
                severity=Severity.INFO,
                entity_id=entity.id, entity_name=ip,
            ))

        return counts

    async def _cross_correlate_asns(self, domains, results, lock) -> None:
        asn_domain_map: Dict[str, List[str]] = {}
        for domain in domains:
            asn = domain.properties.get("bgp_asn", "")
            if asn:
                asn_domain_map.setdefault(asn, []).append(domain.name)

        for asn, domain_list in asn_domain_map.items():
            if len(domain_list) > 3:
                for domain in self.graph.get_by_type(EntityType.DOMAIN):
                    if domain.name in domain_list:
                        self.graph.penalize_entity(domain.id, Anomaly(
                            code="ASN_INFRASTRUCTURE_CLUSTER",
                            title="Multiple Domains Share ASN Infrastructure",
                            detail=f"{len(domain_list)} domains share {asn} — single point of failure",
                            severity=Severity.INFO,
                            entity_id=domain.id, entity_name=domain.name,
                        ))
                        break

    async def _get_prefix_overview(self, ip: str) -> Optional[Dict]:
        try:
            resp = await self.http.get(
                f"{RIPESTAT_BASE}/prefix-overview/data.json",
                params={"resource": ip},
                timeout_override=10,
            )
            if resp and resp.get("status") == 200:
                data = resp.get("data", {}) or {}
                if isinstance(data, dict):
                    d = data.get("data", data)
                    asns = d.get("asns", [])
                    asn  = asns[0].get("asn") if asns else None
                    return {
                        "asn":    asn,
                        "holder": asns[0].get("holder", "") if asns else "",
                        "prefix": d.get("resource", ip),
                    }
        except Exception:
            pass

        try:
            resp = await self.http.get(
                f"{BGPVIEW_BASE}/ip/{ip}",
                timeout_override=10,
            )
            if resp and resp.get("status") == 200:
                data = resp.get("data", {}) or {}
                if isinstance(data, dict):
                    pfxs = data.get("data", {}).get("prefixes", [])
                    if pfxs:
                        asn_data = pfxs[0].get("asn", {})
                        return {
                            "asn":    asn_data.get("asn"),
                            "holder": asn_data.get("name", ""),
                            "prefix": pfxs[0].get("prefix", ip),
                        }
        except Exception:
            pass
        return None

    async def _get_asn_peers(self, asn_str: str) -> List[str]:
        asn_num = asn_str.replace("AS", "")
        try:
            resp = await self.http.get(
                f"{BGPVIEW_BASE}/asn/{asn_num}/peers",
                timeout_override=10,
            )
            if resp and resp.get("status") == 200:
                data = resp.get("data", {}) or {}
                peers = []
                for peer in data.get("data", {}).get("ipv4_peers", [])[:10]:
                    peers.append(f"AS{peer.get('asn')} ({peer.get('name','')})")
                return peers
        except Exception:
            pass
        return []

    async def _get_asn_routes(self, asn_str: str) -> List[Dict]:
        asn_num = asn_str.replace("AS", "")
        try:
            resp = await self.http.get(
                f"{RIPESTAT_BASE}/announced-prefixes/data.json",
                params={"resource": asn_str, "starttime": "2024-01-01"},
                timeout_override=10,
            )
            if resp and resp.get("status") == 200:
                data = resp.get("data", {}) or {}
                return data.get("data", {}).get("prefixes", [])[:20]
        except Exception:
            pass
        return []

    async def _detect_route_anomalies(self, asn_str: str,
                                       prefix: str,
                                       routes: List) -> str:
        try:
            resp = await self.http.get(
                f"{RIPESTAT_BASE}/bgp-state/data.json",
                params={"resource": prefix, "rrcs": "0,1,5"},
                timeout_override=10,
            )
            if resp and resp.get("status") == 200:
                data    = resp.get("data", {}) or {}
                routes  = data.get("data", {}).get("routes", [])
                origins = set()
                for r in routes:
                    path  = r.get("path", [])
                    if path:
                        origins.add(str(path[-1]))
                if len(origins) > 1:
                    return f"Multiple origin ASNs: {', '.join(origins)}"
        except Exception:
            pass
        return ""

    async def _detect_ixp(self, asn_str: str) -> str:
        asn_num = asn_str.replace("AS", "")
        try:
            resp = await self.http.get(
                f"{RIPESTAT_BASE}/ixs/data.json",
                params={"resource": asn_str},
                timeout_override=10,
            )
            if resp and resp.get("status") == 200:
                data = resp.get("data", {}) or {}
                ixps = data.get("data", {}).get("ixs", [])
                if ixps:
                    return ixps[0].get("name", "Unknown IXP")
        except Exception:
            pass
        return ""
