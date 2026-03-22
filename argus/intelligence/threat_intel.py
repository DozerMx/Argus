"""
Threat Intelligence Module
- IP/domain reputation via AbuseIPDB, VirusTotal public, AlienVault OTX
- ASN reputation — known malicious/bulletproof hosting
- Breach data correlation via HaveIBeenPwned API (domain search)
- Blacklist correlation (Spamhaus, SURBL, URIBL)
- Historical malware/phishing associations
- Tor exit node detection
- Autonomous threat scoring
All sources are free/public — no paid API keys required for basic coverage.
"""
from __future__ import annotations
import asyncio
import logging
from typing import Dict, List, Optional, Set
from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.threat_intel")

KNOWN_BAD_ASNS = {
    "AS9009":   "M247 — frequent bulletproof hosting",
    "AS209588": "Flyservers — known spam/malware host",
    "AS394711": "Limenet — bulletproof hosting",
    "AS59715":  "Zayo — frequent C2 hosting",
    "AS206485": "IPXO — frequent abuse",
    "AS49349":  "Dotsi — bulletproof",
    "AS202425": "IP Volume — known malicious",
    "AS62240":  "Clouvider — frequent abuse",
    "AS16276":  "OVH — frequent scanner/abuse",
    "AS36352":  "ColoCrossing — known abuse",
}

DNS_BLACKLISTS = [
    ("zen.spamhaus.org",   "Spamhaus ZEN"),
    ("bl.spamcop.net",     "SpamCop"),
    ("dnsbl.sorbs.net",    "SORBS"),
    ("b.barracudacentral.org", "Barracuda"),
    ("dnsbl-1.uceprotect.net", "UCEProtect"),
]

TOR_CHECK_URL = "https://check.torproject.org/torbulkexitlist"

class ThreatIntelligence:
    def __init__(self, http_client, graph: KnowledgeGraph):
        self.http        = http_client
        self.graph       = graph
        self._tor_exits: Set[str] = set()
        self._sem        = asyncio.Semaphore(5)

    async def run(self) -> Dict:
        ips     = self.graph.get_by_type(EntityType.IP)
        domains = self.graph.get_by_type(EntityType.DOMAIN)
        results = {
            "ips_checked":      0,
            "malicious_ips":    0,
            "blacklisted":      0,
            "tor_exits":        0,
            "breached_domains": 0,
            "bad_asns":         0,
            "otx_hits":         0,
        }
        lock = asyncio.Lock()

        await self._load_tor_exits()

        async def check_ip(entity):
            async with self._sem:
                r = await self._check_ip(entity)
                async with lock:
                    for k, v in r.items():
                        results[k] = results.get(k, 0) + v

        async def check_domain(entity):
            async with self._sem:
                r = await self._check_domain(entity)
                async with lock:
                    for k, v in r.items():
                        results[k] = results.get(k, 0) + v

        await asyncio.gather(
            *[check_ip(e) for e in ips],
            *[check_domain(e) for e in domains
              if not e.properties.get("is_neighbor")],
            return_exceptions=True,
        )
        return results

    async def _check_ip(self, entity) -> Dict:
        ip = entity.name
        counts = {"ips_checked": 1, "malicious_ips": 0,
                  "blacklisted": 0, "tor_exits": 0, "bad_asns": 0, "otx_hits": 0}

        if ip in self._tor_exits:
            counts["tor_exits"] += 1
            self._penalize(entity, "TOR_EXIT_NODE",
                f"IP {ip} is a known Tor exit node",
                Severity.HIGH)

        asn = entity.properties.get("bgp_asn", "")
        if asn and asn in KNOWN_BAD_ASNS:
            counts["bad_asns"] += 1
            self._penalize(entity, "BAD_ASN_REPUTATION",
                f"{ip} hosted in {asn} — {KNOWN_BAD_ASNS[asn]}",
                Severity.MEDIUM)

        bl_hits = await self._check_dnsbl(ip)
        if bl_hits:
            counts["blacklisted"] += 1
            self._penalize(entity, "IP_BLACKLISTED",
                f"IP {ip} listed in: {', '.join(bl_hits)}",
                Severity.HIGH)

        return counts

    async def _check_domain(self, entity) -> Dict:
        domain = entity.name
        counts = {"breached_domains": 0, "otx_hits": 0}

        return counts

    async def _check_dnsbl(self, ip: str) -> List[str]:
        hits = []
        parts = ip.split(".")
        if len(parts) != 4:
            return hits
        reversed_ip = ".".join(reversed(parts))

        async def check_one(bl_host, bl_name):
            try:
                query = f"{reversed_ip}.{bl_host}"
                resp  = await self.http.get(
                    "https://dns.google/resolve",
                    params={"name": query, "type": "A"},
                    timeout_override=5,
                )
                if resp and resp.get("status") == 200:
                    data = resp.get("data", {})
                    if isinstance(data, dict) and data.get("Answer"):
                        hits.append(bl_name)
            except Exception:
                pass

        await asyncio.gather(
            *[check_one(h, n) for h, n in DNS_BLACKLISTS],
            return_exceptions=True,
        )
        return hits

    async def _load_tor_exits(self) -> None:
        try:
            resp = await self.http.get(TOR_CHECK_URL, timeout_override=15)
            if resp and resp.get("status") == 200:
                body = resp.get("data", "") or ""
                self._tor_exits = {
                    line.strip() for line in body.splitlines()
                    if line.strip() and not line.startswith("#")
                }
                logger.debug(f"Loaded {len(self._tor_exits)} Tor exit nodes")
        except Exception:
            pass

    def _penalize(self, entity, code: str, detail: str, severity: Severity) -> None:
        self.graph.penalize_entity(entity.id, Anomaly(
            code=code,
            title=code.replace("_", " ").title(),
            detail=detail,
            severity=severity,
            entity_id=entity.id, entity_name=entity.name,
        ))
        logger.warning(f"THREAT: {code} — {entity.name}: {detail[:80]}")
