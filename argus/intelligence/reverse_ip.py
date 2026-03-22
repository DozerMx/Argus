"""
Reverse IP & ASN Pivot Intelligence
  - Reverse IP: find ALL domains hosted on same IPs (not just target's)
  - ASN Pivot: enumerate all .gov.co (or TLD) domains in same ASN
  - Banner version analysis: CVE-risk scoring from service banners
  - Co-location intelligence: identify suspicious neighbors
"""
from __future__ import annotations
import asyncio
import logging
import re
from typing import Dict, List, Optional, Set

from argus.ontology.entities import (
    Anomaly, EntityType, RelationType, Severity,
)
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.reverse_ip")

VULNERABLE_VERSIONS: List[Dict] = [
    {"pattern": r"apache[/ ]2\.2\.",    "service": "Apache", "note": "Apache 2.2.x — EOL since 2018, multiple critical CVEs"},
    {"pattern": r"apache[/ ]2\.4\.(0|[1-3][0-9]|4[0-9])\b", "service": "Apache", "note": "Apache 2.4 < 2.4.51 — vulnerable to CVE-2021-41773 (RCE) family"},
    {"pattern": r"nginx[/ ]1\.(0|[2-9]|1[0-7])\.", "service": "nginx", "note": "nginx < 1.18 — multiple known vulnerabilities"},
    {"pattern": r"openssl[/ ]1\.0\.",   "service": "OpenSSL", "note": "OpenSSL 1.0.x — EOL, Heartbleed-era"},
    {"pattern": r"openssl[/ ]1\.1\.0",  "service": "OpenSSL", "note": "OpenSSL 1.1.0 — EOL since Sep 2019"},
    {"pattern": r"php[/ ][45678]\.",    "service": "PHP", "note": "PHP 4-8 — check exact version for EOL status"},
    {"pattern": r"php[/ ][5678]\.[0-3]\.", "service": "PHP", "note": "Potentially EOL PHP version"},
    {"pattern": r"iis[/ ][678]\.",      "service": "IIS", "note": "IIS 6-8 — very old, EOL"},
    {"pattern": r"openssh[_ ]([1-7]\.|8\.[0-3])", "service": "OpenSSH", "note": "Potentially outdated OpenSSH"},
    {"pattern": r"proftpd[/ ]1\.[23]", "service": "ProFTPD", "note": "ProFTPD < 1.3.x — multiple CVEs"},
    {"pattern": r"vsftpd 2\.",          "service": "vsftpd", "note": "vsftpd 2.x — check for backdoor CVE-2011-2523"},
    {"pattern": r"exim[/ ][1-4]\.",     "service": "Exim", "note": "Exim — check version against CVE-2019-10149 (RCE)"},
]

HACKERTARGET_REVERSEIP = "https://api.hackertarget.com/reverseiplookup/"

class ReverseIPIntel:
    def __init__(self, http_client, dns_correlator, graph: KnowledgeGraph):
        self.http  = http_client
        self.dns   = dns_correlator
        self.graph = graph

    async def run(self, apex_domain: str) -> Dict:
        """Run all reverse IP and banner analysis."""
        reverse_count  = await self._reverse_ip_all()
        banner_count   = self._analyze_banners()
        neighbor_count = self._flag_suspicious_neighbors(apex_domain)

        return {
            "reverse_ip_domains": reverse_count,
            "vulnerable_banners":  banner_count,
            "flagged_neighbors":   neighbor_count,
        }

    async def _reverse_ip_all(self) -> int:
        """Query HackerTarget reverse IP for all discovered IPs."""
        ip_entities = self.graph.get_by_type(EntityType.IP)
        sem = asyncio.Semaphore(5)
        total = 0
        lock = asyncio.Lock()

        async def reverse_one(ip_entity):
            nonlocal total
            async with sem:
                domains = await self._reverse_ip_lookup(ip_entity.name)
                async with lock:
                    total += len(domains)

                ip_entity.properties["reverse_ip_neighbors"] = domains[:50]
                ip_entity.properties["reverse_ip_total"]     = len(domains)
                for domain_name in domains:
                    domain_name = domain_name.lower().strip()
                    if domain_name:
                        self.graph.index_ip_domain(ip_entity.name, domain_name)

        await asyncio.gather(*[reverse_one(ip) for ip in ip_entities[:20]], return_exceptions=True)
        return total

    async def _reverse_ip_lookup(self, ip: str) -> List[str]:
        """HackerTarget reverse IP lookup — free, no auth."""
        try:
            resp = await self.http.get(
                HACKERTARGET_REVERSEIP,
                params={"q": ip},
            )
            if resp and resp.get("status") == 200:
                data = resp.get("data", "")
                if isinstance(data, str) and "error" not in data.lower():
                    return [line.strip() for line in data.splitlines() if line.strip()]
        except Exception as e:
            logger.debug(f"Reverse IP error for {ip}: {e}")
        return []

    def _analyze_banners(self) -> int:
        """
        Analyze service banners for version disclosure and known vulnerabilities.
        """
        vulnerable_count = 0
        for svc in self.graph.get_by_type(EntityType.PORT_SERVICE):
            banner = (svc.properties.get("banner") or "").lower()
            server = (svc.properties.get("server") or "").lower()
            combined = f"{banner} {server}"

            if not combined.strip():
                continue

            for vuln in VULNERABLE_VERSIONS:
                if re.search(vuln["pattern"], combined, re.IGNORECASE):
                    vulnerable_count += 1

                    ip_str = svc.properties.get("ip", "")
                    ip_entity = self.graph.get_by_name(ip_str) if ip_str else None
                    target_id   = ip_entity.id if ip_entity else svc.id
                    target_name = ip_str or svc.name

                    self.graph.penalize_entity(target_id, Anomaly(
                        code="BANNER_VULNERABLE_VERSION",
                        title=f"Potentially Vulnerable {vuln['service']} Version",
                        detail=f"Port {svc.properties.get('port','?')}: {vuln['note']} | Banner: {combined[:80]}",
                        severity=Severity.HIGH,
                        entity_id=target_id, entity_name=target_name,
                    ))
                    svc.properties["vulnerability_note"] = vuln["note"]
                    break

        return vulnerable_count

    def _flag_suspicious_neighbors(self, apex_domain: str) -> int:
        """
        Flag IPs where reverse IP lookup reveals suspicious co-hosted domains
        (e.g., government IP hosting non-government domains, or known malicious patterns).
        """
        flagged = 0
        apex_tld = ".".join(apex_domain.split(".")[-2:])

        for ip_name, domain_names in self.graph._ip_index.items():
            if len(domain_names) < 2:
                continue

            target_domains = {d for d in domain_names if apex_tld in d}
            other_domains  = {d for d in domain_names if apex_tld not in d}

            if target_domains and other_domains and len(other_domains) > 5:
                ip_entity = self.graph.get_by_name(ip_name)
                if ip_entity:
                    self.graph.penalize_entity(ip_entity.id, Anomaly(
                        code="IP_MIXED_TENANCY",
                        title="Government IP Shared With Non-Government Domains",
                        detail=f"{ip_name} hosts {len(target_domains)} gov domains alongside "
                               f"{len(other_domains)} non-gov domains: "
                               f"{', '.join(list(other_domains)[:4])}…",
                        severity=Severity.MEDIUM,
                        entity_id=ip_entity.id, entity_name=ip_name,
                    ))
                    flagged += 1

        return flagged
