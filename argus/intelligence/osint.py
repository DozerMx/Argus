"""
Multi-module intelligence:

1. WaybackMachine — historical endpoint discovery via Wayback CDX API
2. CloudAssets — S3/Azure/GCP bucket detection and cloud provider identification
3. ActiveMisconfigDetector — CORS, Open Redirect, Clickjacking without exploitation
"""
from __future__ import annotations
import asyncio
import ipaddress
import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.osint")

CLOUD_CIDR_PREFIXES: Dict[str, List[str]] = {
    "AWS": ["3.0.0.0/8", "13.32.0.0/15", "52.0.0.0/8", "54.0.0.0/8",
            "18.0.0.0/8", "35.0.0.0/8", "34.0.0.0/8"],
    "GCP": ["35.186.0.0/16", "34.64.0.0/10", "35.190.0.0/15",
            "142.250.0.0/15", "172.217.0.0/16"],
    "Azure": ["20.0.0.0/8", "40.0.0.0/8", "51.0.0.0/8", "52.224.0.0/11",
              "13.64.0.0/11", "23.96.0.0/13"],
    "DigitalOcean": ["159.65.0.0/16", "167.99.0.0/16", "178.62.0.0/15",
                     "188.166.0.0/15", "206.81.0.0/20"],
    "Vultr": ["64.237.48.0/20", "104.156.224.0/19", "108.61.0.0/16"],
    "Linode": ["45.33.0.0/17", "45.56.0.0/18", "45.79.0.0/16"],
    "Hetzner": ["5.9.0.0/16", "23.88.0.0/21", "88.198.0.0/16"],
    "OVH": ["51.68.0.0/16", "51.75.0.0/16", "137.74.0.0/16"],
}

BUCKET_PATTERNS: List[Tuple[str, str, str]] = [
    (r"s3\.amazonaws\.com",            "AWS S3 Bucket",     "AWS"),
    (r"s3-[a-z0-9-]+\.amazonaws\.com", "AWS S3 Bucket",     "AWS"),
    (r"storage\.googleapis\.com",       "GCP Storage",       "GCP"),
    (r"storage\.cloud\.google\.com",    "GCP Storage",       "GCP"),
    (r"blob\.core\.windows\.net",       "Azure Blob Storage","Azure"),
    (r"azurewebsites\.net",             "Azure App Service", "Azure"),
    (r"cloudapp\.azure\.com",           "Azure Cloud App",   "Azure"),
    (r"s3-website",                     "AWS S3 Static Site","AWS"),
    (r"digitaloceanspaces\.com",        "DigitalOcean Spaces","DO"),
    (r"r2\.cloudflarestorage\.com",     "Cloudflare R2",     "Cloudflare"),
    (r"backblazeb2\.com",               "Backblaze B2",      "Backblaze"),
]

CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]

class WaybackMachine:
    """Query Wayback CDX API for historical endpoints."""
    CDX_API = "https://web.archive.org/cdx/search/cdx"

    def __init__(self, http_client, graph: KnowledgeGraph):
        self.http  = http_client
        self.graph = graph

    async def discover(self, domain: str) -> Dict[str, int]:
        """Discover historical URLs for domain. Returns summary."""
        domain_entity = self.graph.get_by_name(domain)
        results: Set[str] = set()
        interesting: List[str] = []

        try:

            resp = await self.http.get(
                self.CDX_API,
                params={
                    "url":        f"*.{domain}",
                    "output":     "json",
                    "fl":         "original,statuscode,timestamp",
                    "collapse":   "urlkey",
                    "limit":      "500",
                    "filter":     "statuscode:200",
                },
            )

            if not resp or resp.get("status") != 200:
                return {"urls_found": 0}

            data = resp.get("data") or []
            if not isinstance(data, list) or len(data) < 2:
                return {"urls_found": 0}

            for row in data[1:]:
                if not isinstance(row, list) or len(row) < 3:
                    continue
                url, status, ts = row[0], row[1], row[2]
                results.add(url)

                interesting_patterns = [
                    r"/admin", r"/backup", r"\.env", r"\.git",
                    r"/api/", r"/swagger", r"/config", r"/token",
                    r"/password", r"/credentials", r"\.sql", r"\.zip",
                    r"/phpmyadmin", r"/actuator", r"/debug",
                ]
                for pat in interesting_patterns:
                    if re.search(pat, url, re.IGNORECASE):
                        interesting.append(url)
                        break

            if interesting and domain_entity:
                domain_entity.properties["wayback_interesting"] = interesting[:20]
                self.graph.penalize_entity(domain_entity.id, Anomaly(
                    code="WAYBACK_SENSITIVE_PATHS",
                    title=f"Historical Sensitive Paths in Wayback Machine ({len(interesting)})",
                    detail=f"Archive.org has {len(interesting)} sensitive historical URLs: "
                           + ", ".join(interesting[:5]),
                    severity=Severity.MEDIUM,
                    entity_id=domain_entity.id,
                    entity_name=domain,
                ))

        except Exception as e:
            logger.debug(f"Wayback error for {domain}: {e}")

        return {"urls_found": len(results), "interesting": len(interesting)}

class CloudAssetDetector:
    """Detect cloud provider assets and storage buckets."""

    def __init__(self, http_client, dns_correlator, graph: KnowledgeGraph):
        self.http  = http_client
        self.dns   = dns_correlator
        self.graph = graph
        self._compiled = self._compile_cloud_ranges()

    def _compile_cloud_ranges(self):
        compiled = []
        for provider, cidrs in CLOUD_CIDR_PREFIXES.items():
            for cidr in cidrs:
                try:
                    compiled.append((ipaddress.ip_network(cidr, strict=False), provider))
                except ValueError:
                    pass
        return compiled

    def identify_cloud_provider(self, ip: str) -> Optional[str]:
        try:
            addr = ipaddress.ip_address(ip)
            for network, provider in self._compiled:
                if addr in network:
                    return provider
        except ValueError:
            pass
        return None

    async def run(self) -> int:
        """Detect cloud assets across all discovered entities."""
        found = 0

        for ip_entity in self.graph.get_by_type(EntityType.IP):
            provider = self.identify_cloud_provider(ip_entity.name)
            if provider and not ip_entity.properties.get("cloud_provider"):
                ip_entity.properties["cloud_provider"] = provider
                found += 1

        for domain_entity in self.graph.get_by_type(EntityType.DOMAIN):
            await self._check_cname_buckets(domain_entity)

        return found

    async def _check_cname_buckets(self, domain_entity) -> None:
        name = domain_entity.name
        try:
            cnames = await self.dns._doh(name, "CNAME")
            for cname in cnames:
                for pattern, label, provider in BUCKET_PATTERNS:
                    if re.search(pattern, cname, re.IGNORECASE):
                        domain_entity.properties["cloud_asset"] = {
                            "type": label, "provider": provider, "cname": cname
                        }
                        self.graph.penalize_entity(domain_entity.id, Anomaly(
                            code="CLOUD_ASSET_DETECTED",
                            title=f"Cloud Asset: {label} ({provider})",
                            detail=f"{name} CNAME → {cname} — {label} on {provider}",
                            severity=Severity.INFO,
                            entity_id=domain_entity.id,
                            entity_name=name,
                        ))
                        break
        except Exception:
            pass

class ActiveMisconfigDetector:
    """Detect CORS misconfigs, open redirects, clickjacking — passively."""

    def __init__(self, http_client, graph: KnowledgeGraph, concurrency: int = 30):
        self.http        = http_client
        self.graph       = graph
        self.concurrency = concurrency

    async def run(self) -> Dict[str, int]:
        alive = [
            d for d in self.graph.get_by_type(EntityType.DOMAIN)
            if d.properties.get("is_alive")
        ]
        sem = asyncio.Semaphore(self.concurrency)
        cors_found = 0
        redirect_found = 0
        clickjack_found = 0
        lock = asyncio.Lock()

        async def check_one(d):
            nonlocal cors_found, redirect_found, clickjack_found
            async with sem:
                c, r, k = await self._check_domain(d)
                async with lock:
                    cors_found     += c
                    redirect_found += r
                    clickjack_found+= k

        await asyncio.gather(*[check_one(d) for d in alive], return_exceptions=True)
        return {"cors": cors_found, "open_redirect": redirect_found, "clickjacking": clickjack_found}

    async def _check_domain(self, domain_entity) -> Tuple[int, int, int]:
        name   = domain_entity.name
        scheme = domain_entity.properties.get("http_scheme", "https")
        c = r = k = 0

        for origin in CORS_TEST_ORIGINS:
            try:
                resp = await self.http.get(
                    f"{scheme}://{name}/",
                    headers={"Origin": origin},
                )
                if not resp:
                    continue
                headers = {k2.lower(): v for k2, v in (resp.get("headers") or {}).items()}
                acao = headers.get("access-control-allow-origin", "")
                acac = headers.get("access-control-allow-credentials", "")

                if acao == "*":
                    c += 1
                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                        code="CORS_WILDCARD",
                        title="CORS Wildcard — Any Origin Allowed",
                        detail=f"{name} responds with Access-Control-Allow-Origin: * — "
                               f"any website can make cross-origin requests",
                        severity=Severity.MEDIUM,
                        entity_id=domain_entity.id, entity_name=name,
                    ))
                    break
                elif acao == origin and "true" in acac.lower() and origin != "null":
                    c += 1
                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                        code="CORS_REFLECTED_ORIGIN_WITH_CREDENTIALS",
                        title="CORS: Reflected Origin + Allow-Credentials",
                        detail=f"{name} reflects arbitrary Origin ({origin}) with "
                               f"Allow-Credentials: true — allows cross-origin authenticated requests",
                        severity=Severity.HIGH,
                        entity_id=domain_entity.id, entity_name=name,
                    ))
                    break
            except Exception:
                pass

        redirect_params = ["url", "redirect", "next", "return", "returnUrl",
                           "redirect_uri", "continue", "goto", "target", "to"]
        for param in redirect_params[:5]:
            try:
                resp = await self.http.get(
                    f"{scheme}://{name}/?{param}=https://evil.com",
                )
                if not resp:
                    continue
                status  = resp.get("status", 0)
                headers = {k2.lower(): v for k2, v in (resp.get("headers") or {}).items()}
                location = headers.get("location", "")
                if status in (301, 302, 303, 307, 308) and "evil.com" in location:
                    r += 1
                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                        code="OPEN_REDIRECT",
                        title=f"Open Redirect via ?{param}=",
                        detail=f"{name}/?{param}=https://evil.com → HTTP {status} → {location} — "
                               f"allows phishing redirects from trusted domain",
                        severity=Severity.HIGH,
                        entity_id=domain_entity.id, entity_name=name,
                    ))
                    break
            except Exception:
                pass

        try:
            resp = await self.http.get(f"{scheme}://{name}/")
            if resp and resp.get("status") == 200:
                headers = {k2.lower(): v for k2, v in (resp.get("headers") or {}).items()}
                body = str(resp.get("data", ""))
                has_login_form = bool(re.search(
                    r'(?i)<input[^>]+type=["\']password["\']|<form[^>]+login',
                    body
                ))
                has_xfo = "x-frame-options" in headers
                has_csp_frame = "frame-ancestors" in headers.get("content-security-policy", "")

                if has_login_form and not has_xfo and not has_csp_frame:
                    k += 1
                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                        code="CLICKJACKING_LOGIN_FORM",
                        title="Clickjacking: Login Form Without Frame Protection",
                        detail=f"{name} has a login form without X-Frame-Options or "
                               f"CSP frame-ancestors — vulnerable to UI redress/clickjacking attacks",
                        severity=Severity.MEDIUM,
                        entity_id=domain_entity.id, entity_name=name,
                    ))
        except Exception:
            pass

        return c, r, k
