"""
JavaScript Secret Scanner
Downloads all JS files from alive domains and scans for:
  - API keys (AWS, GCP, Azure, Stripe, Twilio, etc.)
  - Hardcoded passwords and tokens
  - JWT secrets
  - Private keys
  - Internal endpoints and IPs
  - Database connection strings
  - OAuth tokens
  - Base64 encoded credentials

Technique: discover JS files via HTML parsing + common paths,
download, normalize (strip minification), apply regex patterns.
"""
from __future__ import annotations
import asyncio
import base64
import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.js_scanner")

def _shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())

def _is_likely_secret(value: str) -> bool:
    if len(value) < 20:
        return False
    entropy = _shannon_entropy(value)
    if entropy < 3.5:
        return False
    SKIP_VALUES = {"undefined", "null", "true", "false", "localhost",
                   "example.com", "your_key_here", "xxx", "placeholder"}
    if value.lower() in SKIP_VALUES:
        return False
    if len(set(value)) < 8:
        return False
    return True

SECRET_PATTERNS: List[Tuple[str, re.Pattern, Severity]] = [

    ("AWS Access Key",
     re.compile(r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])", re.I),
     Severity.CRITICAL),
    ("AWS Secret Key",
     re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+=]{40}['\"]"),
     Severity.CRITICAL),
    ("GCP API Key",
     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
     Severity.CRITICAL),
    ("GCP Service Account",
     re.compile(r'"type"\s*:\s*"service_account"'),
     Severity.CRITICAL),
    ("Azure Storage Key",
     re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"),
     Severity.CRITICAL),
    ("Azure Client Secret",
     re.compile(r"(?i)client.?secret['\"\s:=]+[A-Za-z0-9_~.\-]{34,40}"),
     Severity.HIGH),

    ("JWT Token",
     re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     Severity.HIGH),
    ("Bearer Token",
     re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
     Severity.HIGH),
    ("OAuth Client Secret",
     re.compile(r"(?i)client.?secret['\"\s:=]+[A-Za-z0-9_\-]{20,60}"),
     Severity.HIGH),

    ("Stripe Live Key",
     re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
     Severity.CRITICAL),
    ("Stripe Publishable Key",
     re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
     Severity.MEDIUM),
    ("PayPal Secret",
     re.compile(r"(?i)paypal.{0,20}secret.{0,20}['\"][A-Za-z0-9]{20,50}['\"]"),
     Severity.CRITICAL),

    ("Twilio Account SID",
     re.compile(r"AC[a-zA-Z0-9]{32}"),
     Severity.HIGH),
    ("Twilio Auth Token",
     re.compile(r"(?i)twilio.{0,20}['\"][a-f0-9]{32}['\"]"),
     Severity.CRITICAL),
    ("SendGrid API Key",
     re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
     Severity.HIGH),
    ("Mailgun API Key",
     re.compile(r"key-[0-9a-zA-Z]{32}"),
     Severity.HIGH),
    ("Firebase API Key",
     re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
     Severity.HIGH),

    ("RSA Private Key",
     re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
     Severity.CRITICAL),
    ("Private Key (generic)",
     re.compile(r"-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----"),
     Severity.CRITICAL),
    ("PGP Private Key",
     re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
     Severity.CRITICAL),

    ("Hardcoded Password",
     re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,50}['\"]"),
     Severity.HIGH),
    ("Database URL with credentials",
     re.compile(r"(?i)(?:mysql|postgres|mongodb|redis|mssql|oracle)://[^:]+:[^@]+@[^\s'\"]+"),
     Severity.CRITICAL),
    ("JDBC Connection String",
     re.compile(r"(?i)jdbc:[a-z]+://[^\s'\"]{10,}"),
     Severity.HIGH),

    ("Internal IP in JS",
     re.compile(r"(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)"),
     Severity.MEDIUM),
    ("Localhost reference",
     re.compile(r"(?i)(?:http://|['\"])localhost(?::\d+)?(?:[/'\"]|$)"),
     Severity.LOW),
    ("Internal endpoint pattern",
     re.compile(r"(?i)['\"](?:http://)?(?:internal|intranet|corp|dev|staging|admin|api\.internal)\.[a-z0-9.-]+['\"]"),
     Severity.MEDIUM),

    ("High-entropy string (possible secret)",
     re.compile(r"(?i)(?:secret|token|key|api_key|apikey|auth)['\"\s:=]+['\"][A-Za-z0-9+/=_\-]{40,}['\"]"),
     Severity.MEDIUM),
]

JS_PATHS = [
    "/main.js", "/app.js", "/bundle.js", "/index.js",
    "/assets/js/app.js", "/assets/js/main.js", "/js/app.js",
    "/static/js/main.js", "/static/js/bundle.js",
    "/dist/app.js", "/dist/bundle.js", "/dist/main.js",
    "/build/static/js/main.chunk.js", "/build/static/js/2.chunk.js",
    "/js/config.js", "/config.js", "/env.js", "/settings.js",
    "/assets/config.js", "/static/config.js",
    "/api/config", "/api/v1/config",
]

MAP_PATHS = [p + ".map" for p in JS_PATHS]

class JSScanner:
    def __init__(self, http_client, graph: KnowledgeGraph,
                 timeout: int = 6, concurrency: int = 15):
        self.http         = http_client
        self.graph        = graph
        self.timeout      = timeout
        self.concurrency  = concurrency
        self._seen_global: set = set()

    async def run(self) -> Dict[str, int]:
        """
        Scan all alive domains for JS secrets.
        Returns summary counts.
        """
        alive_domains = [
            d for d in self.graph.get_by_type(EntityType.DOMAIN)
            if d.properties.get("is_alive")
        ]

        sem = asyncio.Semaphore(self.concurrency)
        total_secrets = 0
        total_js_files = 0
        self._seen_global = set()
        lock = asyncio.Lock()

        async def scan_domain(domain_entity):
            nonlocal total_secrets, total_js_files
            async with sem:

                secrets, js_count = await self._scan_domain(domain_entity)
                async with lock:
                    total_secrets  += secrets
                    total_js_files += js_count

        await asyncio.gather(*[scan_domain(d) for d in alive_domains], return_exceptions=True)
        return {"secrets_found": total_secrets, "js_files_scanned": total_js_files}

    async def _scan_domain(self, domain_entity) -> Tuple[int, int]:
        name = domain_entity.name
        scheme = domain_entity.properties.get("http_scheme", "https")
        js_urls: Set[str] = set()

        try:
            resp = await self.http.get(f"{scheme}://{name}/")
            if resp and resp.get("status") == 200:
                body = resp.get("data") or ""
                if isinstance(body, str):
                    for match in re.finditer(
                        r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
                        body, re.IGNORECASE
                    ):
                        src = match.group(1)
                        if src.startswith("http"):

                            if name in src:
                                js_urls.add(src)
                        elif src.startswith("//"):
                            js_urls.add(f"{scheme}:{src}")
                        else:
                            js_urls.add(f"{scheme}://{name}{src if src.startswith('/') else '/' + src}")
        except Exception as e:
            logger.debug(f"HTML parse error {name}: {e}")

        for path in JS_PATHS:
            js_urls.add(f"{scheme}://{name}{path}")

        js_urls = set(list(js_urls)[:30])

        secrets_found = 0
        js_scanned = 0
        js_sem = asyncio.Semaphore(5)

        async def scan_js(url: str):
            nonlocal secrets_found, js_scanned
            async with js_sem:
                count = await self._scan_js_url(url, domain_entity)
                if count > 0:
                    secrets_found += count
                    js_scanned += 1
                elif count == 0:
                    js_scanned += 1

        await asyncio.gather(*[scan_js(url) for url in js_urls], return_exceptions=True)

        await self._check_source_maps(name, scheme, domain_entity)

        return secrets_found, js_scanned

    async def _scan_js_url(self, url: str, domain_entity) -> int:
        """Download and scan a single JS file. Returns secrets found count."""
        try:
            resp = await self.http.get(url)
            if not resp or resp.get("status") != 200:
                return -1

            content_type = ""
            headers = resp.get("headers") or {}
            content_type = headers.get("content-type", headers.get("Content-Type", ""))
            if content_type:
                if "javascript" not in content_type and "ecmascript" not in content_type:
                    return -1

            body = resp.get("data") or ""
            if not isinstance(body, str) or len(body) < 500:
                return -1

            if body.strip().startswith("<!") or "<html" in body[:300].lower():
                return -1

            secrets_found = 0
            seen_secrets: Set[str] = set()

            for name_str, pattern, severity in SECRET_PATTERNS:
                for match in pattern.finditer(body):
                    secret_val = match.group(0)

                    raw_val = secret_val.split("=")[-1].strip("""'"` """)
                    if len(raw_val) > 15 and not _is_likely_secret(raw_val):
                        continue

                    dedup_key = f"{name_str}:{secret_val[:30]}"
                    if dedup_key in seen_secrets:
                        continue
                    seen_secrets.add(dedup_key)

                    global_key = f"{url}|{name_str}|{secret_val[:30]}"
                    if global_key in self._seen_global:
                        continue
                    self._seen_global.add(global_key)

                    if self._is_false_positive(secret_val, name_str):
                        continue

                    start = max(0, match.start() - 50)
                    end   = min(len(body), match.end() + 50)
                    context = body[start:end].replace("\n", " ").strip()

                    secrets_found += 1
                    logger.warning(f"SECRET: {name_str} in {url}")

                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                        code="JS_SECRET_EXPOSED",
                        title=f"Secret in JavaScript: {name_str}",
                        detail=f"File: {url} | Type: {name_str} | Context: ...{context[:120]}...",
                        severity=severity,
                        entity_id=domain_entity.id,
                        entity_name=domain_entity.name,
                    ))

                    existing = domain_entity.properties.get("js_secrets", [])
                    existing.append({
                        "type": name_str,
                        "url":  url,
                        "severity": severity.value,
                        "preview": secret_val[:40] + "..." if len(secret_val) > 40 else secret_val,
                    })
                    domain_entity.properties["js_secrets"] = existing

            return secrets_found

        except Exception as e:
            logger.debug(f"JS scan error {url}: {e}")
            return -1

    async def _check_source_maps(self, domain: str, scheme: str, domain_entity) -> None:
        """
        Check if .js.map files are publicly accessible.
        Source maps expose original source code — critical finding.
        """
        map_paths = ["/main.js.map", "/app.js.map", "/bundle.js.map",
                     "/static/js/main.chunk.js.map", "/dist/bundle.js.map"]

        map_sem = asyncio.Semaphore(5)

        async def check_map(path: str):
            async with map_sem:
                try:
                    resp = await self.http.get(f"{scheme}://{domain}{path}")
                    if resp and resp.get("status") == 200:
                        body = resp.get("data") or ""

                        if isinstance(body, str) and ('"sources"' in body or '"mappings"' in body):
                            self.graph.penalize_entity(domain_entity.id, Anomaly(
                                code="SOURCE_MAP_EXPOSED",
                                title="JavaScript Source Map Publicly Accessible",
                                detail=f"Source map at {scheme}://{domain}{path} exposes original "
                                       f"source code, comments, variable names, and internal structure",
                                severity=Severity.HIGH,
                                entity_id=domain_entity.id,
                                entity_name=domain_entity.name,
                            ))
                            domain_entity.properties["source_map_url"] = f"{scheme}://{domain}{path}"
                            logger.warning(f"SOURCE MAP EXPOSED: {domain}{path}")
                except Exception:
                    pass

        await asyncio.gather(*[check_map(p) for p in map_paths], return_exceptions=True)

    @staticmethod
    def _is_false_positive(value: str, secret_type: str) -> bool:
        """Filter common false positives."""
        fp_patterns = [
            r"^(example|test|dummy|placeholder|your[-_]|insert[-_]|xxx|yyy|zzz|abc|123)",
            r"^(AKIA|sk_live_)EXAMPLE",
            r"<YOUR",
            r"\$\{",
            r"process\.env",
        ]
        val_lower = value.lower()
        for p in fp_patterns:
            if re.search(p, val_lower, re.IGNORECASE):
                return True

        if secret_type == "High-entropy string (possible secret)" and len(value) < 40:
            return True

        return False
