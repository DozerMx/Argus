"""
HTTP Intelligence Module
Performs GET/HEAD requests against all alive domains and extracts:
  - Security headers score (CSP, HSTS, X-Frame-Options, etc.)
  - WAF/CDN detection via response signatures
  - Technology stack (Server, X-Powered-By, framework cookies, etc.)
  - Cookie security flags (HttpOnly, Secure, SameSite)
  - Redirect chains
  - HTTP → HTTPS enforcement
  - Interesting response patterns
"""
from __future__ import annotations
import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone

from argus.ontology.entities import (
    Anomaly, EntityType, RelationType, Severity,
)
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.http_intel")

SECURITY_HEADERS: Dict[str, Tuple[str, Severity]] = {
    "strict-transport-security":       ("HSTS",           Severity.HIGH),
    "content-security-policy":         ("CSP",            Severity.HIGH),
    "x-frame-options":                 ("X-Frame-Options",Severity.MEDIUM),
    "x-content-type-options":          ("X-Content-Type", Severity.MEDIUM),
    "referrer-policy":                 ("Referrer-Policy",Severity.LOW),
    "permissions-policy":              ("Permissions-Policy", Severity.LOW),
    "x-xss-protection":                ("X-XSS-Protection",  Severity.LOW),
    "cross-origin-embedder-policy":    ("COEP",           Severity.LOW),
    "cross-origin-opener-policy":      ("COOP",           Severity.LOW),
    "cross-origin-resource-policy":    ("CORP",           Severity.LOW),
}

WAF_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare":      ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
    "AWS WAF":         ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw-id"],
    "Akamai":          ["x-akamai-transformed", "akamai-grn", "x-check-cacheable"],
    "Imperva":         ["x-iinfo", "x-cdn", "incap-ses", "visid-incap"],
    "F5 BIG-IP":       ["x-wa-info", "bigipserver", "f5-"],
    "Fortinet":        ["fortigate", "fortiweb"],
    "Sucuri":          ["x-sucuri-id", "x-sucuri-cache"],
    "Barracuda":       ["barra_counter_session", "barracuda_"],
    "ModSecurity":     ["mod_security", "modsecurity"],
    "Nginx WAF":       ["x-protected-by"],
}

TECH_FINGERPRINTS: Dict[str, List[str]] = {
    "WordPress":     ["wp-content", "wp-includes", "wp-json", "wordpress"],
    "Drupal":        ["drupal", "sites/default", "x-drupal-cache", "x-generator: drupal"],
    "Joomla":        ["joomla", "/components/com_", "x-content-encoded-by: joomla"],
    "SharePoint":    ["sharepoint", "microsoftsharepoint", "x-sharepointhealthscore", "spsdk"],
    "IIS":           ["x-aspnet-version", "x-powered-by: asp.net", "aspsessionid"],
    "PHP":           ["x-powered-by: php", "phpsessid"],
    "Java/Spring":   ["jsessionid", "x-application-context"],
    "Django":        ["csrftoken", "x-frame-options: sameorigin"],
    "Ruby on Rails": ["x-request-id", "_rails_session"],
    "Apache":        ["apache", "x-powered-by: phusion passenger"],
    "Oracle":        ["oracle", "adf.ctrl-state", "oracle.adf"],
    "SAP":           ["sap-", "x-sap-", "sap_sessionid"],
}

TAKEOVER_FINGERPRINTS: Dict[str, Tuple[str, str]] = {
    "GitHub Pages":      ("github.io",       "There isn't a GitHub Pages site here"),
    "Amazon S3":         ("s3.amazonaws.com","NoSuchBucket"),
    "Amazon CloudFront": ("cloudfront.net",  "The request could not be satisfied"),
    "Heroku":            ("herokuapp.com",   "No such app"),
    "Fastly":            ("fastly.net",      "Fastly error: unknown domain"),
    "Ghost":             ("ghost.io",        "The thing you were looking for is no longer here"),
    "Shopify":           ("myshopify.com",   "Sorry, this shop is currently unavailable"),
    "Tumblr":            ("tumblr.com",      "There's nothing here"),
    "Zendesk":           ("zendesk.com",     "Help Center Closed"),
    "Freshdesk":         ("freshdesk.com",   "May be this is still fresh"),
    "Surge.sh":          ("surge.sh",        "project not found"),
    "GitLab Pages":      ("gitlab.io",       "404"),
    "Azure":             ("azurewebsites.net","404 Web Site not found"),
    "Unbounce":          ("unbouncepages.com","The requested URL was not found"),
    "HubSpot":           ("hubspot.com",     "Domain not found"),
    "Pantheon":          ("pantheonsite.io", "The gods are wise"),
    "Bitbucket":         ("bitbucket.io",    "Repository not found"),
    "Netlify":           ("netlify.app",     "Not Found"),
    "Vercel":            ("vercel.app",      "The deployment could not be found"),
}

class HTTPIntelligence:
    def __init__(self, http_client, dns_correlator, graph: KnowledgeGraph,
                 timeout: int = 6, concurrency: int = 40):
        self.http = http_client
        self.dns  = dns_correlator
        self.graph = graph
        self.timeout = timeout
        self.concurrency = concurrency

    async def run(self, domain: str) -> Dict[str, int]:
        """
        Probe all alive domains. Returns summary counts.
        """
        alive_domains = [
            d for d in self.graph.get_by_type(EntityType.DOMAIN)
            if d.properties.get("is_alive")
        ]

        sem = asyncio.Semaphore(self.concurrency)
        results = {"probed": 0, "missing_headers": 0, "waf_detected": 0,
                   "takeover_candidates": 0, "insecure_cookies": 0}
        lock = asyncio.Lock()

        async def probe_one(domain_entity):
            async with sem:

                r = await self._probe(domain_entity)
                if r:
                    async with lock:
                        results["probed"] += 1
                        if r.get("missing_security_headers"):
                            results["missing_headers"] += len(r["missing_security_headers"])
                        if r.get("waf"):
                            results["waf_detected"] += 1
                        if r.get("takeover_candidate"):
                            results["takeover_candidates"] += 1
                        if r.get("insecure_cookies"):
                            results["insecure_cookies"] += len(r["insecure_cookies"])

        await asyncio.gather(*[probe_one(d) for d in alive_domains], return_exceptions=True)

        await self._check_takeovers(domain)

        return results

    async def _probe(self, domain_entity) -> Optional[Dict]:
        name = domain_entity.name
        result: Dict = {}

        for scheme in ("https", "http"):
            try:
                resp = await self.http.get(
                    f"{scheme}://{name}/",
                    headers={"User-Agent": "Mozilla/5.0 (compatible; Argus/3.0)"},
                )
                if not resp or not resp.get("status"):
                    continue

                status  = resp["status"]

                final_url = resp.get("url", "")
                if final_url and name not in final_url and any(
                    sso in final_url for sso in [
                        "microsoftonline.com", "accounts.google.com",
                        "okta.com", "auth0.com", "login.live.com",
                    ]
                ):
                    break
                headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
                body    = ""
                if isinstance(resp.get("data"), str):
                    body = resp["data"][:4096]

                result["scheme"]      = scheme
                result["status"]      = status
                result["is_https"]    = scheme == "https"
                result["headers"]     = headers
                result["body_sample"] = body[:500]

                domain_entity.properties["http_status"]  = status
                domain_entity.properties["http_scheme"]  = scheme
                domain_entity.properties["final_url"]    = f"{scheme}://{name}/"

                if scheme == "http" and status not in (301, 302, 307, 308):
                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                        code="HTTP_NO_HTTPS_REDIRECT",
                        title="HTTP Served Without HTTPS Redirect",
                        detail=f"{name} serves content over HTTP without redirecting to HTTPS",
                        severity=Severity.HIGH,
                        entity_id=domain_entity.id, entity_name=name,
                    ))

                missing = self._check_security_headers(headers, domain_entity)
                result["missing_security_headers"] = missing

                waf = self._detect_waf(headers, body)
                if waf:
                    result["waf"] = waf
                    domain_entity.properties["waf"] = waf

                techs = self._fingerprint_tech(headers, body)
                if techs:
                    result["technologies"] = techs
                    domain_entity.properties["technologies"] = techs
                    for tech in techs:
                        tech_entity = self.graph.find_or_create(
                            EntityType.TECHNOLOGY, name=tech, source="http_intel"
                        )
                        self.graph.link(
                            domain_entity.id, tech_entity.id,
                            RelationType.USES_TECHNOLOGY, source="http_intel"
                        )

                insecure = self._check_cookies(headers, domain_entity)
                result["insecure_cookies"] = insecure

                powered_by = headers.get("x-powered-by", headers.get("X-Powered-By", ""))
                if powered_by:
                    domain_entity.properties["x_powered_by"] = powered_by
                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                        code="X_POWERED_BY_DISCLOSED",
                        title="Technology Version Disclosed via X-Powered-By",
                        detail=f"X-Powered-By: {powered_by[:80]} — reveals backend tech version",
                        severity=Severity.LOW,
                        entity_id=domain_entity.id, entity_name=name,
                    ))

                server = headers.get("server", "")
                if server:
                    domain_entity.properties["server_header"] = server
                    version_pattern = re.compile(
                        r"(apache|nginx|iis|lighttpd|openresty)[/\s]([\d.]+)",
                        re.IGNORECASE,
                    )
                    m = version_pattern.search(server)
                    if m:
                        domain_entity.properties["server_version"] = f"{m.group(1)}/{m.group(2)}"
                        self.graph.penalize_entity(domain_entity.id, Anomaly(
                            code="HTTP_SERVER_VERSION_LEAKED",
                            title="Server Version Disclosed in Header",
                            detail=f"Server header reveals: {server[:80]}",
                            severity=Severity.LOW,
                            entity_id=domain_entity.id, entity_name=name,
                        ))

                break

            except Exception as e:
                logger.debug(f"HTTP probe error {name}: {e}")
                continue

        return result if result else None

    def _check_security_headers(self, headers: Dict[str, str], domain_entity) -> List[str]:
        missing = []
        for header, (label, severity) in SECURITY_HEADERS.items():
            if header not in headers:
                missing.append(label)
                self.graph.penalize_entity(domain_entity.id, Anomaly(
                    code=f"MISSING_{label.upper().replace('-','_').replace(' ','_')}",
                    title=f"Missing Security Header: {label}",
                    detail=f"Response does not include '{header}' header",
                    severity=severity,
                    entity_id=domain_entity.id, entity_name=domain_entity.name,
                ))

        hsts = headers.get("strict-transport-security", "")
        if hsts:
            max_age_match = re.search(r"max-age=(\d+)", hsts)
            if max_age_match and int(max_age_match.group(1)) < 31536000:
                self.graph.penalize_entity(domain_entity.id, Anomaly(
                    code="HSTS_MAX_AGE_TOO_SHORT",
                    title="HSTS max-age Below Recommended Value",
                    detail=f"max-age={max_age_match.group(1)} — recommended ≥ 31536000 (1 year)",
                    severity=Severity.MEDIUM,
                    entity_id=domain_entity.id, entity_name=domain_entity.name,
                ))

        return missing

    def _detect_waf(self, headers: Dict[str, str], body: str) -> Optional[str]:
        all_headers_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        body_lower = body.lower()
        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig in all_headers_str or sig in body_lower:
                    return waf_name
        return None

    def _fingerprint_tech(self, headers: Dict[str, str], body: str) -> List[str]:
        found = []
        all_str = (
            " ".join(f"{k}: {v}" for k, v in headers.items()) + " " + body
        ).lower()
        for tech, patterns in TECH_FINGERPRINTS.items():
            if any(p.lower() in all_str for p in patterns):
                found.append(tech)
        return found

    def _check_cookies(self, headers: Dict[str, str], domain_entity) -> List[str]:
        insecure = []
        set_cookie = headers.get("set-cookie", "")
        if not set_cookie:
            return insecure

        cookies = set_cookie.split(",")
        for cookie in cookies:
            cookie_lower = cookie.lower()
            name_match = re.match(r"\s*([^=]+)=", cookie)
            cookie_name = name_match.group(1).strip() if name_match else "unknown"

            issues = []
            if "httponly" not in cookie_lower:
                issues.append("missing HttpOnly")
            if "secure" not in cookie_lower:
                issues.append("missing Secure")
            if "samesite" not in cookie_lower:
                issues.append("missing SameSite")

            if issues:
                insecure.append(cookie_name)
                self.graph.penalize_entity(domain_entity.id, Anomaly(
                    code="INSECURE_COOKIE",
                    title=f"Insecure Cookie: {cookie_name}",
                    detail=f"Cookie '{cookie_name}' flags: {', '.join(issues)}",
                    severity=Severity.MEDIUM,
                    entity_id=domain_entity.id, entity_name=domain_entity.name,
                ))
        return insecure

    async def _check_takeovers(self, apex_domain: str) -> None:
        """
        Check all domains for subdomain takeover.
        Detects dangling CNAME pointing to unclaimed external services.
        """
        all_domains = self.graph.get_by_type(EntityType.DOMAIN)
        sem = asyncio.Semaphore(20)

        async def check_one(domain_entity):
            async with sem:
                name = domain_entity.name
                try:

                    cname_records = await self.dns._doh(name, "CNAME")
                    if not cname_records:
                        return

                    for cname in cname_records:
                        cname_lower = cname.lower()
                        for service, (pattern, verify_str) in TAKEOVER_FINGERPRINTS.items():
                            if pattern in cname_lower:

                                try:
                                    resp = await self.http.get(f"https://{name}/")
                                    body = str(resp.get("data", "")) if resp else ""
                                    if verify_str.lower() in body.lower():
                                        self.graph.penalize_entity(domain_entity.id, Anomaly(
                                            code="SUBDOMAIN_TAKEOVER",
                                            title=f"Subdomain Takeover — {service}",
                                            detail=f"{name} CNAME → {cname} ({service}) but service is unclaimed. "
                                                   f"Verified: '{verify_str}' found in response.",
                                            severity=Severity.CRITICAL,
                                            entity_id=domain_entity.id, entity_name=name,
                                        ))
                                        domain_entity.properties["takeover_service"] = service
                                        domain_entity.properties["takeover_cname"] = cname
                                        logger.warning(f"TAKEOVER CANDIDATE: {name} → {service}")
                                except Exception:

                                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                                        code="SUBDOMAIN_TAKEOVER_CANDIDATE",
                                        title=f"Possible Subdomain Takeover — {service}",
                                        detail=f"{name} CNAME → {cname} ({service}) — verify manually",
                                        severity=Severity.HIGH,
                                        entity_id=domain_entity.id, entity_name=name,
                                    ))
                except Exception as e:
                    logger.debug(f"Takeover check error {name}: {e}")

        await asyncio.gather(*[check_one(d) for d in all_domains], return_exceptions=True)
