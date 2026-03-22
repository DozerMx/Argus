"""
API REST Enumeration Module
- OpenAPI/Swagger spec discovery and parsing
- API endpoint extraction from spec
- Authentication scheme detection
- Exposed sensitive API endpoints
- API versioning enumeration
- GraphQL schema extraction
- gRPC reflection enumeration
- Parameter extraction for fuzzer
- Rate limit detection
- API key exposure in responses
"""
from __future__ import annotations
import asyncio
import json
import logging
import re
from typing import Dict, List, Optional, Set
from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.api_enum")

OPENAPI_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html",
    "/api-docs", "/api-docs/", "/api-docs.json", "/api-docs.yaml",
    "/api/swagger.json", "/api/swagger.yaml",
    "/api/docs", "/api/docs/", "/api/documentation",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api/openapi.json", "/api/openapi.yaml",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/spec.json", "/spec.yaml",
    "/rest/swagger.json", "/rest/api-docs",
    "/redoc", "/redoc/",
    "/docs", "/docs/",
    "/.well-known/openapi",
    "/api/schema/", "/api/schema/swagger-ui/",
]

SENSITIVE_ENDPOINT_PATTERNS = [
    (r"/admin",                 "Admin endpoint",           Severity.HIGH),
    (r"/debug",                 "Debug endpoint",           Severity.HIGH),
    (r"/internal",              "Internal API endpoint",    Severity.HIGH),
    (r"/private",               "Private endpoint",         Severity.HIGH),
    (r"/secret",                "Secret endpoint",          Severity.HIGH),
    (r"/config",                "Config endpoint",          Severity.HIGH),
    (r"/backup",                "Backup endpoint",          Severity.HIGH),
    (r"/export",                "Data export endpoint",     Severity.MEDIUM),
    (r"/dump",                  "Data dump endpoint",       Severity.HIGH),
    (r"/users?\b",              "User management endpoint", Severity.MEDIUM),
    (r"/accounts?\b",           "Account endpoint",         Severity.MEDIUM),
    (r"/passwords?",            "Password endpoint",        Severity.HIGH),
    (r"/tokens?\b",             "Token endpoint",           Severity.HIGH),
    (r"/keys?\b",               "Key management endpoint",  Severity.HIGH),
    (r"/credentials?",          "Credentials endpoint",     Severity.CRITICAL),
    (r"/payment",               "Payment endpoint",         Severity.HIGH),
    (r"/webhook",               "Webhook endpoint",         Severity.MEDIUM),
    (r"/graphql",               "GraphQL endpoint",         Severity.MEDIUM),
    (r"/actuator",              "Spring Actuator",          Severity.HIGH),
    (r"/metrics",               "Metrics endpoint",         Severity.MEDIUM),
    (r"/health",                "Health endpoint",          Severity.LOW),
    (r"/version",               "Version disclosure",       Severity.LOW),
    (r"/env",                   "Environment endpoint",     Severity.CRITICAL),
    (r"/api/v[0-9]+/admin",     "Admin API endpoint",       Severity.CRITICAL),
    (r"/api/v[0-9]+/users?",    "User API endpoint",        Severity.MEDIUM),
]

AUTH_SCHEMES = {
    "bearer":     "Bearer token (JWT)",
    "basic":      "HTTP Basic Auth",
    "apikey":     "API Key",
    "oauth2":     "OAuth 2.0",
    "openidconnect": "OpenID Connect",
}

VERSIONED_API_PATTERNS = [
    "/api/v{n}", "/api/{n}", "/v{n}/api",
    "/v{n}", "/{n}.0", "/api/r{n}",
]

class APIEnumerator:
    def __init__(self, http_client, graph: KnowledgeGraph,
                 concurrency: int = 8):
        self.http  = http_client
        self.graph = graph
        self._sem  = asyncio.Semaphore(concurrency)
        self._seen: Set[str] = set()

    async def run(self) -> Dict:
        domains = self.graph.get_by_type(EntityType.DOMAIN)
        alive   = [d for d in domains
                   if d.properties.get("is_alive")
                   and not d.properties.get("is_neighbor")]
        results = {
            "specs_found":          0,
            "endpoints_discovered": 0,
            "sensitive_endpoints":  0,
            "auth_schemes":         0,
            "versions_found":       0,
            "api_keys_exposed":     0,
        }
        lock = asyncio.Lock()

        async def enum(entity):
            async with self._sem:
                r = await self._enumerate_domain(entity)
                async with lock:
                    for k, v in r.items():
                        results[k] = results.get(k, 0) + v

        await asyncio.gather(*[enum(d) for d in alive], return_exceptions=True)
        return results

    async def _enumerate_domain(self, entity) -> Dict:
        scheme = "https" if entity.properties.get("tls") else "http"
        name   = entity.name
        base   = f"{scheme}://{name}"
        counts = {k: 0 for k in ["specs_found", "endpoints_discovered",
                                   "sensitive_endpoints", "auth_schemes",
                                   "versions_found", "api_keys_exposed"]}

        spec = await self._find_spec(base, entity, counts)

        if spec:
            await self._parse_spec(spec, base, entity, counts)

        await self._enumerate_versions(base, entity, counts)

        await self._check_api_key_exposure(base, entity, counts)

        return counts

    async def _find_spec(self, base: str, entity, counts: Dict) -> Optional[Dict]:
        for path in OPENAPI_PATHS:
            key = f"spec:{base}{path}"
            if key in self._seen:
                continue
            self._seen.add(key)

            resp = await self._get(f"{base}{path}")
            if not resp or resp.get("status") != 200:
                continue

            body = resp.get("data", "") or ""
            ct   = (resp.get("headers", {}) or {}).get(
                "content-type", "").lower()

            if not body:
                continue

            try:
                if isinstance(body, str) and (
                    body.strip().startswith("{") or "swagger" in body.lower()
                    or "openapi" in body.lower()
                ):
                    spec = json.loads(body) if isinstance(body, str) else body
                    if isinstance(spec, dict) and (
                        "swagger" in spec or "openapi" in spec
                        or "paths" in spec
                    ):
                        counts["specs_found"] += 1
                        entity.properties["openapi_spec_url"] = f"{base}{path}"
                        entity.properties["openapi_spec"]     = spec

                        version = spec.get("info", {}).get("version", "unknown")
                        title   = spec.get("info", {}).get("title", "API")
                        self._penalize(entity, "OPENAPI_SPEC_EXPOSED",
                            f"OpenAPI/Swagger spec exposed at {base}{path} — "
                            f"{title} v{version}",
                            Severity.MEDIUM)
                        logger.warning(f"API: Spec found at {base}{path} — {title} v{version}")
                        return spec

            except Exception:
                if "swagger" in body.lower() or "openapi" in body.lower():
                    counts["specs_found"] += 1
                    entity.properties["openapi_spec_url"] = f"{base}{path}"
                    self._penalize(entity, "OPENAPI_SPEC_EXPOSED",
                        f"API spec exposed at {base}{path}",
                        Severity.MEDIUM)
                    return {}

        return None

    async def _parse_spec(self, spec: Dict, base: str,
                           entity, counts: Dict) -> None:
        if not isinstance(spec, dict):
            return

        paths     = spec.get("paths", {})
        servers   = spec.get("servers", [])
        security  = spec.get("securityDefinitions",
                    spec.get("components", {}).get("securitySchemes", {}))
        info      = spec.get("info", {})

        all_endpoints = list(paths.keys())
        counts["endpoints_discovered"] += len(all_endpoints)
        entity.properties["api_endpoints"] = all_endpoints[:100]

        for scheme_name, scheme_data in security.items():
            scheme_type = str(scheme_data.get("type", "")).lower()
            label = AUTH_SCHEMES.get(scheme_type, scheme_type)
            counts["auth_schemes"] += 1
            entity.properties[f"api_auth_{scheme_name}"] = label

        sensitive_found = []
        for endpoint in all_endpoints:
            for pattern, label, severity in SENSITIVE_ENDPOINT_PATTERNS:
                if re.search(pattern, endpoint, re.I):
                    sensitive_found.append((endpoint, label, severity))
                    counts["sensitive_endpoints"] += 1
                    break

        if sensitive_found:
            crit = [e for e, l, s in sensitive_found if s == Severity.CRITICAL]
            high = [e for e, l, s in sensitive_found if s == Severity.HIGH]

            if crit:
                self._penalize(entity, "API_SENSITIVE_ENDPOINT",
                    f"Critical API endpoints in spec: {', '.join(crit[:5])}",
                    Severity.CRITICAL)

            if high:
                self._penalize(entity, "API_SENSITIVE_ENDPOINT",
                    f"Sensitive API endpoints: {', '.join(high[:5])}",
                    Severity.HIGH)

        api_version = info.get("version", "")
        if api_version and any(v in api_version for v in ["0.", "1.", "beta", "alpha"]):
            self._penalize(entity, "API_VERSION_DISCLOSURE",
                f"API version {api_version} disclosed in spec — "
                f"may indicate legacy/deprecated endpoints",
                Severity.LOW)

        for server in servers:
            url = server.get("url", "")
            if any(k in url for k in ["internal", "dev", "staging",
                                       "localhost", "127.0.0.1", "10.",
                                       "192.168.", "172.16."]):
                self._penalize(entity, "API_INTERNAL_SERVER_DISCLOSED",
                    f"Internal server URL in API spec: {url}",
                    Severity.HIGH)

    async def _enumerate_versions(self, base: str,
                                   entity, counts: Dict) -> None:
        found_versions = []
        for v in range(1, 6):
            for pattern in [f"/api/v{v}", f"/v{v}", f"/api/v{v}.0"]:
                key = f"ver:{base}{pattern}"
                if key in self._seen:
                    continue
                self._seen.add(key)

                resp = await self._get(f"{base}{pattern}")
                if resp and resp.get("status") in (200, 401, 403):
                    found_versions.append(f"v{v}")
                    counts["versions_found"] += 1

        if len(found_versions) > 1:
            self._penalize(entity, "API_MULTIPLE_VERSIONS",
                f"Multiple API versions accessible: {', '.join(found_versions)} — "
                f"older versions may lack security controls",
                Severity.MEDIUM)

    async def _check_api_key_exposure(self, base: str,
                                       entity, counts: Dict) -> None:
        api_key_re = re.compile(
            r'(?i)(?:api[_-]?key|apikey|x-api-key|authorization)'
            r'["\s:=]+["\']?([A-Za-z0-9\-_]{20,})["\']?'
        )

        for path in ["/", "/api", "/api/v1", "/health"]:
            resp = await self._get(f"{base}{path}")
            if not resp:
                continue
            body = resp.get("data", "") or ""
            hdrs = resp.get("headers", {}) or {}

            for src in [body, str(hdrs)]:
                for m in api_key_re.finditer(src):
                    key_val = m.group(1)
                    if len(key_val) >= 20 and key_val not in ("undefined", "null"):
                        counts["api_keys_exposed"] += 1
                        self._penalize(entity, "API_KEY_EXPOSED",
                            f"API key found in response from {base}{path}: "
                            f"{key_val[:8]}...{key_val[-4:]}",
                            Severity.CRITICAL)
                        logger.warning(f"API KEY: exposed at {base}{path}")
                        return

    def _penalize(self, entity, code: str, detail: str,
                  severity: Severity) -> None:
        self.graph.penalize_entity(entity.id, Anomaly(
            code=code,
            title=code.replace("_", " ").title(),
            detail=detail,
            severity=severity,
            entity_id=entity.id, entity_name=entity.name,
        ))

    async def _get(self, url: str):
        try:
            import random
            from argus.intelligence.wordlists import USER_AGENTS
            return await self.http.get(
                url,
                headers={"User-Agent": random.choice(USER_AGENTS),
                         "Accept": "application/json, text/yaml, */*"},
                timeout_override=8,
            )
        except Exception:
            return None
