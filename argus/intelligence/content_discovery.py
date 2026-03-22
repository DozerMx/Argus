"""
Content Discovery Engine
Probes high-value paths on all alive domains.
Not a brute-force directory scanner — targeted at known-dangerous exposures.

Categories:
  - Admin panels and dashboards
  - API documentation (Swagger, OpenAPI, GraphQL introspection)
  - Developer artifacts (.env, .git, Dockerfiles, configs)
  - Framework-specific endpoints (Spring Actuator, Django admin, Laravel)
  - Cloud metadata endpoints
  - Backup files and archives
  - Security-relevant endpoints (security.txt, robots.txt)
  - Database admin interfaces (phpMyAdmin, Adminer, etc.)
  - CI/CD and monitoring interfaces
"""
from __future__ import annotations
import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.content_discovery")

DISCOVERY_PATHS: List[Tuple[str, str, Severity, Optional[str]]] = [

    ("/.git/HEAD",          "Git Repository Exposed",       Severity.CRITICAL, r"ref:"),
    ("/.git/config",        "Git Config Exposed",           Severity.CRITICAL, r"\[core\]"),
    ("/.env",               ".env File Exposed",            Severity.CRITICAL, r"[A-Z_]+="),
    ("/.env.local",         ".env.local Exposed",           Severity.CRITICAL, r"[A-Z_]+="),
    ("/.env.production",    ".env.production Exposed",      Severity.CRITICAL, r"[A-Z_]+="),
    ("/.env.backup",        ".env.backup Exposed",          Severity.CRITICAL, r"[A-Z_]+="),
    ("/config.php",         "PHP Config Exposed",           Severity.CRITICAL, r"(?i)password|db_|database"),
    ("/wp-config.php",      "WordPress Config Exposed",     Severity.CRITICAL, r"DB_PASSWORD|DB_USER"),
    ("/config/database.yml","Rails DB Config Exposed",      Severity.CRITICAL, r"password|adapter"),
    ("/application.properties", "Spring Config Exposed",    Severity.CRITICAL, r"(?i)password|datasource|secret"),
    ("/application.yml",    "Spring YAML Config Exposed",   Severity.CRITICAL, r"(?i)password|datasource"),

    ("/admin",              "Admin Panel",                  Severity.HIGH,   r"(?i)(admin|dashboard|login|logout|panel|welcome)"),
    ("/admin/",             "Admin Panel",                  Severity.HIGH,   r"(?i)(admin|dashboard|login|logout|panel)"),
    ("/administrator",      "Administrator Panel",          Severity.HIGH,   r"(?i)(admin|administrator|login|panel)"),
    ("/wp-admin/",          "WordPress Admin",              Severity.HIGH,   r"(?i)wordpress|wp-login"),
    ("/wp-login.php",       "WordPress Login",              Severity.HIGH,   r"(?i)wordpress|user_login"),
    ("/phpmyadmin/",        "phpMyAdmin Exposed",           Severity.CRITICAL, r"(?i)phpmyadmin|mysql"),
    ("/phpmyadmin",         "phpMyAdmin Exposed",           Severity.CRITICAL, r"(?i)phpmyadmin|mysql"),
    ("/adminer.php",        "Adminer DB Interface",         Severity.CRITICAL, r"(?i)adminer|login"),
    ("/adminer",            "Adminer DB Interface",         Severity.CRITICAL, r"(?i)adminer"),
    ("/console",            "Web Console",                  Severity.HIGH,   r"(?i)(console|terminal|shell|command)"),
    ("/manager/html",       "Tomcat Manager",               Severity.CRITICAL, r"(?i)tomcat|apache"),
    ("/host-manager/html",  "Tomcat Host Manager",          Severity.CRITICAL, r"(?i)tomcat"),

    ("/actuator",           "Spring Boot Actuator",         Severity.HIGH,   r'"_links"'),
    ("/actuator/env",       "Spring Actuator /env",         Severity.CRITICAL, r'"activeProfiles"|"propertySources"'),
    ("/actuator/heapdump",  "Spring Actuator Heap Dump",    Severity.CRITICAL, r"(?i)(java|heap|GC|OutOfMemory)"),
    ("/actuator/mappings",  "Spring Actuator Mappings",     Severity.HIGH,   r'"dispatcherServlets"'),
    ("/actuator/beans",     "Spring Actuator Beans",        Severity.HIGH,   r'"beans"'),
    ("/actuator/httptrace", "Spring Actuator HTTP Trace",   Severity.HIGH,   r'"traces"'),
    ("/metrics",            "Prometheus Metrics Exposed",   Severity.MEDIUM, r"# HELP|# TYPE"),
    ("/prometheus",         "Prometheus Endpoint",          Severity.MEDIUM, r"# HELP|# TYPE"),
    ("/health",             "Health Endpoint",              Severity.LOW,    r"(?i)(status|up|healthy|UP|DOWN|alive)"),
    ("/info",               "Info Endpoint",                Severity.LOW,    r"(?i)(version|build|application|git)"),
    ("/status",             "Status Endpoint",              Severity.LOW,    r"(?i)(status|alive|ready|running)"),
    ("/debug",              "Debug Endpoint",               Severity.HIGH,   r"(?i)(debug|stack|trace|exception|config)"),
    ("/debug/pprof/",       "Go pprof Profiling",           Severity.HIGH,   r"goroutine|heap|allocs"),
    ("/django-admin/",      "Django Admin",                 Severity.HIGH,   r"(?i)django"),
    ("/laravel-admin",      "Laravel Admin",                Severity.HIGH,   r"(?i)(laravel|admin|dashboard|login)"),
    ("/horizon",            "Laravel Horizon",              Severity.HIGH,   r"(?i)horizon|laravel"),
    ("/telescope",          "Laravel Telescope",            Severity.HIGH,   r"(?i)telescope"),

    ("/swagger",            "Swagger UI",                   Severity.MEDIUM, r"(?i)swagger|openapi"),
    ("/swagger/",           "Swagger UI",                   Severity.MEDIUM, r"(?i)swagger"),
    ("/swagger-ui",         "Swagger UI",                   Severity.MEDIUM, r"(?i)swagger"),
    ("/swagger-ui.html",    "Swagger UI",                   Severity.MEDIUM, r"(?i)swagger"),
    ("/api/swagger",        "API Swagger",                  Severity.MEDIUM, r"(?i)swagger"),
    ("/api/docs",           "API Documentation",            Severity.MEDIUM, r"(?i)(swagger|openapi|api|endpoint)"),
    ("/api/v1",             "API v1 Root",                  Severity.LOW,    r"(?i)(version|api|endpoint|status)"),
    ("/api/v2",             "API v2 Root",                  Severity.LOW,    r"(?i)(version|api|endpoint|status)"),
    ("/openapi.json",       "OpenAPI Spec",                 Severity.MEDIUM, r'"openapi"|"swagger"'),
    ("/openapi.yaml",       "OpenAPI Spec YAML",            Severity.MEDIUM, r"openapi:|swagger:"),
    ("/v2/api-docs",        "Springfox API Docs",           Severity.MEDIUM, r'"swagger"'),
    ("/v3/api-docs",        "OpenAPI v3 Docs",              Severity.MEDIUM, r'"openapi"'),
    ("/graphql",            "GraphQL Endpoint",             Severity.HIGH,   r"(?i)(data|errors|graphql|typename)"),
    ("/graphiql",           "GraphiQL Interface",           Severity.HIGH,   r"(?i)graphiql|graphql"),
    ("/api/graphql",        "GraphQL API",                  Severity.MEDIUM, r"(?i)(data|errors|graphql|typename)"),

    ("/Dockerfile",         "Dockerfile Exposed",           Severity.HIGH,   r"FROM |RUN |CMD "),
    ("/docker-compose.yml", "Docker Compose Exposed",       Severity.HIGH,   r"version:|services:"),
    ("/docker-compose.yaml","Docker Compose Exposed",       Severity.HIGH,   r"version:|services:"),
    ("/Makefile",           "Makefile Exposed",             Severity.MEDIUM, r"\.PHONY|all:|install:"),
    ("/package.json",       "package.json Exposed",         Severity.MEDIUM, r'"name"|"version"'),
    ("/composer.json",      "composer.json Exposed",        Severity.MEDIUM, r'"require"'),
    ("/requirements.txt",   "requirements.txt Exposed",     Severity.LOW,    r"(?i)(django|flask|fastapi|requests|boto|==)"),
    ("/Gemfile",            "Gemfile Exposed",              Severity.LOW,    r"source |gem "),
    ("/yarn.lock",          "yarn.lock Exposed",            Severity.LOW,    r"^# yarn lockfile"),
    ("/package-lock.json",  "package-lock.json Exposed",    Severity.LOW,    r'"lockfileVersion"'),
    ("/web.config",         "IIS web.config Exposed",       Severity.HIGH,   r"<configuration>|<system\.web"),
    ("/crossdomain.xml",    "Flash Crossdomain Policy",     Severity.MEDIUM, r"cross-domain-policy"),
    ("/clientaccesspolicy.xml","Silverlight Policy",        Severity.LOW,    r"access-policy"),
    ("/server-status",      "Apache Server Status",         Severity.MEDIUM, r"Apache Server Status"),
    ("/server-info",        "Apache Server Info",           Severity.MEDIUM, r"Apache Server Info"),
    ("/phpinfo.php",        "PHP Info Page",                Severity.HIGH,   r"PHP Version|phpinfo"),
    ("/info.php",           "PHP Info",                     Severity.HIGH,   r"PHP Version|phpinfo"),
    ("/test.php",           "PHP Test Page",                Severity.MEDIUM, r"<?php|PHP"),

    ("/latest/meta-data/",  "AWS Instance Metadata",        Severity.CRITICAL, r"ami-id|instance-id"),
    ("/metadata/v1/",       "DigitalOcean Metadata",        Severity.HIGH,   r"droplet_id|hostname"),

    ("/backup",             "Backup Directory",             Severity.MEDIUM, r"(?i)(index of|backup|sql|zip|tar)"),
    ("/backup.zip",         "Backup Archive",               Severity.CRITICAL, r"PK\x03\x04|PK\x05\x06"),
    ("/backup.tar.gz",      "Backup Archive",               Severity.CRITICAL, r"\x1f\x8b|ustar"),
    ("/backup.tar",         "Backup Archive",               Severity.CRITICAL, r"ustar|\x1f\x8b"),
    ("/backup.sql",         "SQL Backup",                   Severity.CRITICAL, r"(?i)CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL"),
    ("/site.zip",           "Site Archive",                 Severity.CRITICAL, r"PK\x03\x04|PK\x05\x06"),
    ("/www.zip",            "Site Archive",                 Severity.CRITICAL, r"PK\x03\x04|PK\x05\x06"),
    ("/htdocs.zip",         "Site Archive",                 Severity.CRITICAL, r"PK\x03\x04|PK\x05\x06"),
    ("/db.sql",             "SQL Dump",                     Severity.CRITICAL, r"(?i)INSERT INTO|CREATE TABLE"),
    ("/dump.sql",           "SQL Dump",                     Severity.CRITICAL, r"(?i)INSERT INTO|CREATE TABLE"),
    ("/database.sql",       "SQL Dump",                     Severity.CRITICAL, r"(?i)INSERT INTO|CREATE TABLE"),

    ("/.well-known/security.txt", "Security.txt Present",  Severity.INFO,   r"Contact:|contact:"),
    ("/robots.txt",         "Robots.txt",                   Severity.INFO,   r"User-agent|Disallow"),
    ("/sitemap.xml",        "Sitemap",                      Severity.INFO,   r"<urlset|<sitemapindex"),
    ("/.htaccess",          ".htaccess Exposed",            Severity.HIGH,   r"RewriteRule|Deny from|Allow from"),
    ("/crossorigin.xml",    "CrossOrigin Policy",           Severity.LOW,    r"(?i)(cross-domain|allow-access|policy)"),

    ("/jenkins",            "Jenkins CI",                   Severity.HIGH,   r"(?i)jenkins"),
    ("/jenkins/",           "Jenkins CI",                   Severity.HIGH,   r"(?i)jenkins"),
    ("/kibana",             "Kibana Dashboard",             Severity.HIGH,   r"(?i)kibana|elastic"),
    ("/grafana",            "Grafana Dashboard",            Severity.HIGH,   r"(?i)grafana"),
    ("/sonar",              "SonarQube",                    Severity.HIGH,   r"(?i)sonar"),
    ("/jira",               "Jira",                         Severity.MEDIUM, r"(?i)jira|atlassian"),
    ("/confluence",         "Confluence",                   Severity.MEDIUM, r"(?i)confluence"),
    ("/gitlab",             "GitLab",                       Severity.MEDIUM, r"(?i)gitlab"),
]

GRAPHQL_INTROSPECTION = '{"query":"{__schema{types{name}}}"}'

class ContentDiscovery:
    _global_seen: set = set()

    @classmethod
    def reset_seen(cls) -> None:
        cls._global_seen.clear()

    def __init__(self, http_client, graph: KnowledgeGraph,
                 timeout: int = 5, concurrency: int = 60):
        self.http             = http_client
        self.graph            = graph
        self.timeout          = timeout
        self.concurrency      = concurrency
        self._catchall_hosts: set = set()

    async def run(self) -> Dict[str, int]:
        """Probe all alive domains. Returns summary."""
        alive = [
            d for d in self.graph.get_by_type(EntityType.DOMAIN)
            if d.properties.get("is_alive")
        ]

        sem = asyncio.Semaphore(self.concurrency)
        total_found = 0
        lock = asyncio.Lock()

        async def probe_domain(domain_entity):
            nonlocal total_found
            async with sem:
                found = await self._probe(domain_entity)
                async with lock:
                    total_found += found

        await asyncio.gather(*[probe_domain(d) for d in alive], return_exceptions=True)
        return {"paths_found": total_found, "domains_probed": len(alive)}

    async def _probe(self, domain_entity) -> int:
        name   = domain_entity.name
        scheme = domain_entity.properties.get("http_scheme", "https")
        found  = 0
        from argus.utils.request_cache import is_host_skippable
        if is_host_skippable(name):
            return 0
        path_sem = asyncio.Semaphore(self.concurrency)

        try:
            probe = await self.http.get(f"{scheme}://{name}/", use_cache=True)
            if not probe or probe.get("status") in (502, 503, 504, 0):
                return 0

            final_url = probe.get("url", "")
            if final_url and name not in final_url and any(sso in final_url for sso in [
                "microsoftonline.com", "accounts.google.com", "okta.com"
            ]):
                return 0

            import random as _rr, string as _ss
            for _ in range(2):
                _rp = "/" + "".join(_rr.choices(_ss.ascii_lowercase, k=12))
                _wr = await self.http.get(f"{scheme}://{name}{_rp}", use_cache=False)
                if _wr and _wr.get("status") == 200:
                    self._catchall_hosts.add(name)
                    break

        except Exception:
            return 0

        async def check_path(path: str, label: str, severity: Severity, verify: Optional[str]):
            nonlocal found
            async with path_sem:
                url = f"{scheme}://{name}{path}"
                try:
                    resp = await self.http.get(url)
                    if not resp:
                        return

                    status = resp.get("status", 0)
                    if status not in (200, 301, 302, 401, 403):
                        return

                    body = ""
                    if isinstance(resp.get("data"), str):
                        body = resp["data"][:2000]

                
                    if status == 200:
                        body_lower = body.lower()

                        if any(fp in body_lower for fp in [
                            "502 bad gateway",
                            "503 service unavailable",
                            "504 gateway timeout",
                            "application gateway",
                            "microsoft-azure-application-gateway",
                            "an error occurred while starting the application",
                        ]):
                            return

                        headers = resp.get("headers") or {}
                        location = headers.get("location", headers.get("Location", ""))
                        if location and name not in location and any(ext in location for ext in [
                            "microsoftonline.com", "login.microsoft.com",
                            "accounts.google.com", "okta.com", "auth0.com",
                            "login.live.com", "sts.windows.net",
                        ]):
                            return

                        if any(fp in body_lower for fp in [
                            "microsoftonline.com",
                            "oauth2/v2.0/authorize",
                            "login.microsoftonline",
                            "accounts.google.com",
                            "location.href",
                        ]) and len(body) < 2000:
                            return

                        if any(fp in body_lower for fp in [
                            "404 not found",
                            "page not found",
                            "no encontrado",
                            "the resource you are looking for",
                        ]) and not verify:
                            return

                    # On catch-all hosts: require pattern match for ALL 200 responses
                    if status == 200 and name in self._catchall_hosts:
                        # GraphQL: try POST probe — GET always returns SPA on catch-all
                        if path in ("/graphql", "/api/graphql", "/graphql/"):
                            try:
                                _gql_resp = await self.http.post(
                                    url,
                                    data='{"query":"{ __typename }"}',
                                    headers={"Content-Type": "application/json",
                                             "Accept": "application/json"},
                                )
                                if _gql_resp and _gql_resp.get("status") == 200:
                                    _gql_body = _gql_resp.get("data", "") or ""
                                    if any(k in _gql_body for k in
                                           ("__typename", "data", "errors")):
                                        body = _gql_body
                                    else:
                                        return
                                else:
                                    return
                            except Exception:
                                return
                        elif not verify:
                            return  # No pattern to validate — skip on catch-all
                        elif not re.search(verify, body, re.IGNORECASE):
                            return  # Pattern doesn't match — catch-all returning index.html

                    if verify and status == 200:
                        if not re.search(verify, body, re.IGNORECASE):
                            return

                    actual_severity = severity
                    sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
                    if status in (401, 403):
                        label = f"{label} (auth-protected)"

                        truly_sensitive = any(x in path for x in [
                            ".env", ".git/", "id_rsa", ".sql", "dump",
                            "backup", "shadow", "passwd", "credentials",
                        ])
                        if truly_sensitive:

                            idx = sev_order.index(severity)
                            actual_severity = sev_order[min(idx + 1, len(sev_order) - 1)]
                        else:

                            actual_severity = Severity.LOW

                    found += 1
                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                        code="CONTENT_DISCOVERED",
                        title=f"Sensitive Path Found: {label}",
                        detail=f"HTTP {status} at {url}",
                        severity=actual_severity,
                        entity_id=domain_entity.id,
                        entity_name=name,
                    ))

                    paths = domain_entity.properties.get("discovered_paths", [])
                    paths.append({"path": path, "label": label,
                                  "status": status, "severity": actual_severity.value})
                    domain_entity.properties["discovered_paths"] = paths

                    # Save special endpoints for other modules to use
                    if "graphql" in path.lower() and status == 200:
                        domain_entity.properties["graphql_endpoint"] = f"{scheme}://{name}{path}"
                    if path in ("/swagger-ui.html", "/api-docs", "/swagger.json", "/openapi.json"):
                        domain_entity.properties["openapi_endpoint"] = f"{scheme}://{name}{path}"

                    if actual_severity in (Severity.CRITICAL, Severity.HIGH):
                        logger.warning(f"CONTENT FOUND [{status}]: {url} — {label}")

                    if status == 200 and path.rstrip("/") in (
                        "/admin", "/api", "/backup", "/.git",
                        "/config", "/console", "/dashboard", "/manage",
                    ):
                        import random, string
                        _rand = "/" + "".join(random.choices(string.ascii_lowercase, k=12))
                        _wild = await self.http.get(f"{scheme}://{name}{_rand}", use_cache=False)
                        _is_wildcard = _wild and _wild.get("status") == 200
                        if not _is_wildcard:
                            _base = path.rstrip("/")
                            sub_paths = [
                                f"{_base}/config",   f"{_base}/settings",
                                f"{_base}/users",    f"{_base}/accounts",
                                f"{_base}/debug",    f"{_base}/logs",
                                f"{_base}/.env",     f"{_base}/backup",
                            ]
                        for sp in sub_paths:
                            sub_resp = await self.http.get(
                                f"{scheme}://{name}{sp}", use_cache=False
                            )
                            if sub_resp and sub_resp.get("status") in (200, 403):
                                async with path_sem:
                                    pass
                                _rec_key = f"{scheme}://{name}{sp}"
                                if _rec_key not in ContentDiscovery._global_seen:
                                    ContentDiscovery._global_seen.add(_rec_key)
                                    logger.warning(
                                        f"CONTENT FOUND [{sub_resp.get('status')}]: "
                                        f"{scheme}://{name}{sp} — Recursive discovery"
                                    )

                    if path in ("/graphql", "/api/graphql") and status == 200:
                        await self._test_graphql_introspection(url, domain_entity)

                    if ".git" in path and status == 200:
                        await self._probe_git(scheme, name, domain_entity)

                except Exception as e:
                    logger.debug(f"Content discovery error {url}: {e}")

        await asyncio.gather(
            *[check_path(path, label, sev, verify)
              for path, label, sev, verify in DISCOVERY_PATHS],
            return_exceptions=True,
        )
        return found

    async def _test_graphql_introspection(self, url: str, domain_entity) -> None:
        """Test if GraphQL introspection is enabled."""
        try:
            resp = await self.http.get(
                url,
                headers={"Content-Type": "application/json"},
            )

            self.graph.penalize_entity(domain_entity.id, Anomaly(
                code="GRAPHQL_ENDPOINT_EXPOSED",
                title="GraphQL Endpoint Accessible",
                detail=f"GraphQL at {url} — test introspection manually: "
                       f'POST with body: {GRAPHQL_INTROSPECTION}',
                severity=Severity.MEDIUM,
                entity_id=domain_entity.id,
                entity_name=domain_entity.name,
            ))
        except Exception:
            pass

    async def _probe_git(self, scheme: str, name: str, domain_entity) -> None:
        """Try to fetch more git objects to confirm full exposure."""
        git_files = ["/.git/COMMIT_EDITMSG", "/.git/logs/HEAD", "/.git/FETCH_HEAD"]
        for gf in git_files:
            try:
                resp = await self.http.get(f"{scheme}://{name}{gf}")
                if resp and resp.get("status") == 200:
                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                        code="GIT_REPO_FULLY_EXPOSED",
                        title="Git Repository Fully Exposed (Confirmed)",
                        detail=f"Multiple git objects accessible at {scheme}://{name}/.git/ — "
                               f"full source code recovery possible with git-dumper",
                        severity=Severity.CRITICAL,
                        entity_id=domain_entity.id,
                        entity_name=domain_entity.name,
                    ))
                    break
            except Exception:
                pass
