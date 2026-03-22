"""
Daemon Mode + Nuclei-style Template Engine

1. Daemon Mode
   - Runs scans on a schedule (every N hours)
   - Compares each scan against previous via ScanDiff
   - Sends alerts only on new findings
   - Supports Telegram and Slack webhooks

2. Template Engine
   - YAML-defined custom checks
   - HTTP request templates with matchers
   - Regex/status code/header matching
   - No code required to add new checks
   - Templates stored in ~/.argus/templates/
"""
from __future__ import annotations
import asyncio
import json
import logging
import re
import time
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("argus.intelligence.daemon")

TEMPLATES_DIR  = Path.home() / ".argus" / "templates"
DEFAULT_TEMPLATES: List[Dict] = [
    {
        "id":          "exposed-env-backup",
        "name":        "Exposed .env.bak file",
        "severity":    "critical",
        "requests": [{
            "path":    "/.env.bak",
            "method":  "GET",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "regex",  "pattern": "[A-Z_]+="},
            ],
        }],
    },
    {
        "id":          "graphql-introspection",
        "name":        "GraphQL Introspection Enabled",
        "severity":    "medium",
        "requests": [{
            "path":    "/graphql",
            "method":  "GET",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "regex",  "pattern": r'"__schema"|"__type"|"data":\s*\{'},
            ],
        }],
    },
    {
        "id":          "spring-actuator-env",
        "name":        "Spring Boot /actuator/env exposed",
        "severity":    "critical",
        "requests": [{
            "path":    "/actuator/env",
            "method":  "GET",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "regex",  "pattern": "activeProfiles|propertySources"},
            ],
        }],
    },
    {
        "id":          "kubernetes-api",
        "name":        "Kubernetes API Server Exposed",
        "severity":    "critical",
        "requests": [{
            "path":    "/api/v1/namespaces",
            "method":  "GET",
            "matchers": [
                {"type": "status", "values": [200, 401, 403]},

                {"type": "regex",  "pattern": r'"kind":\s*"(NamespaceList|Status)"|Unauthorized.*kubernetes|apiVersion'},
            ],
        }],
    },
    {
        "id":          "docker-api",
        "name":        "Docker API Exposed",
        "severity":    "critical",
        "ports":       [2375, 2376],
        "requests": [{
            "path":    "/v1.41/info",
            "method":  "GET",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "regex",  "pattern": "DockerRootDir|NCPU|MemTotal"},
            ],
        }],
    },
    {
        "id":          "prometheus-metrics",
        "name":        "Prometheus Metrics Exposed",
        "severity":    "medium",
        "requests": [{
            "path":    "/metrics",
            "method":  "GET",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "regex",  "pattern": "# HELP|# TYPE|go_goroutines"},
            ],
        }],
    },
    {
        "id":          "aws-metadata",
        "name":        "AWS IMDSv1 Metadata Accessible",
        "severity":    "critical",
        "requests": [{
            "path":    "/latest/meta-data/iam/security-credentials/",
            "method":  "GET",
            "matchers": [
                {"type": "status", "values": [200]},

                {"type": "regex",  "pattern": r"[A-Za-z0-9_+=,.@-]{1,64}"},

                {"type": "word",   "words_absent": ["<html", "<HTML", "<!DOCTYPE"]},
            ],
        }],
    },
    {
        "id":          "exposed-git-config",
        "name":        "Git Config with Remote URL",
        "severity":    "high",
        "requests": [{
            "path":    "/.git/config",
            "method":  "GET",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "regex",  "pattern": r"\[remote|url\s*=|\[core\]"},
            ],
        }],
    },
    {
        "id":          "laravel-debug-mode",
        "name":        "Laravel Debug Mode Enabled",
        "severity":    "high",
        "requests": [{
            "path":    "/",
            "method":  "GET",
            "matchers": [
                {"type": "regex",  "pattern": "Whoops!.*Exception|APP_DEBUG.*true|laravel.*debug"},
                {"type": "status", "values": [500]},
            ],
        }],
    },
    {
        "id":          "phpunit-eval-stdin",
        "name":        "PHPUnit Remote Code Execution",
        "severity":    "critical",
        "requests": [{
            "path":    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "method":  "GET",
            "matchers": [
                {"type": "status", "values": [200]},

                {"type": "regex",  "pattern": r"php|stdin|eval|phpunit"},
            ],
        }],
    },
]

class TemplateEngine:
    """
    Nuclei-style YAML template runner.
    Loads templates from disk + builtin defaults.
    """

    def __init__(self, http_client, graph, concurrency: int = 30):
        self.http        = http_client
        self.graph       = graph
        self.concurrency = concurrency
        self._templates: List[Dict] = []
        self._load_templates()

    def _load_templates(self) -> None:
        """Load builtin + user templates from ~/.argus/templates/"""
        self._templates = list(DEFAULT_TEMPLATES)
        TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        for template_file in TEMPLATES_DIR.glob("*.yaml"):
            try:
                data = yaml.safe_load(template_file.read_text())
                if isinstance(data, dict) and "id" in data:
                    self._templates.append(data)
                    logger.debug(f"Loaded template: {data['id']}")
            except Exception as e:
                logger.warning(f"Template load error {template_file}: {e}")
        logger.info(f"Template engine: {len(self._templates)} templates loaded")

    async def run(self) -> Dict[str, int]:
        """Run all templates against all alive domains."""
        from argus.ontology.entities import EntityType, Anomaly, Severity
        alive = [
            d for d in self.graph.get_by_type(EntityType.DOMAIN)
            if d.properties.get("is_alive")
        ]
        sem = asyncio.Semaphore(self.concurrency)
        total_hits = 0
        lock = asyncio.Lock()

        async def run_templates_on_domain(domain_entity):
            nonlocal total_hits
            name   = domain_entity.name
            scheme = domain_entity.properties.get("http_scheme", "https")
            hits   = 0

            for template in self._templates:
                async with sem:
                    matched = await self._run_template(template, name, scheme)
                    if matched:
                        hits += 1
                        sev_map = {
                            "critical": Severity.CRITICAL,
                            "high":     Severity.HIGH,
                            "medium":   Severity.MEDIUM,
                            "low":      Severity.LOW,
                            "info":     Severity.INFO,
                        }
                        severity = sev_map.get(template.get("severity", "medium").lower(), Severity.MEDIUM)
                        self.graph.penalize_entity(domain_entity.id, Anomaly(
                            code=f"TEMPLATE_{template['id'].upper().replace('-','_')}",
                            title=f"[Template] {template['name']}",
                            detail=f"Template '{template['id']}' matched on {name}",
                            severity=severity,
                            entity_id=domain_entity.id, entity_name=name,
                        ))
                        logger.warning(f"TEMPLATE HIT: [{template['id']}] {name}")

            async with lock:
                total_hits += hits

        await asyncio.gather(*[run_templates_on_domain(d) for d in alive], return_exceptions=True)
        return {"template_hits": total_hits, "templates_loaded": len(self._templates)}

    async def _run_template(self, template: Dict, name: str, scheme: str) -> bool:
        """Execute a single template against a domain. Returns True if all matchers match."""
        requests = template.get("requests", [])
        if not requests:
            return False

        for req in requests:
            path    = req.get("path", "/")
            method  = req.get("method", "GET").upper()
            headers = req.get("headers", {})
            body    = req.get("body")

            url = f"{scheme}://{name}{path}"

            try:
                if method == "GET":
                    resp = await self.http.get(url, headers=headers)
                else:

                    resp = await self.http.get(url, headers=headers)

                if not resp:
                    return False

                status  = resp.get("status", 0)
                resp_body = str(resp.get("data") or "")

                matchers = req.get("matchers", [])
                if not matchers:
                    continue

                all_match = True
                for matcher in matchers:
                    mtype = matcher.get("type", "status")
                    if mtype == "status":
                        if status not in matcher.get("values", [200]):
                            all_match = False
                            break
                    elif mtype == "regex":
                        pattern = matcher.get("pattern", "")
                        if not re.search(pattern, resp_body, re.IGNORECASE):
                            all_match = False
                            break
                    elif mtype == "word":
                        words = matcher.get("words", [])
                        if words and not all(w in resp_body for w in words):
                            all_match = False
                            break

                        words_absent = matcher.get("words_absent", [])
                        if any(w in resp_body for w in words_absent):
                            all_match = False
                            break

                if all_match:
                    return True

            except Exception as e:
                logger.debug(f"Template {template['id']} error on {name}: {e}")

        return False

class DaemonMode:
    """
    Continuous monitoring daemon.
    Runs scans on a schedule, alerts only on new findings.
    """

    def __init__(self, config, webhook_url: Optional[str] = None,
                 interval_hours: float = 6.0):
        self.config        = config
        self.webhook_url   = webhook_url
        self.interval_secs = interval_hours * 3600

    async def run(self, domains: List[str]) -> None:
        """Start daemon loop."""
        logger.info(f"Daemon started — scanning {len(domains)} domain(s) every {self.interval_secs/3600:.1f}h")
        iteration = 0

        while True:
            iteration += 1
            logger.info(f"Daemon iteration {iteration} — scanning {len(domains)} domains")
            start = time.time()

            for domain in domains:
                try:
                    await self._scan_and_alert(domain)
                except Exception as e:
                    logger.error(f"Daemon scan error for {domain}: {e}")

            elapsed = time.time() - start
            sleep_for = max(0, self.interval_secs - elapsed)
            logger.info(f"Daemon iteration {iteration} complete in {elapsed:.0f}s — sleeping {sleep_for:.0f}s")
            await asyncio.sleep(sleep_for)

    async def _scan_and_alert(self, domain: str) -> None:
        """Run a scan and send alerts only for new findings."""
        from argus.core import ArgusEngine
        from argus.output.terminal import TerminalRenderer
        from argus.intelligence.scan_diff import ScanSnapshot, ScanDiffer

        renderer = TerminalRenderer(quiet=True)
        engine   = ArgusEngine(self.config, renderer)
        result   = await engine.run(domain)

        if hasattr(result, 'diff_data') and result.diff_data:
            diff  = result.diff_data
            total = diff["summary"].get("total_changes", 0)

            if total > 0 and self.webhook_url:
                await self._send_alert(domain, diff)
                logger.info(f"Alert sent for {domain}: {total} changes")

    async def _send_alert(self, domain: str, diff: Dict) -> None:
        """Send webhook alert (Telegram or Slack format)."""
        try:
            import aiohttp

            appeared  = diff["domains"]["appeared"]
            new_anom  = diff["security"]["new_anomalies"]
            new_ports = diff["infrastructure"].get("new_ports_opened", {})

            lines = [
                f"*Argus Alert* — `{domain}`",
                f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                "",
            ]
            if appeared:
                lines.append(f"🆕 *New subdomains ({len(appeared)}):*")
                lines.extend(f"  `{s}`" for s in appeared[:5])
            if new_anom:
                lines.append(f"*New anomaly types ({len(new_anom)}):*")
                lines.extend(f"  `{a}`" for a in new_anom[:5])
            if new_ports:
                lines.append("*New open ports:*")
                for ip, ports in list(new_ports.items())[:3]:
                    lines.append(f"  `{ip}`: {ports}")

            message = "\n".join(lines)

            if "api.telegram.org" in self.webhook_url:
                payload = {"text": message, "parse_mode": "Markdown"}
            else:

                payload = {"text": message}

            async with aiohttp.ClientSession() as session:
                await session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                )
        except Exception as e:
            logger.warning(f"Alert send error: {e}")
