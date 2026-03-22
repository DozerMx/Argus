"""
Supply Chain Analysis
Detects third-party JavaScript libraries loaded by target pages
and cross-references them against known CVE databases.

Sources:
  - Retire.js vulnerability database (embedded subset, most critical)
  - NPM audit patterns
  - Known vulnerable versions of top 50 web libraries

Also detects exposed package.json/composer.json/requirements.txt
to extract exact dependency versions.
"""
from __future__ import annotations
import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.supply_chain")

VULNERABLE_LIBS: List[Tuple[str, re.Pattern, str, Severity, str]] = [

    ("jQuery",
     re.compile(r"jquery[/-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I),
     "CVE-2019-11358 / CVE-2020-11022",
     Severity.HIGH,
     "jQuery < 3.5.0 vulnerable to XSS via prototype pollution"),

    ("Lodash",
     re.compile(r"lodash[/-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I),
     "CVE-2019-10744 / CVE-2020-8203",
     Severity.HIGH,
     "Lodash < 4.17.21 vulnerable to prototype pollution"),

    ("AngularJS",
     re.compile(r"angular[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I),
     "CVE-2019-14863",
     Severity.HIGH,
     "AngularJS 1.x — End of Life Dec 2021, multiple XSS vectors"),

    ("Bootstrap",
     re.compile(r"bootstrap[/-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I),
     "CVE-2018-14041 / CVE-2019-8331",
     Severity.MEDIUM,
     "Bootstrap < 4.3.1 XSS in data-template attribute"),

    ("Moment.js",
     re.compile(r"moment[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I),
     "CVE-2022-24785",
     Severity.HIGH,
     "Moment.js < 2.29.2 path traversal in locale loading"),

    ("Handlebars",
     re.compile(r"handlebars[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I),
     "CVE-2019-19919 / CVE-2021-23369",
     Severity.CRITICAL,
     "Handlebars < 4.7.7 prototype pollution → RCE"),

    ("Underscore",
     re.compile(r"underscore[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I),
     "CVE-2021-23358",
     Severity.HIGH,
     "Underscore < 1.13.0/1.12.1 prototype pollution"),

    ("Vue.js",
     re.compile(r"vue[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I),
     "CVE-2021-22960",
     Severity.MEDIUM,
     "Vue.js 2.x — check for XSS in v-html directives"),

    ("React DOM",
     re.compile(r"react-dom[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I),
     "CVE-2018-6341",
     Severity.MEDIUM,
     "React < 16.4.2 XSS in SSR attribute names"),

    ("Prototype.js",
     re.compile(r"prototype[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I),
     "CVE-2008-7220",
     Severity.HIGH,
     "Prototype.js multiple historical XSS/injection vulnerabilities"),

    ("MooTools",
     re.compile(r"mootools[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I),
     "CVE-2021-20087",
     Severity.HIGH,
     "MooTools legacy — prototype pollution vulnerabilities"),

    ("Dojo",
     re.compile(r"dojo[/-]([0-9]+\.[0-9]+\.[0-9]+)/dojo\.js", re.I),
     "CVE-2022-3602",
     Severity.HIGH,
     "Dojo Toolkit multiple XSS vulnerabilities"),

    ("CKEditor",
     re.compile(r"ckeditor[/-]([0-9]+\.[0-9]+\.[0-9]+)", re.I),
     "CVE-2021-37695 / CVE-2021-41165",
     Severity.HIGH,
     "CKEditor < 4.17.0 XSS in HTML comments"),

    ("TinyMCE",
     re.compile(r"tinymce[/-]([0-9]+\.[0-9]+\.[0-9]+)", re.I),
     "CVE-2021-44460 / CVE-2022-23494",
     Severity.HIGH,
     "TinyMCE < 6.3.1 XSS via content manipulation"),

    ("PDF.js",
     re.compile(r"pdf[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js", re.I),
     "CVE-2024-4367",
     Severity.CRITICAL,
     "PDF.js < 4.2.67 arbitrary JavaScript execution"),

    ("Socket.io",
     re.compile(r"socket\.io[/-]([0-9]+\.[0-9]+\.[0-9]+)", re.I),
     "CVE-2022-2421",
     Severity.HIGH,
     "Socket.io < 4.6.0 prototype pollution"),
]

def _parse_version(v: str) -> Tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except Exception:
        return (0, 0, 0)

SAFE_VERSIONS: Dict[str, str] = {
    "jQuery":      "3.5.0",
    "Lodash":      "4.17.21",
    "Bootstrap":   "4.3.1",
    "Moment.js":   "2.29.2",
    "Handlebars":  "4.7.7",
    "Underscore":  "1.13.0",
    "PDF.js":      "4.2.67",
    "Socket.io":   "4.6.0",
}

DEPENDENCY_PATHS = [
    "/package.json",
    "/package-lock.json",
    "/composer.json",
    "/requirements.txt",
    "/Pipfile",
    "/Gemfile",
    "/build.gradle",
    "/pom.xml",
    "/go.mod",
    "/Cargo.toml",
]

class SupplyChainAnalyzer:
    def __init__(self, http_client, graph: KnowledgeGraph,
                 timeout: int = 10, concurrency: int = 15):
        self.http        = http_client
        self.graph       = graph
        self.timeout     = timeout
        self.concurrency = concurrency

    async def run(self) -> Dict:
        """Analyze supply chain for all alive domains."""
        alive = [
            d for d in self.graph.get_by_type(EntityType.DOMAIN)
            if d.properties.get("is_alive")
        ]
        sem = asyncio.Semaphore(self.concurrency)
        total_vulns = 0
        total_libs  = 0
        lock = asyncio.Lock()

        async def analyze_one(domain_entity):
            nonlocal total_vulns, total_libs
            async with sem:
                vulns, libs = await self._analyze_domain(domain_entity)
                async with lock:
                    total_vulns += vulns
                    total_libs  += libs

        await asyncio.gather(*[analyze_one(d) for d in alive], return_exceptions=True)
        return {"vulnerable_libs": total_vulns, "libs_detected": total_libs}

    async def _analyze_domain(self, domain_entity) -> Tuple[int, int]:
        name   = domain_entity.name
        scheme = domain_entity.properties.get("http_scheme", "https")
        vulns  = 0
        libs   = 0

        try:
            resp = await self.http.get(f"{scheme}://{name}/")
            if resp and resp.get("status") == 200:
                body = resp.get("data") or ""
                if isinstance(body, str):
                    script_srcs = re.findall(
                        r'<script[^>]+src=["\']([^"\']+)["\']',
                        body, re.IGNORECASE
                    )
                    for src in script_srcs:

                        if src.startswith("//"):
                            src = f"{scheme}:{src}"
                        elif src.startswith("/"):
                            src = f"{scheme}://{name}{src}"
                        elif not src.startswith("http"):
                            src = f"{scheme}://{name}/{src}"

                        detected, is_vuln = self._check_url_for_known_libs(src, domain_entity)
                        if detected:
                            libs += 1
                        if is_vuln:
                            vulns += 1

                    for lib_name, pattern, cve, severity, desc in VULNERABLE_LIBS:
                        m = pattern.search(body)
                        if m:
                            version = m.group(1)
                            if self._is_vulnerable_version(lib_name, version):
                                vulns += 1
                                self._add_vuln_anomaly(domain_entity, lib_name, version, cve, severity, desc)

        except Exception as e:
            logger.debug(f"Supply chain HTML error {name}: {e}")

        dep_sem = asyncio.Semaphore(5)

        async def check_dep_file(path: str):
            async with dep_sem:
                try:
                    resp = await self.http.get(f"{scheme}://{name}{path}")
                    if resp and resp.get("status") == 200:
                        body = resp.get("data") or ""
                        if isinstance(body, str) and len(body) > 10:
                            findings = self._parse_dependency_file(path, body)
                            for lib, ver, cve, sev, desc in findings:
                                self._add_vuln_anomaly(domain_entity, lib, ver, cve, sev, desc,
                                                        f"Found in {path}")
                except Exception:
                    pass

        await asyncio.gather(*[check_dep_file(p) for p in DEPENDENCY_PATHS], return_exceptions=True)

        return vulns, libs

    def _check_url_for_known_libs(self, url: str, domain_entity) -> Tuple[bool, bool]:
        detected = False
        is_vuln  = False
        for lib_name, pattern, cve, severity, desc in VULNERABLE_LIBS:
            m = pattern.search(url)
            if m:
                detected = True
                version = m.group(1) if m.lastindex else "unknown"
                if self._is_vulnerable_version(lib_name, version):
                    is_vuln = True
                    self._add_vuln_anomaly(domain_entity, lib_name, version, cve, severity, desc)
        return detected, is_vuln

    def _is_vulnerable_version(self, lib_name: str, version: str) -> bool:
        safe_str = SAFE_VERSIONS.get(lib_name)
        if not safe_str:
            return True
        try:
            return _parse_version(version) < _parse_version(safe_str)
        except Exception:
            return False

    def _add_vuln_anomaly(self, domain_entity, lib: str, version: str,
                           cve: str, severity: Severity, desc: str,
                           context: str = ""):

        existing = domain_entity.properties.get("supply_chain_vulns", [])
        for v in existing:
            if v.get("lib") == lib and v.get("version") == version and v.get("cve") == cve:
                return

        detail = f"{lib} v{version} — {desc}"
        if context:
            detail += f" | {context}"
        detail += f" | {cve}"

        self.graph.penalize_entity(domain_entity.id, Anomaly(
            code="SUPPLY_CHAIN_VULN",
            title=f"Vulnerable Dependency: {lib} v{version}",
            detail=detail,
            severity=severity,
            entity_id=domain_entity.id,
            entity_name=domain_entity.name,
        ))

        existing.append({"lib": lib, "version": version, "cve": cve, "severity": severity.value})
        domain_entity.properties["supply_chain_vulns"] = existing
        logger.warning(f"SUPPLY CHAIN: {domain_entity.name} — {lib} v{version} ({cve})")

    def _parse_dependency_file(self, path: str, content: str) -> List[Tuple]:
        findings = []
        if "package.json" in path or "package-lock.json" in path:

            for lib_name, pattern, cve, severity, desc in VULNERABLE_LIBS:
                lib_lower = lib_name.lower().replace(".", "").replace(" ", "-")
                ver_match = re.search(
                    rf'["\'](?:lodash|jquery|moment|handlebars|underscore|bootstrap|'
                    rf'socket\.io|vue|react)["\'\s:]+["\']([~^]?[0-9]+\.[0-9]+\.[0-9]+)',
                    content, re.IGNORECASE
                )
                if ver_match:
                    version = ver_match.group(1).lstrip("^~")
                    if self._is_vulnerable_version(lib_name, version):
                        findings.append((lib_name, version, cve, severity, desc))

        elif "requirements.txt" in path or "Pipfile" in path:

            python_vulns = [
                (r"django[==<>!]+([0-9.]+)", "Django", "CVE-2021-44420", Severity.HIGH,
                 "Django < 3.2.10 SQL injection in QuerySet.order_by"),
                (r"flask[==<>!]+([0-9.]+)", "Flask", "CVE-2023-30861", Severity.HIGH,
                 "Flask < 2.3.2 cookie session security"),
                (r"requests[==<>!]+([0-9.]+)", "Requests", "CVE-2023-32681", Severity.MEDIUM,
                 "Requests < 2.31.0 proxy credential leak"),
                (r"pillow[==<>!]+([0-9.]+)", "Pillow", "CVE-2023-44271", Severity.HIGH,
                 "Pillow < 10.0.0 arbitrary code execution"),
                (r"cryptography[==<>!]+([0-9.]+)", "cryptography", "CVE-2023-49083", Severity.MEDIUM,
                 "cryptography < 41.0.6 NULL pointer dereference"),
            ]
            for ver_pattern, lib, cve, sev, desc in python_vulns:
                m = re.search(ver_pattern, content, re.IGNORECASE)
                if m:
                    findings.append((lib, m.group(1), cve, sev, desc))

        return findings
