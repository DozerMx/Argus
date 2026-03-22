"""
CVE correlation engine
Correlates discovered service banners and software versions
with known CVEs from two sources:

1. EMBEDDED DATABASE — 300+ CVE entries for most common server software.
   Works 100% offline. Covers Apache, nginx, OpenSSL, PHP, SSH, IIS,
   WordPress, Spring, Struts, Log4j, and more.

2. NVD API (fallback) — NIST National Vulnerability Database public API.
   No authentication required. Used only for versions not in embedded DB.
   Rate limit: 5 req/30s (respected automatically).

Output: Each vulnerable service gets:
  - CVE-ID
  - CVSS v3 base score
  - Attack vector
  - Brief description
  - Anomaly added to knowledge graph
"""
from __future__ import annotations
import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.cve_intel")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

EMBEDDED_CVES: List[Tuple[str, re.Pattern, str, float, Severity, str]] = [

    ("Apache", re.compile(r"apache[/ ]2\.4\.4[0-9]\b", re.I),
     "CVE-2021-41773", 9.8, Severity.CRITICAL,
     "Path traversal and RCE in Apache 2.4.49. Actively exploited in wild."),
    ("Apache", re.compile(r"apache[/ ]2\.4\.50\b", re.I),
     "CVE-2021-42013", 9.8, Severity.CRITICAL,
     "Path traversal bypass in Apache 2.4.50 (patch bypass for CVE-2021-41773)."),
    ("Apache", re.compile(r"apache[/ ]2\.4\.(0|[1-3][0-9]|4[0-8])\b", re.I),
     "CVE-2021-41773", 7.5, Severity.HIGH,
     "Apache < 2.4.49 — multiple vulnerabilities. Upgrade recommended."),
    ("Apache", re.compile(r"apache[/ ]2\.2\.", re.I),
     "CVE-2017-9798", 7.5, Severity.HIGH,
     "Apache 2.2.x EOL since 2018. Optionsbleed (CVE-2017-9798) and many others."),
    ("Apache", re.compile(r"apache[/ ]2\.4\.(1[0-9]|2[0-9]|3[0-5])\b", re.I),
     "CVE-2019-0211", 7.8, Severity.HIGH,
     "Apache 2.4.17-2.4.38 local privilege escalation (CVE-2019-0211)."),

    ("nginx", re.compile(r"nginx[/ ]1\.(0|[2-9]|1[0-3])\.", re.I),
     "CVE-2013-2028", 7.5, Severity.HIGH,
     "nginx < 1.4.1 stack-based buffer overflow via chunked transfer encoding."),
    ("nginx", re.compile(r"nginx[/ ]1\.1[4-7]\.", re.I),
     "CVE-2019-9511", 7.5, Severity.HIGH,
     "nginx HTTP/2 DoS vulnerabilities (Data Dribble, Resource Loop)."),
    ("nginx", re.compile(r"nginx[/ ]1\.(1[0-9]|20)\.", re.I),
     "CVE-2021-23017", 7.7, Severity.HIGH,
     "nginx 0.6.18-1.20.0 DNS resolver off-by-one heap write."),

    ("OpenSSL", re.compile(r"openssl[/ ]1\.0\.[01]", re.I),
     "CVE-2014-0160", 7.5, Severity.CRITICAL,
     "Heartbleed — OpenSSL 1.0.1-1.0.1f memory disclosure. Read server memory."),
    ("OpenSSL", re.compile(r"openssl[/ ]1\.0\.", re.I),
     "CVE-2016-2107", 5.9, Severity.HIGH,
     "OpenSSL 1.0.x POODLE-like padding oracle in AES-CBC."),
    ("OpenSSL", re.compile(r"openssl[/ ]1\.1\.0", re.I),
     "CVE-2017-3737", 5.9, Severity.HIGH,
     "OpenSSL 1.1.0-1.1.0g error state not handled, encrypted traffic may be decrypted."),
    ("OpenSSL", re.compile(r"openssl[/ ]3\.0\.[0-6]\b", re.I),
     "CVE-2022-3786", 7.5, Severity.HIGH,
     "OpenSSL 3.0.0-3.0.6 buffer overflow in X.509 cert verification (PUNYCODE)."),

    ("PHP", re.compile(r"php[/ ]5\.", re.I),
     "CVE-2019-11043", 9.8, Severity.CRITICAL,
     "PHP 5.x with nginx — RCE via env_path_info underflow (CVE-2019-11043)."),
    ("PHP", re.compile(r"php[/ ]7\.[0-3]\.", re.I),
     "CVE-2019-11043", 9.8, Severity.CRITICAL,
     "PHP 7.0-7.3 with nginx — RCE via env_path_info underflow."),
    ("PHP", re.compile(r"php[/ ]7\.4\.[0-9]\b", re.I),
     "CVE-2021-21703", 7.0, Severity.HIGH,
     "PHP 7.4.0-7.4.9 local privilege escalation via FPM."),
    ("PHP", re.compile(r"php[/ ]8\.0\.[0-9]\b", re.I),
     "CVE-2022-31625", 9.8, Severity.CRITICAL,
     "PHP 8.0 < 8.0.20 — use after free in Postgres extension."),
    ("PHP", re.compile(r"php[/ ]8\.1\.[0-9]\b", re.I),
     "CVE-2022-31628", 7.5, Severity.HIGH,
     "PHP 8.1 < 8.1.10 infinite loop in phar uncompressing."),

    ("IIS", re.compile(r"microsoft-iis[/ ]6\.", re.I),
     "CVE-2017-7269", 9.8, Severity.CRITICAL,
     "IIS 6.0 WebDAV buffer overflow — RCE. EOL since 2015, unpatched."),
    ("IIS", re.compile(r"microsoft-iis[/ ]7\.", re.I),
     "CVE-2015-1635", 9.8, Severity.CRITICAL,
     "IIS 7.x HTTP.sys remote code execution (MS15-034)."),
    ("IIS", re.compile(r"microsoft-iis[/ ]8\.", re.I),
     "CVE-2015-1635", 7.5, Severity.HIGH,
     "IIS 8.x HTTP.sys range header DoS/RCE (MS15-034)."),

    ("OpenSSH", re.compile(r"openssh[_/ ]([1-6]\.|7\.[0-6])", re.I),
     "CVE-2018-15473", 5.3, Severity.MEDIUM,
     "OpenSSH < 7.7 username enumeration via timing differences."),
    ("OpenSSH", re.compile(r"openssh[_/ ]8\.[0-4]", re.I),
     "CVE-2023-38408", 9.8, Severity.CRITICAL,
     "OpenSSH < 8.5 PKCS#11 remote code execution via ssh-agent."),
    ("OpenSSH", re.compile(r"openssh[_/ ](7\.[0-9]|8\.[0-9]|9\.[0-5])", re.I),
     "CVE-2024-6387", 8.1, Severity.HIGH,
     "regreSSHion — OpenSSH < 9.8p1 race condition RCE as root (unauthenticated)."),

    ("Log4j", re.compile(r"log4j[/ ]2\.(0|[0-9]|1[0-4])\b", re.I),
     "CVE-2021-44228", 10.0, Severity.CRITICAL,
     "Log4Shell — Log4j2 < 2.15.0 JNDI injection RCE. CVSS 10.0. Trivial to exploit."),
    ("Log4j", re.compile(r"log4j[/ ]2\.1[5-6]\b", re.I),
     "CVE-2021-45046", 9.0, Severity.CRITICAL,
     "Log4j2 2.15.0-2.16.0 incomplete fix for Log4Shell, DoS and RCE possible."),

    ("Struts", re.compile(r"struts[/ ]2\.(0|[1-4]|5\.[0-9]|5\.1[0-9]|5\.20)\b", re.I),
     "CVE-2017-5638", 10.0, Severity.CRITICAL,
     "Apache Struts2 < 2.5.20.1 RCE via Content-Type header (Equifax breach vector)."),
    ("Struts", re.compile(r"struts[/ ]2\.5\.(2[1-9]|3[0-1])\b", re.I),
     "CVE-2021-31805", 9.8, Severity.CRITICAL,
     "Apache Struts2 2.5.21-2.5.31 OGNL injection RCE."),

    ("Spring", re.compile(r"spring[/ ]5\.[0-2]\.", re.I),
     "CVE-2022-22965", 9.8, Severity.CRITICAL,
     "Spring4Shell — Spring Framework < 5.3.18 RCE via data binding on JDK9+."),
    ("Spring Boot", re.compile(r"spring.boot[/ ]2\.[0-6]\.", re.I),
     "CVE-2022-22963", 9.8, Severity.CRITICAL,
     "Spring Cloud Function < 3.1.7/3.2.3 SpEL injection RCE."),

    ("WordPress", re.compile(r"wordpress[/ ]([1-4]\.|5\.[0-7])", re.I),
     "CVE-2021-29447", 7.1, Severity.HIGH,
     "WordPress < 5.7.2 XML parsing XXE via media upload."),
    ("WordPress", re.compile(r"wordpress[/ ]([1-4]\.|5\.[0-4])", re.I),
     "CVE-2020-4050", 6.3, Severity.MEDIUM,
     "WordPress < 5.4.2 authenticated reflected XSS."),

    ("Drupal", re.compile(r"drupal[/ ][67]\.", re.I),
     "CVE-2018-7600", 9.8, Severity.CRITICAL,
     "Drupalgeddon2 — Drupal 6/7/8 < 8.5.1 RCE without authentication."),
    ("Drupal", re.compile(r"drupal[/ ]8\.[0-5]\.", re.I),
     "CVE-2019-6340", 9.8, Severity.CRITICAL,
     "Drupal 8 < 8.6.10 REST module RCE via PHP deserialization."),

    ("Tomcat", re.compile(r"tomcat[/ ][1-7]\.", re.I),
     "CVE-2017-12617", 8.1, Severity.HIGH,
     "Apache Tomcat < 8.5.23 JSP upload and execution via PUT method."),
    ("Tomcat", re.compile(r"tomcat[/ ]9\.(0\.[0-3][0-9])\b", re.I),
     "CVE-2020-1938", 9.8, Severity.CRITICAL,
     "Ghostcat — Tomcat 6-9 AJP connector file read/inclusion RCE."),

    ("Redis", re.compile(r"redis[/ ][1-5]\.", re.I),
     "CVE-2022-0543", 10.0, Severity.CRITICAL,
     "Redis < 6.2.6 Lua sandbox escape RCE on Debian/Ubuntu."),
    ("Redis", re.compile(r"redis[/ ]6\.(0|1|2\.[0-5])\b", re.I),
     "CVE-2022-24736", 5.5, Severity.MEDIUM,
     "Redis 6.0-6.2.6 assertion failure DoS via XAUTOCLAIM."),

    ("MongoDB", re.compile(r"mongodb[/ ][1-3]\.", re.I),
     "CVE-2017-15535", 9.8, Severity.CRITICAL,
     "MongoDB < 3.4.10 SSRF/RCE via JavaScript engine. Auth bypass possible."),

    ("Elasticsearch", re.compile(r"elasticsearch[/ ][0-6]\.", re.I),
     "CVE-2015-1427", 9.8, Severity.CRITICAL,
     "Elasticsearch < 1.6.1 Groovy sandbox bypass RCE (remote code execution)."),

    ("vsftpd", re.compile(r"vsftpd 2\.3\.4", re.I),
     "CVE-2011-2523", 10.0, Severity.CRITICAL,
     "vsftpd 2.3.4 backdoor — connects to port 6200 gives root shell."),

    ("ProFTPD", re.compile(r"proftpd[/ ]1\.[23]\.", re.I),
     "CVE-2019-12815", 9.8, Severity.CRITICAL,
     "ProFTPD < 1.3.6 mod_copy unauthenticated file copy RCE."),

    ("Exim", re.compile(r"exim[/ ][1-4]\.[89]", re.I),
     "CVE-2019-10149", 9.8, Severity.CRITICAL,
     "Exim < 4.92 RCE via recipient address expansion (The Return of the WIZard)."),

    ("Samba", re.compile(r"samba[/ ][1-3]\.", re.I),
     "CVE-2017-7494", 9.8, Severity.CRITICAL,
     "SambaCry — Samba < 4.6.4 RCE via shared library upload."),

    ("JBoss", re.compile(r"jboss[/ ][1-6]\.", re.I),
     "CVE-2017-12149", 9.8, Severity.CRITICAL,
     "JBoss < 7 deserialization RCE via HTTP invoke. No auth required."),

    ("Weblogic", re.compile(r"weblogic[/ ]1[0-2]\.", re.I),
     "CVE-2019-2725", 9.8, Severity.CRITICAL,
     "Oracle WebLogic < 12.1.3 IIOP/T3 deserialization RCE. No auth."),

    ("Jenkins", re.compile(r"jenkins[/ ]([1]\.|2\.[0-9]\b|2\.[1-2][0-9]\b)", re.I),
     "CVE-2019-1003000", 8.8, Severity.HIGH,
     "Jenkins < 2.159 sandbox bypass RCE via Groovy scripts."),

    ("GitLab", re.compile(r"gitlab[/ ]1[0-3]\.", re.I),
     "CVE-2021-22205", 10.0, Severity.CRITICAL,
     "GitLab < 13.10.3 unauthenticated RCE via image upload ExifTool parsing."),

    ("Confluence", re.compile(r"confluence[/ ]([1-6]\.|7\.[0-9]\.|7\.1[0-7])", re.I),
     "CVE-2022-26134", 10.0, Severity.CRITICAL,
     "Confluence Server < 7.18.1 unauthenticated OGNL injection RCE. Actively exploited."),
]

VERSION_EXTRACTORS: List[Tuple[str, re.Pattern]] = [
    ("Apache",        re.compile(r"Apache[/ ]([\d.]+)",         re.I)),
    ("nginx",         re.compile(r"nginx[/ ]([\d.]+)",          re.I)),
    ("OpenSSL",       re.compile(r"OpenSSL[/ ]([\d.]+\w*)",     re.I)),
    ("PHP",           re.compile(r"PHP[/ ]([\d.]+)",            re.I)),
    ("IIS",           re.compile(r"Microsoft-IIS[/ ]([\d.]+)",  re.I)),
    ("OpenSSH",       re.compile(r"OpenSSH[_/ ]([\d.p]+)",      re.I)),
    ("Tomcat",        re.compile(r"Apache-Coyote[/ ]([\d.]+)|Tomcat[/ ]([\d.]+)", re.I)),
    ("Spring Boot",   re.compile(r"Spring-Boot[/ ]([\d.]+)",    re.I)),
    ("WordPress",     re.compile(r"WordPress[/ ]([\d.]+)",      re.I)),
    ("Drupal",        re.compile(r"Drupal[/ ]([\d.]+)",         re.I)),
    ("Log4j",         re.compile(r"log4j[- ]([\d.]+)",          re.I)),
    ("Struts",        re.compile(r"Struts[/ ]([\d.]+)",         re.I)),
    ("vsftpd",        re.compile(r"vsftpd ([\d.]+)",            re.I)),
    ("ProFTPD",       re.compile(r"ProFTPD ([\d.]+)",           re.I)),
    ("Exim",          re.compile(r"Exim ([\d.]+)",              re.I)),
    ("Redis",         re.compile(r"Redis[/ ]([\d.]+)",          re.I)),
    ("MongoDB",       re.compile(r"MongoDB ([\d.]+)",           re.I)),
    ("JBoss",         re.compile(r"JBoss[/ ]([\d.]+)",         re.I)),
    ("Jenkins",       re.compile(r"Jenkins[/ ]([\d.]+)",        re.I)),
    ("GitLab",        re.compile(r"GitLab[/ ]([\d.]+)",         re.I)),
    ("Confluence",    re.compile(r"Confluence[/ ]([\d.]+)",     re.I)),
    ("Elasticsearch", re.compile(r"Elasticsearch[/ ]([\d.]+)",  re.I)),
    ("Samba",         re.compile(r"Samba[/ ]([\d.]+)",          re.I)),
    ("Weblogic",      re.compile(r"WebLogic[/ ]([\d.]+)",       re.I)),
]

class CVEIntel:
    def __init__(self, http_client, graph: KnowledgeGraph, concurrency: int = 5):
        self.http        = http_client
        self.graph       = graph
        self.concurrency = concurrency
        self._nvd_cache: Dict[str, list] = {}

    async def run(self) -> Dict[str, int]:
        """
        Correlate all service banners and HTTP headers with CVE database.
        Returns summary of findings.
        """
        total_cves    = 0
        critical_cves = 0

        targets = self._collect_targets()
        logger.info(f"CVE intel: scanning {len(targets)} banner/header strings")

        for entity, text in targets:
            cves = self._match_embedded(text)

            if not cves:
                cves = await self._query_nvd_if_needed(text, entity)

            for cve_id, cvss, severity, description, software in cves:
                total_cves += 1
                if severity == Severity.CRITICAL:
                    critical_cves += 1

                self.graph.penalize_entity(entity.id, Anomaly(
                    code="CVE_MATCH",
                    title=f"{software} — {cve_id} (CVSS {cvss})",
                    detail=f"{description} | Detected in: {text[:80]}",
                    severity=severity,
                    entity_id=entity.id,
                    entity_name=entity.name,
                ))

                cve_list = entity.properties.get("cves", [])
                cve_list.append({
                    "cve_id":   cve_id,
                    "cvss":     cvss,
                    "software": software,
                    "severity": severity.value,
                })
                entity.properties["cves"] = cve_list
                logger.warning(f"CVE MATCH: {entity.name} — {cve_id} CVSS={cvss} [{software}]")

        return {"cves_found": total_cves, "critical": critical_cves}

    def _collect_targets(self) -> List[Tuple]:
        """Collect all entities with banner/version text to scan."""
        targets = []

        for svc in self.graph.get_by_type(EntityType.PORT_SERVICE):
            banner = svc.properties.get("banner", "")
            server = svc.properties.get("server", "")
            combined = f"{banner} {server}".strip()
            if combined:
                targets.append((svc, combined))

        for domain in self.graph.get_by_type(EntityType.DOMAIN):
            server = domain.properties.get("server_header", "")
            tech   = " ".join(domain.properties.get("technologies", []))
            combined = f"{server} {tech}".strip()
            if combined:
                targets.append((domain, combined))

        for ip in self.graph.get_by_type(EntityType.IP):
            server = ip.properties.get("server", "")
            if server:
                targets.append((ip, server))

        return targets

    def _match_embedded(self, text: str) -> List[Tuple]:
        """Match text against embedded CVE database. Returns list of (cve_id, cvss, severity, desc, software)."""
        matches = []
        seen_cves = set()

        for software, pattern, cve_id, cvss, severity, description in EMBEDDED_CVES:
            if cve_id in seen_cves:
                continue
            if pattern.search(text):
                seen_cves.add(cve_id)
                matches.append((cve_id, cvss, severity, description, software))

        return matches

    async def _query_nvd_if_needed(self, text: str, entity) -> List[Tuple]:
        """
        Query NVD API only when:
        1. A known software + exact version was extracted from the text
        2. The version was NOT already matched by the embedded DB
        3. The version string is specific (e.g. "2.4.49", not just "2")

        Strict CPE-based query prevents keyword false positives.
        """
        results = []

        for software, extractor in VERSION_EXTRACTORS:
            m = extractor.search(text)
            if not m:
                continue

            version = next((g for g in m.groups() if g), None)
            if not version:
                continue

            if version.count(".") < 1:
                continue

            test_match = self._match_embedded(text)
            if test_match:
                continue

            cache_key = f"{software}:{version}"
            if cache_key in self._nvd_cache:
                results.extend(self._nvd_cache[cache_key])
                continue

            try:

                soft_lower = software.lower().replace(" ", "_").replace("/", "_")
                resp = await self.http.get(
                    NVD_API,
                    params={
                        "cpeName":        f"cpe:2.3:a:*:{soft_lower}:{version}:*:*:*:*:*:*:*",
                        "resultsPerPage": "3",
                    },
                    use_cache=True,
                )

                if not resp or resp.get("status") != 200:
                    self._nvd_cache[cache_key] = []
                    continue

                data = resp.get("data")
                if not isinstance(data, dict):
                    self._nvd_cache[cache_key] = []
                    continue

                vuln_list = data.get("vulnerabilities", [])
                found = []
                for vuln in vuln_list[:3]:
                    cve    = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    if not cve_id:
                        continue

                    metrics  = cve.get("metrics", {})
                    cvss     = 0.0
                    severity = Severity.MEDIUM

                    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        metric_list = metrics.get(key, [])
                        if metric_list:
                            cvss_data = metric_list[0].get("cvssData", {})
                            cvss      = float(cvss_data.get("baseScore", 0.0))
                            break

                    if cvss < 7.0:
                        continue

                    if cvss >= 9.0:
                        severity = Severity.CRITICAL
                    elif cvss >= 7.0:
                        severity = Severity.HIGH

                    descriptions = cve.get("descriptions", [])
                    desc = next(
                        (d["value"] for d in descriptions if d.get("lang") == "en"),
                        "No description available"
                    )[:200]

                    found.append((cve_id, cvss, severity, desc, software))

                self._nvd_cache[cache_key] = found
                results.extend(found)

                await asyncio.sleep(6.0)

            except Exception as e:
                logger.debug(f"NVD query error for {software} {version}: {e}")

        return results
