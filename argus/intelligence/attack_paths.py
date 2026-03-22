"""
Attack Path Synthesis Engine
Analyzes the Knowledge Graph to compute realistic attack paths.
Given: external attacker position (internet)
Goal: identify the lowest-resistance paths to critical assets

Approach:
  1. Identify entry points (exposed services, vulnerable endpoints)
  2. Identify critical assets (admin panels, databases, internal IPs, staging)
  3. Find shortest paths between entry → critical via graph relationships
  4. Score each path by CVSS-like composite risk
  5. Generate human-readable attack narrative

Correlates findings to produce actionable attack chains.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from argus.ontology.entities import Anomaly, EntityType, RelationType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.attack_paths")

ENTRY_POINT_CODES: Set[str] = {
    "SUBDOMAIN_TAKEOVER",
    "SUBDOMAIN_TAKEOVER_CANDIDATE",
    "GIT_REPO_FULLY_EXPOSED",
    "JS_SECRET_EXPOSED",
    "CONTENT_DISCOVERED",
    "TLS_SSLV3_ENABLED",
    "TLS_CRIME_COMPRESSION",
    "OPEN_REDIRECT",
    "CORS_REFLECTED_ORIGIN_WITH_CREDENTIALS",
    "HTTP_NO_HTTPS_REDIRECT",
    "EMAIL_SPOOFING_CRITICAL",
    "EMAIL_SPOOFING_HIGH",
    "AXFR_EXPOSED",
    "SOURCE_MAP_EXPOSED",
}

CRITICAL_ASSET_CODES: Set[str] = {
    "CERT_PRIVATE_IP_SAN",
    "BANNER_VULNERABLE_VERSION",
    "IP_SENSITIVE_PORT",
    "DOMAIN_STAGING_EXPOSED",
    "ORIGIN_IP_LEAKED",
    "IP_MIXED_TENANCY",
}

SEVERITY_CVSS: Dict[str, float] = {
    "CRITICAL": 9.0,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      3.0,
    "INFO":     1.0,
}

@dataclass
class AttackStep:
    entity_name:  str
    entity_type:  str
    action:       str
    anomaly_code: str = ""
    cvss_score:   float = 0.0

@dataclass
class AttackPath:
    path_id:      int
    title:        str
    steps:        List[AttackStep] = field(default_factory=list)
    composite_score: float = 0.0
    severity:     str = "LOW"
    entry_point:  str = ""
    target:       str = ""
    description:  str = ""

    def to_dict(self) -> Dict:
        return {
            "path_id":        self.path_id,
            "title":          self.title,
            "severity":       self.severity,
            "composite_score":round(self.composite_score, 1),
            "entry_point":    self.entry_point,
            "target":         self.target,
            "description":    self.description,
            "steps":          [
                {
                    "step":        i + 1,
                    "entity":      s.entity_name,
                    "type":        s.entity_type,
                    "action":      s.action,
                    "cvss":        s.cvss_score,
                }
                for i, s in enumerate(self.steps)
            ],
        }

class AttackPathEngine:
    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph

    def synthesize(self) -> List[AttackPath]:
        """
        Compute all viable attack paths.
        Returns list sorted by composite risk score (highest first).
        """
        paths: List[AttackPath] = []
        path_id = 1

        for entity in self.graph.get_by_type(EntityType.DOMAIN):
            for anomaly in entity.anomalies:
                if anomaly.code in ("SUBDOMAIN_TAKEOVER", "SUBDOMAIN_TAKEOVER_CANDIDATE"):
                    path = self._build_takeover_path(entity, anomaly, path_id)
                    if path:
                        paths.append(path)
                        path_id += 1

        for entity in self.graph.get_by_type(EntityType.DOMAIN):
            git_anomalies = [a for a in entity.anomalies
                             if "GIT" in a.code or "SOURCE_MAP" in a.code]
            if git_anomalies:
                path = self._build_git_path(entity, git_anomalies[0], path_id)
                if path:
                    paths.append(path)
                    path_id += 1

        for entity in self.graph.get_by_type(EntityType.DOMAIN):
            secret_anomalies = [a for a in entity.anomalies if a.code == "JS_SECRET_EXPOSED"]
            if secret_anomalies:
                path = self._build_secret_path(entity, secret_anomalies, path_id)
                if path:
                    paths.append(path)
                    path_id += 1

        for entity in self.graph.get_by_type(EntityType.DOMAIN):
            spoof_anomalies = [a for a in entity.anomalies
                               if "EMAIL_SPOOFING" in a.code or "SPF_PLUS_ALL" in a.code
                               or "DMARC_MISSING" in a.code]
            if spoof_anomalies:
                path = self._build_phishing_path(entity, spoof_anomalies[0], path_id)
                if path:
                    paths.append(path)
                    path_id += 1

        for entity in self.graph.get_by_type(EntityType.DOMAIN):
            origin_anomalies = [a for a in entity.anomalies if a.code == "ORIGIN_IP_LEAKED"]
            if origin_anomalies:
                path = self._build_cdn_bypass_path(entity, origin_anomalies[0], path_id)
                if path:
                    paths.append(path)
                    path_id += 1

        for entity in self.graph.get_by_type(EntityType.IP):
            port_anomalies = [a for a in entity.anomalies if a.code == "IP_SENSITIVE_PORT"]
            tls_anomalies  = [a for a in entity.anomalies
                              if "TLS_SSLV3" in a.code or "TLS_1_0" in a.code]
            if port_anomalies and tls_anomalies:
                path = self._build_tls_port_path(entity, port_anomalies[0], tls_anomalies[0], path_id)
                if path:
                    paths.append(path)
                    path_id += 1

        for entity in self.graph.get_by_type(EntityType.DOMAIN):
            redirect_anomalies = [a for a in entity.anomalies if a.code == "OPEN_REDIRECT"]
            if redirect_anomalies:
                path = self._build_redirect_path(entity, redirect_anomalies[0], path_id)
                if path:
                    paths.append(path)
                    path_id += 1

        for entity in self.graph.get_by_type(EntityType.DOMAIN):
            staging_anomalies = [a for a in entity.anomalies
                                 if a.code == "DOMAIN_STAGING_EXPOSED"]
            if staging_anomalies:
                path = self._build_staging_path(entity, staging_anomalies[0], path_id)
                if path:
                    paths.append(path)
                    path_id += 1

        paths.sort(key=lambda p: p.composite_score, reverse=True)
        return paths

    def _build_takeover_path(self, entity, anomaly: Anomaly, pid: int) -> Optional[AttackPath]:
        is_confirmed = anomaly.code == "SUBDOMAIN_TAKEOVER"
        score = 9.5 if is_confirmed else 7.5
        return AttackPath(
            path_id=pid,
            title=f"Subdomain Takeover → Full Impersonation: {entity.name}",
            severity="CRITICAL" if is_confirmed else "HIGH",
            composite_score=score,
            entry_point=entity.name,
            target="Users of " + entity.name,
            description=(
                f"{'Confirmed' if is_confirmed else 'Potential'} subdomain takeover on {entity.name}. "
                f"Attacker claims the unclaimed external service, hosts malicious content on the "
                f"trusted subdomain, and intercepts traffic/credentials from legitimate users."
            ),
            steps=[
                AttackStep(entity.name, "domain", f"Claim unclaimed service pointed to by {entity.name} CNAME", anomaly.code, score),
                AttackStep(entity.name, "domain", "Host phishing page or credential harvester on trusted domain", "", 8.0),
                AttackStep("Users", "external", "Users receive links to trusted subdomain, enter credentials", "", 9.0),
                AttackStep("Target Systems", "backend", "Attacker uses harvested credentials to access internal systems", "", 9.5),
            ],
        )

    def _build_git_path(self, entity, anomaly: Anomaly, pid: int) -> Optional[AttackPath]:
        return AttackPath(
            path_id=pid,
            title=f"Git Repository Exposed → Source Code → Credentials: {entity.name}",
            severity="CRITICAL",
            composite_score=9.2,
            entry_point=f"{entity.name}/.git/",
            target="Application backend / credentials",
            description=(
                f"Git repository at {entity.name} is publicly accessible. "
                f"Attacker extracts full source code using git-dumper or similar tool. "
                f"Source code likely contains hardcoded credentials, API keys, database configs, "
                f"or internal endpoint URLs enabling further compromise."
            ),
            steps=[
                AttackStep(entity.name + "/.git/", "url", "Download git objects using git-dumper or wget", anomaly.code, 7.5),
                AttackStep(entity.name, "domain", "Reconstruct full source code from git objects", "", 7.5),
                AttackStep("Source Code", "artifact", "Extract credentials, API keys, DB connection strings", "", 9.0),
                AttackStep("Backend Systems", "backend", "Use extracted credentials to access databases/APIs/admin panels", "", 9.5),
            ],
        )

    def _build_secret_path(self, entity, anomalies: List[Anomaly], pid: int) -> Optional[AttackPath]:
        secret_types = list({a.title.split(": ")[-1] for a in anomalies[:3]})
        return AttackPath(
            path_id=pid,
            title=f"Hardcoded Secrets in JS → API Abuse: {entity.name}",
            severity="CRITICAL",
            composite_score=8.8,
            entry_point=f"{entity.name} JavaScript files",
            target="APIs / Cloud accounts / Third-party services",
            description=(
                f"{len(anomalies)} secret(s) found in publicly accessible JavaScript files on {entity.name}: "
                f"{', '.join(secret_types[:3])}. "
                f"Attacker downloads JS files, extracts credentials, and uses them to access "
                f"cloud resources, payment APIs, or internal services."
            ),
            steps=[
                AttackStep(entity.name, "domain", "Download JavaScript files from public website", anomalies[0].code, 3.0),
                AttackStep("JS Files", "artifact", f"Extract secrets: {', '.join(secret_types[:2])}", "", 5.0),
                AttackStep("External APIs", "service", "Use extracted API keys to access cloud/payment/communication APIs", "", 9.0),
                AttackStep("Data / Services", "backend", "Exfiltrate data, send unauthorized requests, or pivot to internal systems", "", 9.5),
            ],
        )

    def _build_phishing_path(self, entity, anomaly: Anomaly, pid: int) -> Optional[AttackPath]:
        return AttackPath(
            path_id=pid,
            title=f"Email Spoofing → Phishing Campaign: {entity.name}",
            severity="HIGH",
            composite_score=8.0,
            entry_point=f"@{entity.name} email domain",
            target="Employees / Customers of " + entity.name,
            description=(
                f"Domain {entity.name} has weak email authentication ({anomaly.code}). "
                f"Attacker sends emails appearing to come from @{entity.name} — a trusted government/corporate domain. "
                f"Recipients are highly likely to trust and click links, enter credentials, or execute attachments."
            ),
            steps=[
                AttackStep(entity.name, "domain", f"SPF/DMARC misconfiguration allows sending as @{entity.name}", anomaly.code, 6.0),
                AttackStep("Email System", "service", f"Send phishing emails from @{entity.name} to targets", "", 7.0),
                AttackStep("Targets", "external", "Victims trust email from known domain — click malicious links", "", 8.0),
                AttackStep("Credentials / Systems", "backend", "Harvest credentials or execute malware via trusted email vector", "", 9.0),
            ],
        )

    def _build_cdn_bypass_path(self, entity, anomaly: Anomaly, pid: int) -> Optional[AttackPath]:
        return AttackPath(
            path_id=pid,
            title=f"CDN/WAF Bypass → Direct Server Attack: {entity.name}",
            severity="HIGH",
            composite_score=8.3,
            entry_point=entity.name + " (origin IP)",
            target="Origin web server (unprotected)",
            description=(
                f"Real origin IP behind CDN/WAF discovered for {entity.name}. "
                f"Attacker connects directly to the origin server, bypassing all CDN-based protections "
                f"(DDoS mitigation, WAF rules, rate limiting). Direct access to unprotected web server."
            ),
            steps=[
                AttackStep(entity.name, "domain", "Identify origin IP via SPF/MX/SAN correlation", anomaly.code, 5.0),
                AttackStep("Origin IP", "ip", "Connect directly to origin server — bypasses CDN/WAF completely", "", 7.5),
                AttackStep("Web Server", "service", "Probe web application directly without WAF interference", "", 8.0),
                AttackStep("Application", "backend", "Exploit web vulnerabilities that WAF would have blocked", "", 9.0),
            ],
        )

    def _build_tls_port_path(self, entity, port_anomaly: Anomaly, tls_anomaly: Anomaly, pid: int) -> Optional[AttackPath]:
        return AttackPath(
            path_id=pid,
            title=f"Weak TLS + Sensitive Port → MITM + Data Intercept: {entity.name}",
            severity="HIGH",
            composite_score=7.8,
            entry_point=entity.name + " (network position)",
            target="Database / Admin service on " + entity.name,
            description=(
                f"IP {entity.name} has both a sensitive port exposed ({port_anomaly.detail}) "
                f"and deprecated TLS version ({tls_anomaly.code}). "
                f"Attacker with network access (ISP, same datacenter, compromised router) can "
                f"downgrade TLS and intercept/decrypt sensitive communications."
            ),
            steps=[
                AttackStep(entity.name, "ip", f"Identify sensitive service and weak TLS: {tls_anomaly.code}", tls_anomaly.code, 5.0),
                AttackStep("Network", "infrastructure", "Perform MITM via ARP spoofing / BGP hijack / compromised router", "", 7.0),
                AttackStep("TLS Session", "protocol", f"Downgrade TLS to {tls_anomaly.code.replace('TLS_','')} — decrypt traffic", "", 8.0),
                AttackStep("Sensitive Data", "data", "Extract credentials, session tokens, or database queries from plaintext", "", 8.5),
            ],
        )

    def _build_redirect_path(self, entity, anomaly: Anomaly, pid: int) -> Optional[AttackPath]:
        return AttackPath(
            path_id=pid,
            title=f"Open Redirect → Trusted Domain Phishing: {entity.name}",
            severity="MEDIUM",
            composite_score=6.5,
            entry_point=f"{entity.name}/?{anomaly.detail.split('?')[-1].split('=')[0]}=",
            target="Users of " + entity.name,
            description=(
                f"Open redirect found on {entity.name}. "
                f"Attacker crafts links like {entity.name}/?redirect=https://evil.com — "
                f"users see a trusted domain in the URL before being redirected to attacker site. "
                f"Highly effective for phishing when sender is a trusted gov/corporate entity."
            ),
            steps=[
                AttackStep(entity.name, "domain", f"Craft redirect URL: {entity.name}/{anomaly.detail.split('at ')[-1].split(' →')[0]}", anomaly.code, 4.0),
                AttackStep("Email / Chat", "channel", "Send crafted link via email or messaging — URL shows trusted domain", "", 6.0),
                AttackStep("Users", "external", "Users click — browser shows trusted domain, then redirects to evil.com", "", 7.0),
                AttackStep("Credentials", "data", "Users enter credentials on attacker-controlled lookalike site", "", 7.5),
            ],
        )

    def _build_staging_path(self, entity, anomaly: Anomaly, pid: int) -> Optional[AttackPath]:
        return AttackPath(
            path_id=pid,
            title=f"Staging Environment → Lower Security → Pivot: {entity.name}",
            severity="HIGH",
            composite_score=7.5,
            entry_point=entity.name,
            target="Production systems (shared infrastructure)",
            description=(
                f"Staging/development environment {entity.name} is publicly accessible. "
                f"Staging environments typically share infrastructure with production, have debug modes enabled, "
                f"weaker authentication, test credentials, and may expose internal APIs not meant for public access."
            ),
            steps=[
                AttackStep(entity.name, "domain", "Access staging environment — likely debug mode, verbose errors", anomaly.code, 5.0),
                AttackStep(entity.name, "domain", "Enumerate API endpoints, find test credentials, disabled auth", "", 7.0),
                AttackStep("Internal APIs", "service", "Use staging access to probe shared databases / internal services", "", 7.5),
                AttackStep("Production", "backend", "Pivot from staging to production via shared infrastructure", "", 8.5),
            ],
        )
