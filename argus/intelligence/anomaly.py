"""
Anomaly & Pattern Detection Engine
Analyzes the Knowledge Graph to detect security anomalies and patterns.
Penalizes entities with typed, severity-graded Anomaly objects.

Anomaly types:
  Certificate: expired, expiring soon, self-signed, weak key, wildcard, private IP in SAN
  Domain: staging exposed, legacy subdomain, AXFR leakage, no HTTPS
  Pattern: key reuse across domains, co-hosted with suspicious domain, multiple CA switches
"""
from __future__ import annotations
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Set

from argus.ontology.entities import Anomaly, EntityType, RelationType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.anomaly")

STAGING_LABELS: Set[str] = {
    "staging", "stage", "stg", "dev", "develop", "development",
    "test", "testing", "qa", "uat", "preprod", "pre-prod",
    "old", "legacy", "backup", "bak", "beta", "alpha", "demo",
    "internal", "int", "intranet", "sandbox", "poc",
}

SENSITIVE_PORTS: Set[int] = {
    22, 23, 3389, 5900, 5901,
    3306, 5432, 6379, 27017, 1433,
    9200, 9300, 5984,
    8161, 15672, 9090, 4848,
}

class AnomalyDetector:
    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph
        self.now = datetime.now(timezone.utc).replace(tzinfo=None)

    def run_all(self) -> int:
        """Run all anomaly checks. Returns total anomalies found."""
        count = 0
        count += self._check_certificates()
        count += self._check_domains()
        count += self._check_ips()
        count += self._check_patterns()
        logger.info(f"Anomaly detection: {count} anomalies found")
        return count

    def _check_certificates(self) -> int:
        count = 0
        for cert in self.graph.get_by_type(EntityType.CERTIFICATE):
            props = cert.properties

            not_after_str = props.get("not_after")
            if not_after_str:
                try:
                    not_after = datetime.fromisoformat(not_after_str)
                    if not_after < self.now:
                        days_ago = (self.now - not_after).days
                        self.graph.penalize_entity(cert.id, Anomaly(
                            code="CERT_EXPIRED",
                            title="Expired Certificate",
                            detail=f"Expired {days_ago} day(s) ago on {not_after.date()}",
                            severity=Severity.HIGH,
                            entity_id=cert.id, entity_name=cert.name,
                        ))
                        count += 1
                    elif (not_after - self.now) < timedelta(days=30):
                        days_left = (not_after - self.now).days
                        self.graph.penalize_entity(cert.id, Anomaly(
                            code="CERT_EXPIRING_SOON",
                            title="Certificate Expiring Soon",
                            detail=f"Expires in {days_left} day(s) on {not_after.date()}",
                            severity=Severity.MEDIUM,
                            entity_id=cert.id, entity_name=cert.name,
                        ))
                        count += 1
                except ValueError:
                    pass

            if props.get("is_self_signed"):
                self.graph.penalize_entity(cert.id, Anomaly(
                    code="CERT_SELF_SIGNED",
                    title="Self-Signed Certificate",
                    detail=f"Issued by {props.get('issuer_cn', 'unknown')} — not trusted by browsers",
                    severity=Severity.HIGH,
                    entity_id=cert.id, entity_name=cert.name,
                ))
                count += 1

            if props.get("is_wildcard"):
                self.graph.penalize_entity(cert.id, Anomaly(
                    code="CERT_WILDCARD",
                    title="Wildcard Certificate",
                    detail=f"Covers all subdomains of {props.get('common_name', '')}",
                    severity=Severity.MEDIUM,
                    entity_id=cert.id, entity_name=cert.name,
                ))
                count += 1

            for san in props.get("sans", []):
                try:
                    addr = ipaddress.ip_address(san)
                    if addr.is_private:
                        self.graph.penalize_entity(cert.id, Anomaly(
                            code="CERT_PRIVATE_IP_SAN",
                            title="Private IP Address in SAN",
                            detail=f"Internal IP {san} leaked in certificate SAN — reveals network topology",
                            severity=Severity.MEDIUM,
                            entity_id=cert.id, entity_name=cert.name,
                        ))
                        count += 1
                except ValueError:
                    pass

        return count

    def _check_domains(self) -> int:
        count = 0

        apex_domains = {
            ".".join(d.name.split(".")[-2:])
            for d in self.graph.get_by_type(EntityType.DOMAIN)
            if not d.properties.get("is_neighbor")
        }

        for domain in self.graph.get_by_type(EntityType.DOMAIN):
            name = domain.name
            if not name:
                continue

            if domain.properties.get("is_neighbor"):
                continue

            domain_apex = ".".join(name.split(".")[-2:])
            if domain_apex not in apex_domains:
                continue
            label = name.split(".")[0].lower()

            if label in STAGING_LABELS or any(kw in label for kw in STAGING_LABELS):
                self.graph.penalize_entity(domain.id, Anomaly(
                    code="DOMAIN_STAGING_EXPOSED",
                    title="Non-Production Environment Publicly Exposed",
                    detail=f"Subdomain '{name}' appears to be a dev/staging environment accessible from internet",
                    severity=Severity.HIGH,
                    entity_id=domain.id, entity_name=name,
                ))
                count += 1

            if any(kw in label for kw in {"old", "legacy", "backup", "bak", "archive", "deprecated"}):
                self.graph.penalize_entity(domain.id, Anomaly(
                    code="DOMAIN_LEGACY",
                    title="Legacy/Deprecated Subdomain",
                    detail=f"'{name}' appears to be a legacy or deprecated endpoint — likely unmaintained",
                    severity=Severity.MEDIUM,
                    entity_id=domain.id, entity_name=name,
                ))
                count += 1

            if domain.properties.get("is_alive"):
                certs = self.graph.successors(domain.id, RelationType.SECURED_BY)
                if not certs:
                    self.graph.penalize_entity(domain.id, Anomaly(
                        code="DOMAIN_NO_CERT",
                        title="No Certificate Found in CT Logs",
                        detail=f"'{name}' is alive but has no certificate in CT logs — possible hidden infrastructure",
                        severity=Severity.LOW,
                        entity_id=domain.id, entity_name=name,
                    ))
                    count += 1

        return count

    def _check_ips(self) -> int:
        count = 0
        for ip_entity in self.graph.get_by_type(EntityType.IP):

            for svc in self.graph.successors(ip_entity.id, RelationType.EXPOSES_SERVICE):
                port = svc.properties.get("port")
                if port in SENSITIVE_PORTS:
                    self.graph.penalize_entity(ip_entity.id, Anomaly(
                        code="IP_SENSITIVE_PORT",
                        title=f"Sensitive Port {port} Exposed",
                        detail=f"IP {ip_entity.name} has port {port} open ({svc.properties.get('service', 'unknown')})",
                        severity=Severity.MEDIUM,
                        entity_id=ip_entity.id, entity_name=ip_entity.name,
                    ))
                    count += 1

            domains_on_ip = self.graph.get_domains_on_ip(ip_entity.name)
            if len(domains_on_ip) > 20:
                self.graph.penalize_entity(ip_entity.id, Anomaly(
                    code="IP_SHARED_HOSTING",
                    title="High-Density Shared Hosting",
                    detail=f"{len(domains_on_ip)} domains on {ip_entity.name} — shared hosting with unknown neighbors",
                    severity=Severity.LOW,
                    entity_id=ip_entity.id, entity_name=ip_entity.name,
                ))
                count += 1

        return count

    def _check_patterns(self) -> int:
        count = 0

        for spki, cert_ids in self.graph._spki_index.items():
            if len(cert_ids) < 2:
                continue
            cert_entities = [self.graph.get_entity(cid) for cid in cert_ids if self.graph.get_entity(cid)]
            domains = list({c.properties.get("common_name", "") for c in cert_entities if c})

            for cert in cert_entities:
                if cert:
                    self.graph.penalize_entity(cert.id, Anomaly(
                        code="CERT_KEY_REUSE",
                        title="Public Key Reused Across Certificates",
                        detail=f"Same keypair (SPKI {spki[:16]}…) used in {len(cert_ids)} certificates — "
                               f"no key rotation across: {', '.join(domains[:5])}",
                        severity=Severity.HIGH,
                        entity_id=cert.id, entity_name=cert.name,
                    ))

                    for other_id in cert_ids:
                        if other_id != cert.id:
                            self.graph.link(
                                cert.id, other_id,
                                RelationType.SHARES_KEY_WITH,
                                source="anomaly_detector",
                            )
                    count += 1

        for domain in self.graph.get_by_type(EntityType.DOMAIN):
            certs = self.graph.successors(domain.id, RelationType.SECURED_BY)
            ca_orgs = {
                c.properties.get("issuer_o", "")
                for c in certs
                if c.properties.get("issuer_o")
            }
            public_cas = {"Let's Encrypt", "DigiCert", "Sectigo", "GlobalSign", "Comodo"}
            if len(ca_orgs) > 3 and bool(ca_orgs - public_cas) and bool(ca_orgs & public_cas):
                self.graph.penalize_entity(domain.id, Anomaly(
                    code="DOMAIN_ISSUER_DIVERSITY",
                    title="Unusual Certificate Issuer Diversity",
                    detail=f"{len(ca_orgs)} different CAs across cert history: {', '.join(sorted(ca_orgs)[:4])}",
                    severity=Severity.MEDIUM,
                    entity_id=domain.id, entity_name=domain.name,
                ))
                count += 1

        for ip, domain_names in self.graph._ip_index.items():
            domain_list = list(domain_names)
            if len(domain_list) < 2:
                continue
            for i in range(len(domain_list)):
                for j in range(i + 1, min(i + 10, len(domain_list))):
                    d1 = self.graph.get_by_name(domain_list[i])
                    d2 = self.graph.get_by_name(domain_list[j])
                    if d1 and d2:
                        self.graph.link(
                            d1.id, d2.id,
                            RelationType.CO_HOSTED_WITH,
                            properties={"shared_ip": ip},
                            source="pattern_detector",
                        )

        return count
