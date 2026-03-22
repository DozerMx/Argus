"""
Compliance Mapping Engine
Maps every anomaly to its specific violation in:
  - OWASP Top 10 (2021)
  - GDPR (EU 2016/679)
  - ISO/IEC 27001:2022
  - NIST CSF 2.0
  - PCI-DSS v4.0
  - CIS Controls v8

Each finding gets tagged with the exact article/control/requirement
it violates — enabling direct use in security assessment reports.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from argus.ontology.graph import KnowledgeGraph
from argus.ontology.entities import EntityType

@dataclass
class ComplianceViolation:
    framework:   str
    ref:         str
    title:       str
    description: str
    anomaly_codes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "framework":   self.framework,
            "ref":         self.ref,
            "title":       self.title,
            "description": self.description,
        }

COMPLIANCE_MAP: Dict[str, List[ComplianceViolation]] = {

    "CERT_EXPIRED": [
        ComplianceViolation("OWASP Top 10 2021", "A02:2021",
            "Cryptographic Failures",
            "Expired certificates indicate failure to maintain cryptographic controls"),
        ComplianceViolation("ISO 27001:2022", "A.8.24",
            "Use of Cryptography",
            "Controls require certificates to be valid and properly managed"),
        ComplianceViolation("NIST CSF 2.0", "PR.DS-02",
            "Data-in-Transit Protection",
            "Expired certificates compromise integrity of data-in-transit protection"),
        ComplianceViolation("PCI-DSS v4.0", "4.2.1",
            "Strong Cryptography for Cardholder Data Transmission",
            "Certificates must be valid; expired certs violate PCI-DSS 4.2.1"),
    ],
    "CERT_SELF_SIGNED": [
        ComplianceViolation("OWASP Top 10 2021", "A02:2021",
            "Cryptographic Failures",
            "Self-signed certificates are not trusted and indicate poor PKI management"),
        ComplianceViolation("ISO 27001:2022", "A.8.24",
            "Use of Cryptography",
            "Certificates must be issued by trusted CAs to ensure authenticity"),
        ComplianceViolation("PCI-DSS v4.0", "4.2.1",
            "Strong Cryptography",
            "Self-signed certs are not considered trusted for cardholder data transmission"),
    ],
    "CERT_WEAK_KEY": [
        ComplianceViolation("OWASP Top 10 2021", "A02:2021",
            "Cryptographic Failures",
            "Weak key sizes are insufficient for current cryptographic standards"),
        ComplianceViolation("NIST CSF 2.0", "PR.DS-02",
            "Data-in-Transit Protection",
            "NIST SP 800-57 requires minimum RSA-2048 / EC-224"),
        ComplianceViolation("PCI-DSS v4.0", "4.2.1",
            "Strong Cryptography",
            "PCI-DSS requires minimum 2048-bit RSA keys"),
    ],

    "TLS_SSLV3_ENABLED": [
        ComplianceViolation("OWASP Top 10 2021", "A02:2021",
            "Cryptographic Failures — POODLE",
            "SSLv3 is vulnerable to POODLE attack (CVE-2014-3566)"),
        ComplianceViolation("PCI-DSS v4.0", "4.2.1",
            "Strong Cryptography Required",
            "PCI-DSS explicitly prohibits SSLv3 — early TLS protocols are banned"),
        ComplianceViolation("ISO 27001:2022", "A.8.24",
            "Use of Cryptography",
            "SSLv3 must not be used; deprecated and known-broken protocol"),
        ComplianceViolation("NIST CSF 2.0", "PR.DS-02",
            "Data-in-Transit Protection",
            "NIST SP 800-52r2 prohibits SSLv3"),
    ],
    "TLS_1_0_ENABLED": [
        ComplianceViolation("PCI-DSS v4.0", "4.2.1",
            "Strong Cryptography — TLS 1.0 Prohibited",
            "PCI-DSS v4.0 prohibits TLS 1.0 since June 2018"),
        ComplianceViolation("OWASP Top 10 2021", "A02:2021",
            "Cryptographic Failures — BEAST",
            "TLS 1.0 vulnerable to BEAST attack (CVE-2011-3389)"),
        ComplianceViolation("ISO 27001:2022", "A.8.24",
            "Use of Cryptography",
            "TLS 1.0 deprecated per RFC 8996 (2021)"),
    ],
    "TLS_1_1_ENABLED": [
        ComplianceViolation("PCI-DSS v4.0", "4.2.1",
            "Strong Cryptography — TLS 1.1 Prohibited",
            "TLS 1.1 deprecated per RFC 8996; not acceptable for cardholder data"),
        ComplianceViolation("ISO 27001:2022", "A.8.24",
            "Use of Cryptography",
            "TLS 1.1 deprecated per RFC 8996 (2021)"),
    ],
    "TLS_CRIME_COMPRESSION": [
        ComplianceViolation("OWASP Top 10 2021", "A02:2021",
            "Cryptographic Failures — CRIME",
            "TLS compression enables CRIME attack (CVE-2012-4929)"),
    ],
    "TLS_NO_FORWARD_SECRECY": [
        ComplianceViolation("NIST CSF 2.0", "PR.DS-02",
            "Data-in-Transit Protection",
            "Forward secrecy required per NIST SP 800-52r2"),
        ComplianceViolation("ISO 27001:2022", "A.8.24",
            "Use of Cryptography",
            "Forward secrecy recommended to protect past sessions"),
    ],

    "MISSING_HSTS": [
        ComplianceViolation("OWASP Top 10 2021", "A05:2021",
            "Security Misconfiguration",
            "Missing HSTS allows protocol downgrade attacks"),
        ComplianceViolation("OWASP Top 10 2021", "A02:2021",
            "Cryptographic Failures",
            "Without HSTS, HTTPS connections can be downgraded to HTTP"),
    ],
    "MISSING_CSP": [
        ComplianceViolation("OWASP Top 10 2021", "A03:2021",
            "Injection — XSS Prevention",
            "Content Security Policy prevents XSS and data injection attacks"),
    ],
    "MISSING_X-FRAME-OPTIONS": [
        ComplianceViolation("OWASP Top 10 2021", "A05:2021",
            "Security Misconfiguration — Clickjacking",
            "Missing X-Frame-Options enables clickjacking/UI redress attacks"),
    ],
    "HTTP_NO_HTTPS_REDIRECT": [
        ComplianceViolation("OWASP Top 10 2021", "A02:2021",
            "Cryptographic Failures",
            "HTTP without redirect allows plaintext transmission of sensitive data"),
        ComplianceViolation("GDPR", "Art. 32",
            "Security of Processing",
            "GDPR requires appropriate technical measures including encryption in transit"),
        ComplianceViolation("PCI-DSS v4.0", "4.2.1",
            "Strong Cryptography for Transmission",
            "All cardholder data transmission must use strong cryptography"),
    ],

    "CONTENT_DISCOVERED": [
        ComplianceViolation("OWASP Top 10 2021", "A01:2021",
            "Broken Access Control",
            "Sensitive paths accessible without authentication violate access control"),
        ComplianceViolation("ISO 27001:2022", "A.8.3",
            "Information Access Restriction",
            "Access to sensitive information must be restricted per need-to-know"),
        ComplianceViolation("NIST CSF 2.0", "PR.AA-05",
            "Access Permissions and Authorizations",
            "Unnecessary exposure of admin/config interfaces violates least-privilege"),
    ],
    "GIT_REPO_FULLY_EXPOSED": [
        ComplianceViolation("OWASP Top 10 2021", "A01:2021",
            "Broken Access Control",
            "Full source code exposure via git repository"),
        ComplianceViolation("OWASP Top 10 2021", "A05:2021",
            "Security Misconfiguration",
            "Development artifacts must not be deployed to production"),
        ComplianceViolation("GDPR", "Art. 32",
            "Security of Processing",
            "Source code may contain personal data processing logic and credentials"),
        ComplianceViolation("ISO 27001:2022", "A.8.9",
            "Configuration Management",
            "Configuration files must be protected and not publicly accessible"),
    ],

    "JS_SECRET_EXPOSED": [
        ComplianceViolation("OWASP Top 10 2021", "A02:2021",
            "Cryptographic Failures — Hardcoded Secrets",
            "Credentials in client-side code are a critical security failure"),
        ComplianceViolation("OWASP Top 10 2021", "A07:2021",
            "Identification and Authentication Failures",
            "Exposed API keys and tokens compromise authentication mechanisms"),
        ComplianceViolation("GDPR", "Art. 32",
            "Security of Processing",
            "Exposed credentials may lead to unauthorized access to personal data"),
        ComplianceViolation("ISO 27001:2022", "A.8.13",
            "Information Backup",
            "Secrets management must prevent credential exposure in any medium"),
        ComplianceViolation("PCI-DSS v4.0", "6.3.3",
            "Security Vulnerabilities Addressed",
            "Payment credentials must never appear in client-accessible code"),
    ],

    "SPF_MISSING": [
        ComplianceViolation("OWASP Top 10 2021", "A05:2021",
            "Security Misconfiguration",
            "Missing SPF record enables email spoofing from the domain"),
        ComplianceViolation("ISO 27001:2022", "A.8.22",
            "Filtering of Network Services",
            "Email authentication records are required to prevent domain spoofing"),
        ComplianceViolation("NIST CSF 2.0", "PR.PS-01",
            "Configuration Management",
            "Email security configuration (SPF/DMARC) is a baseline requirement"),
    ],
    "DMARC_MISSING": [
        ComplianceViolation("OWASP Top 10 2021", "A05:2021",
            "Security Misconfiguration",
            "Missing DMARC enables phishing attacks using the domain"),
        ComplianceViolation("NIST CSF 2.0", "PR.PS-01",
            "Configuration Management",
            "DMARC policy required to prevent email-based phishing"),
        ComplianceViolation("CIS Controls v8", "9.5",
            "Implement DMARC",
            "CIS Control 9.5 requires DMARC deployment for all domains"),
    ],
    "EMAIL_SPOOFING_CRITICAL": [
        ComplianceViolation("GDPR", "Art. 32",
            "Security of Processing",
            "Lack of email authentication enables phishing that can lead to data breaches"),
        ComplianceViolation("ISO 27001:2022", "A.6.8",
            "Information Security Event Reporting",
            "Domains enabling spoofing create vectors for undetected social engineering"),
    ],

    "SUBDOMAIN_TAKEOVER": [
        ComplianceViolation("OWASP Top 10 2021", "A01:2021",
            "Broken Access Control — Subdomain Takeover",
            "Attacker gains full control of subdomain — serves arbitrary content on trusted domain"),
        ComplianceViolation("ISO 27001:2022", "A.8.9",
            "Configuration Management",
            "Dangling DNS records must be removed to prevent domain hijacking"),
        ComplianceViolation("GDPR", "Art. 32",
            "Security of Processing",
            "Subdomain takeover can expose users' personal data to attackers"),
    ],
    "DOMAIN_STAGING_EXPOSED": [
        ComplianceViolation("OWASP Top 10 2021", "A05:2021",
            "Security Misconfiguration",
            "Non-production environments should not be publicly accessible"),
        ComplianceViolation("ISO 27001:2022", "A.8.31",
            "Separation of Development, Test and Production Environments",
            "Staging/dev environments must be separated from internet access"),
    ],

    "INSECURE_COOKIE": [
        ComplianceViolation("OWASP Top 10 2021", "A02:2021",
            "Cryptographic Failures",
            "Cookies without Secure flag can be sent over HTTP"),
        ComplianceViolation("OWASP Top 10 2021", "A07:2021",
            "Identification and Authentication Failures",
            "Session cookies must have HttpOnly and Secure flags"),
        ComplianceViolation("GDPR", "Art. 32",
            "Security of Processing",
            "Session management must implement appropriate security measures"),
    ],

    "CORS_WILDCARD": [
        ComplianceViolation("OWASP Top 10 2021", "A01:2021",
            "Broken Access Control",
            "CORS wildcard allows any origin to make cross-origin requests"),
    ],
    "CORS_REFLECTED_ORIGIN_WITH_CREDENTIALS": [
        ComplianceViolation("OWASP Top 10 2021", "A01:2021",
            "Broken Access Control — CORS Misconfiguration",
            "Reflected Origin with credentials enables cross-origin authenticated requests from any site"),
        ComplianceViolation("OWASP Top 10 2021", "A05:2021",
            "Security Misconfiguration",
            "CORS must be explicitly configured with trusted origins only"),
    ],
    "OPEN_REDIRECT": [
        ComplianceViolation("OWASP Top 10 2021", "A01:2021",
            "Broken Access Control — Unvalidated Redirects",
            "Open redirects facilitate phishing using trusted domain URLs"),
        ComplianceViolation("OWASP Top 10 2021", "A10:2021",
            "Server-Side Request Forgery (SSRF)",
            "Open redirects can be chained with SSRF vulnerabilities"),
    ],

    "IP_SENSITIVE_PORT": [
        ComplianceViolation("OWASP Top 10 2021", "A05:2021",
            "Security Misconfiguration",
            "Database and admin ports must not be exposed to the internet"),
        ComplianceViolation("ISO 27001:2022", "A.8.22",
            "Filtering of Network Services",
            "Network filtering must block access to sensitive management ports"),
        ComplianceViolation("CIS Controls v8", "4.4",
            "Implement and Manage Network Firewall",
            "CIS Control 4.4 requires blocking unauthorized port access"),
        ComplianceViolation("PCI-DSS v4.0", "1.3.2",
            "Network Access Controls",
            "All network traffic must be restricted to business-necessary communications"),
    ],
    "BANNER_VULNERABLE_VERSION": [
        ComplianceViolation("OWASP Top 10 2021", "A06:2021",
            "Vulnerable and Outdated Components",
            "Outdated software versions contain known exploitable vulnerabilities"),
        ComplianceViolation("ISO 27001:2022", "A.8.8",
            "Management of Technical Vulnerabilities",
            "Vulnerability management must include timely patching of known CVEs"),
        ComplianceViolation("NIST CSF 2.0", "ID.RA-01",
            "Vulnerabilities in Assets Identified",
            "Asset vulnerabilities must be identified and remediated"),
        ComplianceViolation("PCI-DSS v4.0", "6.3.3",
            "All System Components Protected from Known Vulnerabilities",
            "All components must have security patches within defined timeframes"),
    ],
    "ORIGIN_IP_LEAKED": [
        ComplianceViolation("OWASP Top 10 2021", "A05:2021",
            "Security Misconfiguration",
            "Origin IP disclosure bypasses CDN/WAF protections, exposing real server"),
        ComplianceViolation("ISO 27001:2022", "A.8.22",
            "Filtering of Network Services",
            "Network architecture must not allow bypass of security controls"),
    ],
}

class ComplianceMapper:
    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph

    def map_all(self) -> Dict:
        """
        Map all anomalies in the graph to compliance violations.
        Returns structured report organized by framework.
        """
        by_framework: Dict[str, List[Dict]] = {}
        by_anomaly:   Dict[str, List[Dict]] = {}
        total_violations = 0
        violated_frameworks: Set[str] = set()

        for anomaly in self.graph.all_anomalies:
            violations = COMPLIANCE_MAP.get(anomaly.code, [])
            if not violations:
                continue

            anomaly_key = anomaly.code
            if anomaly_key not in by_anomaly:
                by_anomaly[anomaly_key] = []

            for v in violations:
                violated_frameworks.add(v.framework)
                total_violations += 1

                v_dict = {
                    **v.to_dict(),
                    "anomaly_code":   anomaly.code,
                    "entity_name":    anomaly.entity_name,
                    "anomaly_detail": anomaly.detail[:150],
                    "severity":       anomaly.severity.value,
                }

                by_anomaly[anomaly_key].append(v_dict)

                fw = v.framework
                if fw not in by_framework:
                    by_framework[fw] = []
                by_framework[fw].append(v_dict)

        for fw in by_framework:
            seen_refs: Set[str] = set()
            deduped = []
            for item in by_framework[fw]:
                key = f"{item['ref']}:{item['anomaly_code']}"
                if key not in seen_refs:
                    seen_refs.add(key)
                    deduped.append(item)
            by_framework[fw] = sorted(deduped, key=lambda x: x["severity"])

        return {
            "total_violations":    total_violations,
            "violated_frameworks": sorted(violated_frameworks),
            "by_framework":        by_framework,
            "by_anomaly":          by_anomaly,
            "summary": {
                fw: len(items)
                for fw, items in by_framework.items()
            },
        }

    def owasp_top10_coverage(self) -> Dict[str, int]:
        """Count violations per OWASP Top 10 category."""
        counts: Dict[str, int] = {}
        for anomaly in self.graph.all_anomalies:
            for v in COMPLIANCE_MAP.get(anomaly.code, []):
                if "OWASP" in v.framework:
                    counts[v.ref] = counts.get(v.ref, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))
