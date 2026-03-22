"""
Email Security Intelligence
Analyzes email security posture for a domain:
  - SPF: presence, policy strictness, +all/~all/?all/-all
  - DMARC: presence, policy (none/quarantine/reject), pct, rua/ruf
  - DKIM: selector discovery + key strength
  - MX: open relay indicators, null MX
  - Email spoofing risk scoring
"""
from __future__ import annotations
import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple

from argus.ontology.entities import (
    Anomaly, EntityType, Severity,
)
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.email_security")

DKIM_SELECTORS = [
    "default", "google", "k1", "k2", "mail", "dkim", "email",
    "smtp", "selector1", "selector2", "s1", "s2", "key1", "key2",
    "mimecast", "proofpoint", "mailchimp", "sendgrid", "ses",
    "mandrill", "postmark", "sparkpost", "mailgun", "zoho",
    "gov", "corp", "primary", "secondary", "mx", "dkim1",
]

class EmailSecurityAnalyzer:
    def __init__(self, dns_correlator, graph: KnowledgeGraph):
        self.dns   = dns_correlator
        self.graph = graph

    async def analyze(self, domain: str) -> Dict:
        try:
            return await asyncio.wait_for(self._analyze_inner(domain), timeout=40)
        except (asyncio.TimeoutError, Exception) as e:
            logger.debug(f"Email analysis timeout/error for {domain}: {e}")
            return {"spf": "timeout", "dmarc": "timeout", "dkim": "timeout",
                    "risk": "UNKNOWN", "domain": domain}

    async def _analyze_inner(self, domain: str) -> Dict:
        """
        Full email security analysis for a domain.
        Returns summary dict and populates graph with anomalies.
        """
        domain_entity = self.graph.get_by_name(domain)

        _spf_pre   = await self._analyze_spf(domain, skip_anomaly=True)
        _dmarc_pre = await self._analyze_dmarc(domain, skip_anomaly=True)
        _skip      = self._calc_spoofing_risk(_spf_pre, _dmarc_pre) == "CRITICAL"

        spf_result, dmarc_result, dkim_results = await asyncio.gather(
            self._analyze_spf(domain, skip_anomaly=_skip),
            self._analyze_dmarc(domain, skip_anomaly=_skip),
            self._discover_dkim(domain),
            return_exceptions=True,
        )

        if isinstance(spf_result,   Exception): spf_result   = {}
        if isinstance(dmarc_result, Exception): dmarc_result = {}
        if isinstance(dkim_results, Exception): dkim_results = []

        spoofing_risk = self._calc_spoofing_risk(spf_result, dmarc_result)

        summary = {
            "spf":           spf_result,
            "dmarc":         dmarc_result,
            "dkim_selectors": dkim_results,
            "spoofing_risk": spoofing_risk,
        }

        if domain_entity:
            domain_entity.properties["email_security"] = {
                "spf_policy":    spf_result.get("policy", "missing"),
                "dmarc_policy":  dmarc_result.get("policy", "missing"),
                "dkim_found":    len(dkim_results),
                "spoofing_risk": spoofing_risk,
            }

            if spoofing_risk == "CRITICAL":
                self.graph.penalize_entity(domain_entity.id, Anomaly(
                    code="EMAIL_SPOOFING_CRITICAL",
                    title="Domain Can Be Spoofed in Phishing Attacks",
                    detail=f"No SPF, no DMARC — anyone can send email as @{domain}",
                    severity=Severity.CRITICAL,
                    entity_id=domain_entity.id, entity_name=domain,
                ))
            elif spoofing_risk == "HIGH":
                self.graph.penalize_entity(domain_entity.id, Anomaly(
                    code="EMAIL_SPOOFING_HIGH",
                    title="Weak Email Authentication — Spoofing Likely",
                    detail=f"SPF/DMARC misconfigured for {domain} — spoofing may be possible",
                    severity=Severity.HIGH,
                    entity_id=domain_entity.id, entity_name=domain,
                ))

        return summary

    async def analyze_all_subdomains(self, apex_domain: str) -> int:
        """
        Check all discovered subdomains for email security.
        Focus on those with MX records.
        """
        mx_domains = [
            d for d in self.graph.get_by_type(EntityType.DOMAIN)
            if self.graph.successors(d.id)
            and d.name != apex_domain
        ]

        analyzed = 0
        sem = asyncio.Semaphore(10)

        async def analyze_one(d):
            nonlocal analyzed
            async with sem:
                mx = await asyncio.wait_for(self.dns._doh(d.name, "MX"), timeout=12)
                if mx:
                    await self.analyze(d.name)
                    analyzed += 1

        await asyncio.gather(*[analyze_one(d) for d in mx_domains[:20]], return_exceptions=True)
        return analyzed

    async def _analyze_spf(self, domain: str, skip_anomaly: bool = False) -> Dict:
        result: Dict = {"domain": domain, "record": None, "policy": "missing",
                        "includes": [], "ip4": [], "ip6": [], "issues": []}

        txt_records = await asyncio.wait_for(self.dns._doh(domain, "TXT"), timeout=12)
        spf_record = None
        for record in txt_records:
            if record.lower().startswith("v=spf1"):
                spf_record = record
                break

        if not spf_record:
            result["issues"].append("No SPF record found")
            domain_entity = self.graph.get_by_name(domain)
            if domain_entity:

                existing = [a.code for a in domain_entity.anomalies]
                if not skip_anomaly:
                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                        code="SPF_MISSING",
                        title="No SPF Record",
                        detail=f"Domain {domain} has no SPF record — anyone can send email as @{domain}",
                        severity=Severity.HIGH,
                        entity_id=domain_entity.id, entity_name=domain,
                    ))
            return result

        result["record"] = spf_record

        if "+all" in spf_record or spf_record.strip().endswith(" all"):
            result["policy"] = "+all"
            result["issues"].append("+all: allows ANY server to send — completely open")
            self._spf_anomaly(domain, "SPF_PLUS_ALL",
                              "SPF Record Uses +all — Completely Open",
                              f"SPF '+all' means any server on the internet can send email as @{domain}",
                              Severity.CRITICAL)
        elif "~all" in spf_record:
            result["policy"] = "~all"
            result["issues"].append("~all: softfail — email will be marked but not rejected")
            self._spf_anomaly(domain, "SPF_SOFTFAIL",
                              "SPF SoftFail (~all) — Spoofing Possible",
                              f"~all only marks suspicious mail but doesn't block it. "
                              f"Combined with no DMARC enforcement, spoofing is likely.",
                              Severity.MEDIUM)
        elif "?all" in spf_record:
            result["policy"] = "?all"
            result["issues"].append("?all: neutral — no enforcement")
            self._spf_anomaly(domain, "SPF_NEUTRAL",
                              "SPF Neutral (?all) — No Enforcement",
                              "?all provides no protection — same as no SPF for deliverability",
                              Severity.HIGH)
        elif "-all" in spf_record:
            result["policy"] = "-all"
        else:
            result["policy"] = "unknown"

        includes = re.findall(r"include:([^\s]+)", spf_record)
        result["includes"] = includes
        lookups = len(includes) + len(re.findall(r"(?:a|mx|ptr|exists|redirect):", spf_record))
        if lookups > 10:
            self._spf_anomaly(domain, "SPF_TOO_MANY_LOOKUPS",
                              "SPF Record Exceeds 10 DNS Lookup Limit",
                              f"{lookups} lookups found — SPF will permerror and fail",
                              Severity.MEDIUM)

        return result

    async def _analyze_dmarc(self, domain: str, skip_anomaly: bool = False) -> Dict:
        result: Dict = {"domain": domain, "record": None, "policy": "missing",
                        "pct": 100, "rua": [], "ruf": [], "issues": []}

        txt_records = await asyncio.wait_for(self.dns._doh(f"_dmarc.{domain}", "TXT"), timeout=12)
        dmarc_record = None
        for record in txt_records:
            if record.lower().startswith("v=dmarc1"):
                dmarc_record = record
                break

        if not dmarc_record:
            result["issues"].append("No DMARC record found")
            domain_entity = self.graph.get_by_name(domain)
            if domain_entity:
                if not skip_anomaly:
                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                        code="DMARC_MISSING",
                        title="No DMARC Record",
                        detail=f"Domain {domain} has no DMARC record — email authentication not enforced",
                        severity=Severity.HIGH,
                        entity_id=domain_entity.id, entity_name=domain,
                    ))
            return result

        result["record"] = dmarc_record

        p_match = re.search(r"\bp=(\w+)", dmarc_record, re.IGNORECASE)
        if p_match:
            result["policy"] = p_match.group(1).lower()
            if result["policy"] == "none":
                self._dmarc_anomaly(domain, "DMARC_POLICY_NONE",
                                    "DMARC Policy is 'none' — Monitoring Only",
                                    "p=none means DMARC only monitors — no emails are rejected or quarantined",
                                    Severity.HIGH)
            elif result["policy"] == "quarantine":
                pct_m = re.search(r"\bpct=(\d+)", dmarc_record, re.IGNORECASE)
                pct = int(pct_m.group(1)) if pct_m else 100
                result["pct"] = pct
                if pct < 100:
                    self._dmarc_anomaly(domain, "DMARC_PARTIAL_ENFORCEMENT",
                                        f"DMARC Quarantine Only {pct}% of Mail",
                                        f"pct={pct} means {100-pct}% of spoofed mail bypasses DMARC",
                                        Severity.MEDIUM)

        rua_match = re.findall(r"rua=([^;]+)", dmarc_record, re.IGNORECASE)
        if not rua_match:
            result["issues"].append("No rua (aggregate reports) configured")
        else:
            result["rua"] = rua_match

        return result

    async def _discover_dkim(self, domain: str) -> List[Dict]:
        """Probe common DKIM selectors."""
        found = []
        sem = asyncio.Semaphore(15)

        async def probe_selector(selector: str):
            async with sem:
                try:
                    query = f"{selector}._domainkey.{domain}"
                    txt_records = await asyncio.wait_for(self.dns._doh(query, "TXT"), timeout=12)
                    for record in txt_records:
                        if "v=dkim1" in record.lower() or "k=rsa" in record.lower() or "p=" in record.lower():

                            key_size = self._estimate_dkim_key_size(record)
                            entry = {"selector": selector, "record": record[:200], "key_size": key_size}
                            found.append(entry)
                            if key_size and key_size < 2048:
                                domain_entity = self.graph.get_by_name(domain)
                                if domain_entity:
                                    self.graph.penalize_entity(domain_entity.id, Anomaly(
                                        code="DKIM_WEAK_KEY",
                                        title=f"Weak DKIM Key: {key_size} bits",
                                        detail=f"Selector '{selector}' uses {key_size}-bit key — "
                                               f"recommended minimum is 2048 bits",
                                        severity=Severity.MEDIUM,
                                        entity_id=domain_entity.id, entity_name=domain,
                                    ))
                            break
                except Exception:
                    pass

        await asyncio.gather(*[probe_selector(s) for s in DKIM_SELECTORS], return_exceptions=True)
        return found

    def _estimate_dkim_key_size(self, record: str) -> Optional[int]:
        """Estimate key size from base64 public key length in DKIM record."""
        p_match = re.search(r"p=([A-Za-z0-9+/=]+)", record)
        if not p_match:
            return None
        b64_key = p_match.group(1).replace(" ", "")

        key_len = len(b64_key)
        if key_len < 200:
            return 1024
        elif key_len < 400:
            return 2048
        else:
            return 4096

    def _calc_spoofing_risk(self, spf: Dict, dmarc: Dict) -> str:
        spf_policy   = spf.get("policy", "missing")
        dmarc_policy = dmarc.get("policy", "missing")

        if spf_policy == "missing" and dmarc_policy == "missing":
            return "CRITICAL"
        if spf_policy in ("+all", "?all", "missing"):
            return "HIGH" if dmarc_policy in ("reject", "quarantine") else "CRITICAL"
        if dmarc_policy in ("none", "missing"):
            return "HIGH"
        if spf_policy == "~all" and dmarc_policy == "none":
            return "HIGH"
        if dmarc_policy == "quarantine" and dmarc.get("pct", 100) < 100:
            return "MEDIUM"
        return "LOW"

    def _spf_anomaly(self, domain, code, title, detail, severity):
        entity = self.graph.get_by_name(domain)
        if entity:
            self.graph.penalize_entity(entity.id, Anomaly(
                code=code, title=title, detail=detail, severity=severity,
                entity_id=entity.id, entity_name=domain,
            ))

    def _dmarc_anomaly(self, domain, code, title, detail, severity):
        key = f"{domain}:{code}"
        if key in self._seen_codes:
            return
        self._seen_codes.add(key)
        entity = self.graph.get_by_name(domain)
        if entity:
            self.graph.penalize_entity(entity.id, Anomaly(
                code=code, title=title, detail=detail, severity=severity,
                entity_id=entity.id, entity_name=domain,
            ))
