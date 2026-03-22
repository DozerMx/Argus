"""
Argus v3.4 — Maximum Coverage Engine
Argus scan engine. Runs all intelligence modules in sequence.
"""
from __future__ import annotations
import asyncio
import logging
from datetime import datetime, timezone

from argus.ontology.entities import EntityType
from argus.ontology.graph import KnowledgeGraph
from argus.ontology.pivot import PivotEngine
from argus.utils.config import Config
from argus.utils.cache import DiskCache
from argus.utils.http_client import HTTPClient
from argus.utils.rate_limiter import PerHostRateLimiter, RetryHandler
from argus.sources.ct_source import CTLogSource
from argus.sources.brute import SubdomainBruter
from argus.correlators.dns import DNSCorrelator
from argus.correlators.cdn_bypass import CDNBypassEngine
from argus.correlators.port_scanner import PortScanner
from argus.intelligence.asn_intel import ASNIntel
from argus.intelligence.anomaly import AnomalyDetector
from argus.intelligence.http_intel import HTTPIntelligence
from argus.intelligence.email_security import EmailSecurityAnalyzer
from argus.intelligence.reverse_ip import ReverseIPIntel
from argus.intelligence.jarm import JARMFingerprinter
from argus.intelligence.js_scanner import JSScanner
from argus.intelligence.content_discovery import ContentDiscovery
from argus.intelligence.tls_analysis import TLSAnalyzer
from argus.intelligence.osint import WaybackMachine, CloudAssetDetector, ActiveMisconfigDetector
from argus.intelligence.attack_paths import AttackPathEngine
from argus.intelligence.compliance import ComplianceMapper
from argus.intelligence.scan_diff import ScanSnapshot, ScanDiffer
from argus.intelligence.ipv6 import IPv6Intel
from argus.intelligence.supply_chain import SupplyChainAnalyzer
from argus.intelligence.advanced_probes import AdvancedProbes, CVSSScorer
from argus.intelligence.daemon import TemplateEngine
from argus.intelligence.cve_intel import CVEIntel

logger = logging.getLogger("argus.core")

class ArgusEngine:
    def __init__(self, config: Config, renderer):
        self.config   = config
        self.renderer = renderer
        self.cache    = DiskCache(ttl=config.cache_ttl, enabled=config.cache)
        self.http     = HTTPClient(
            timeout=config.timeout, proxy=config.proxy,
            rate_limiter=PerHostRateLimiter(global_delay=config.delay),
            retry_handler=RetryHandler(),
        )
        self.graph = KnowledgeGraph()
        self.pivot = PivotEngine(self.graph)

        self.ct_source    = CTLogSource(self.http, self.cache, self.graph)
        self.dns          = DNSCorrelator(self.http, self.cache, self.graph, timeout=config.timeout)
        self.bruter       = SubdomainBruter(self.dns, self.graph, concurrency=config.brute_concurrency)

        self.asn_intel    = ASNIntel(self.dns, self.graph)
        self.cdn_bypass   = CDNBypassEngine(self.http, self.dns, self.graph)
        self.port_scanner = PortScanner(self.graph, timeout=max(1.0, config.timeout/3),
                                         concurrency=config.port_concurrency)
        self.ipv6_intel   = IPv6Intel(self.dns, self.graph)

        self.http_intel    = HTTPIntelligence(self.http, self.dns, self.graph, timeout=config.timeout)
        self.email_sec     = EmailSecurityAnalyzer(self.dns, self.graph)
        self.reverse_ip    = ReverseIPIntel(self.http, self.dns, self.graph)
        self.jarm          = JARMFingerprinter(self.graph, timeout=max(2.0, config.timeout/2))
        self.js_scanner    = JSScanner(self.http, self.graph, timeout=config.timeout)
        self.content_disc  = ContentDiscovery(self.http, self.graph, timeout=config.timeout)
        self.tls_analyzer  = TLSAnalyzer(self.graph, timeout=max(3.0, config.timeout/2))
        self.wayback       = WaybackMachine(self.http, self.graph)
        self.cloud_detect  = CloudAssetDetector(self.http, self.dns, self.graph)
        self.misconfig     = ActiveMisconfigDetector(self.http, self.graph)
        self.supply_chain  = SupplyChainAnalyzer(self.http, self.graph, timeout=config.timeout)
        self.adv_probes    = AdvancedProbes(self.http, self.dns, self.graph, timeout=config.timeout)
        self.templates     = TemplateEngine(self.http, self.graph)
        self.cvss_scorer   = CVSSScorer()
        self.anomaly_det   = AnomalyDetector(self.graph)

    async def run(self, domain: str) -> "ScanResult":
        domain     = domain.lower().strip()
        N          = getattr(self, '_total_phases', 33)
        scan_start = datetime.now(timezone.utc).replace(tzinfo=None)
        previous   = ScanSnapshot.load_latest(domain) if self.config.diff else None

        from argus.correlators.dns import clear_scan_dns_cache
        from argus.utils.request_cache import clear_all as clear_request_cache, reset_global_sem
        clear_scan_dns_cache()
        clear_request_cache()
        reset_global_sem(200)

        async with self.http:

            self.renderer.phase(1, N, "Certificate Transparency log collection")
            certs = await self.ct_source.collect(domain)
            self.renderer.success(f"Collected {certs} certs → {len(self.graph.get_by_type(EntityType.DOMAIN))} domains")

            self.renderer.phase(2, N, "Passive subdomain discovery (HackerTarget)")
            extra = await self._passive_discovery(domain)
            self.renderer.success(f"Passive DNS: +{extra} subdomains")

            if self.config.axfr:
                self.renderer.phase(3, N, "DNS Zone Transfer (AXFR)")
                axfr = await self.bruter.axfr_attempt(domain)
                self.renderer.warning(f"AXFR SUCCESS — {len(axfr)} records!") if axfr else self.renderer.info("AXFR refused")
            else:
                self.renderer.phase(3, N, "AXFR skipped (--axfr)")

            if self.config.brute:
                self.renderer.phase(4, N, "Subdomain brute force + permutation engine")
                known = [d.name for d in self.graph.get_by_type(EntityType.DOMAIN)]
                found = await self.bruter.brute_force(domain, known_subdomains=known)
                self.renderer.success(f"Brute force: +{found} subdomains")
            else:
                self.renderer.phase(4, N, "Brute force skipped (--brute)")

            self.renderer.phase(5, N, "DNS resolution + IPv6 AAAA (parallel)")
            alive, ipv6_r = await asyncio.gather(
                self.dns.resolve_all_domains(concurrency=self.config.threads),
                self.ipv6_intel.run(),
            )
            total_d = len(self.graph.get_by_type(EntityType.DOMAIN))
            total_i = len(self.graph.get_by_type(EntityType.IP))
            self.renderer.success(
                f"{alive}/{total_d} alive → {total_i} IPs | "
                f"IPv6: {ipv6_r['ipv6_addresses_found']} addrs — "
                f"{ipv6_r['cdn_bypass_candidates']} CDN bypass"
            )
            self.renderer.phase(6, N, "(parallel — completed in phase 5)")

            if self.config.deep:
                self.renderer.phase(7, N, "ASN intelligence + Cloud provider identification")
                await self.asn_intel.enrich_all_ips()
                cloud_n = await self.cloud_detect.run()
                cdn_n   = sum(1 for ip in self.graph.get_by_type(EntityType.IP) if ip.properties.get("is_cdn"))
                self.renderer.success(f"ASN: {total_i} enriched — {cdn_n} CDN — {cloud_n} cloud")
            else:
                self.renderer.phase(7, N, "ASN/Cloud skipped (--deep)")

            if self.config.cdn_bypass:
                self.renderer.phase(8, N, "CDN origin IP discovery")
                origins = await self.cdn_bypass.run(domain)
                self.renderer.success(f"CDN bypass: {origins} origin IP(s)")
            else:
                self.renderer.phase(8, N, "CDN bypass skipped (--cdn-bypass)")

            if self.config.ports:
                self.renderer.phase(9, N, "Async TCP port scan + service banner grab")
                open_p = await self.port_scanner.scan_all_ips()
                self.renderer.success(f"Port scan: {open_p} open ports")
            else:
                self.renderer.phase(9, N, "Port scan skipped (--ports)")

            self.renderer.phase(10, N, "TLS + HTTP + Content + JS (parallel execution)")
            tls_r, http_r, content_r, js_r = await asyncio.gather(
                self.tls_analyzer.run(),
                self.http_intel.run(domain),
                self.content_disc.run(),
                self.js_scanner.run(),
                return_exceptions=False,
            )
            self.renderer.success(
                f"TLS: {tls_r['tls_vulnerabilities']} vulns | "
                f"HTTP: {http_r['probed']} probed | "
                f"Content: {content_r['paths_found']} paths | "
                f"JS: {js_r['secrets_found']} secrets"
            )

            self.renderer.phase(11, N, "(parallel — see phase 10)")
            self.renderer.phase(12, N, "(parallel — see phase 10)")
            self.renderer.phase(13, N, "(parallel — see phase 10)")

            self.renderer.phase(14, N, "Supply chain + Advanced probes + Templates + Misconfigs (parallel)")
            sc_r, adv_r, tmpl_r, misc_r = await asyncio.gather(
                self.supply_chain.run(),
                self.adv_probes.run(),
                self.templates.run(),
                self.misconfig.run(),
            )
            self.renderer.success(
                f"Supply: {sc_r['vulnerable_libs']} vuln libs | "
                f"Advanced: {adv_r['cache_poison']} cache/{adv_r['websocket']} WS | "
                f"Templates: {tmpl_r['template_hits']} hits | "
                f"Misconfigs: {misc_r['cors']} CORS/{misc_r['open_redirect']} redirect"
            )
            self.renderer.phase(15, N, "(parallel — see phase 14)")
            self.renderer.phase(16, N, "(parallel — see phase 14)")
            self.renderer.phase(17, N, "(parallel — see phase 14)")

            self.renderer.phase(18, N, "Email security (SPF, DMARC, DKIM)")
            try:
                email_r = await asyncio.wait_for(self.email_sec.analyze(domain), timeout=30)
            except asyncio.TimeoutError:
                email_r = {"spf": "timeout", "dmarc": "timeout", "risk": "UNKNOWN"}
                logger.warning("Email security analysis timed out")
            spoof    = email_r.get("spoofing_risk", "UNKNOWN")
            spf_val  = email_r.get("spf",   {})
            dmarc_val= email_r.get("dmarc", {})
            spf_pol  = spf_val.get("policy",  "?") if isinstance(spf_val,  dict) else str(spf_val)
            dmarc_pol= dmarc_val.get("policy","?") if isinstance(dmarc_val,dict) else str(dmarc_val)
            self.renderer.success(f"Email: SPF={spf_pol} DMARC={dmarc_pol} risk={spoof}")

            if self.config.deep:
                self.renderer.phase(19, N, "Wayback Machine historical endpoint discovery")
                wb_r = await self.wayback.discover(domain)
                self.renderer.success(f"Wayback: {wb_r['urls_found']} URLs — {wb_r.get('interesting',0)} sensitive")
            else:
                self.renderer.phase(19, N, "Wayback skipped (--deep)")

            if self.config.deep:
                self.renderer.phase(20, N, "Reverse IP enrichment + banner vulnerability analysis")
                rev_r = await self.reverse_ip.run(domain)
                self.renderer.success(f"Reverse IP: {rev_r['reverse_ip_domains']} neighbors — {rev_r['vulnerable_banners']} vuln banners")
            else:
                self.renderer.phase(20, N, "Reverse IP skipped (--deep)")

            if self.config.jarm:
                self.renderer.phase(21, N, "JARM TLS fingerprinting (C2/malware detection)")
                jarm_n = await self.jarm.run()
                self.renderer.success(f"JARM: {jarm_n} hosts fingerprinted")
            else:
                self.renderer.phase(21, N, "JARM skipped (--jarm)")

            self.renderer.phase(22, N, "Anomaly detection + pattern analysis")
            self.anomaly_det.run_all()
            all_a    = self.graph.all_anomalies
            critical = sum(1 for a in all_a if a.severity.value == "CRITICAL")
            high     = sum(1 for a in all_a if a.severity.value == "HIGH")
            medium   = sum(1 for a in all_a if a.severity.value == "MEDIUM")
            total_a  = len(all_a)
            self.renderer.warning(f"Anomalies: {total_a} — {critical} CRITICAL, {high} HIGH, {medium} MEDIUM")

            self.renderer.phase(23, N, "CVSS 3.1 auto-scoring")
            cvss_r = self.cvss_scorer.score_all(self.graph)
            self.renderer.success(f"CVSS: {cvss_r['scored']} findings scored")

            self.renderer.phase(24, N, "Attack path synthesis (entry→target chain analysis)")
            attack_engine = AttackPathEngine(self.graph)
            attack_paths  = attack_engine.synthesize()
            attack_dicts  = [p.to_dict() for p in attack_paths]
            if attack_paths:
                self.renderer.warning(f"Attack paths: {len(attack_paths)} — top: [{attack_paths[0].severity}] {attack_paths[0].title[:55]}")
            else:
                self.renderer.success("No exploitable attack chains found")

            self.renderer.phase(25, N, "Compliance mapping (OWASP, GDPR, ISO 27001, NIST, PCI-DSS, CIS)")
            compliance_mapper = ComplianceMapper(self.graph)
            compliance_data   = compliance_mapper.map_all()
            self.renderer.success(f"Compliance: {compliance_data['total_violations']} violations — {', '.join(compliance_data['violated_frameworks'][:3])}")

            self.renderer.phase(26, N, "CVE correlation (embedded DB + NVD API fallback)")
            cve_r = await CVEIntel(self.http, self.graph).run()
            if cve_r["critical"] > 0:
                self.renderer.warning(
                    f"CVE: {cve_r['cves_found']} CVEs matched — "
                    f"{cve_r['critical']} CRITICAL"
                )
            else:
                self.renderer.success(
                    f"CVE: {cve_r['cves_found']} CVEs matched"
                )
            ai_report = None

            self.renderer.phase(27, N, "Graph analytics (centrality, clusters, bridge nodes)")
            stats    = self.graph.stats()

            if stats.get('nodes', 0) <= 200:
                bridges  = self.pivot.bridge_nodes(top_n=5)
                clusters = self.pivot.cluster_analysis()
            else:

                bridges  = self.pivot.bridge_nodes_fast(top_n=5)
                clusters = {}
            self.renderer.success(f"Graph: {stats['nodes']} nodes, {stats['edges']} edges, {stats['components']} clusters, {len(bridges)} bridges")

            diff_data = None
            self.renderer.phase(28, N, "Scan diff (infrastructure change detection)")
            current_snap = ScanSnapshot(domain, self.graph)
            if previous:
                diff_data = ScanDiffer().diff(previous, current_snap)
                d = diff_data["domains"]
                s = diff_data["security"]
                self.renderer.success(f"Diff: +{len(d['appeared'])} new domains, {len(s['new_anomalies'])} new anomaly types")
            else:
                self.renderer.info("No previous snapshot — saved as baseline")
            snap_path = current_snap.save()
            self.renderer.success(f"Snapshot → {snap_path}")

            self.renderer.phase(29, N, "Risk scoring + top findings")
            top_risk = self.pivot.top_risk_entities(top_n=3)
            if top_risk:
                self.renderer.warning("Top risk: " + " | ".join(f"{e.name} ({e.risk_label()})" for e in top_risk))

            self.renderer.phase(30, N, "Report generation")

        return ScanResult(
            graph=self.graph, domain=domain, scan_start=scan_start,
            attack_paths=attack_dicts, compliance=compliance_data,
            ai_report=ai_report, diff_data=diff_data,
        )

    async def _passive_discovery(self, domain: str) -> int:
        try:
            resp = await self.http.get("https://api.hackertarget.com/hostsearch/",
                                   params={"q": domain},
                                   read_limit=512*1024,
                                   use_cache=False)
            if not resp or resp.get("status") != 200:
                return 0
            data = resp.get("data", "")
            if not isinstance(data, str) or "error" in data.lower():
                return 0
            added = 0
            for line in data.splitlines():
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if (sub.endswith(f".{domain}") or sub == domain) and not self.graph.get_by_name(sub):
                        self.graph.find_or_create(EntityType.DOMAIN, name=sub, source="hackertarget")
                        added += 1
            return added
        except Exception as e:
            logger.debug(f"HackerTarget: {e}")
            return 0

class ScanResult:
    def __init__(self, graph, domain, scan_start, attack_paths, compliance, ai_report, diff_data):
        self.graph = graph; self.domain = domain; self.scan_start = scan_start
        self.attack_paths = attack_paths; self.compliance = compliance
        self.ai_report = ai_report; self.diff_data = diff_data

class ArgusEngineV4(ArgusEngine):
    """
    Argus v3.5 — Final maximum coverage engine.
    Adds 3 final phases:
      31. HTTP Request Smuggling (CL.TE, TE.CL, TE.TE)
      32. Cross-organization correlation (ASN-level infrastructure mapping)
      33. GNN Subdomain Prediction (pattern-based undiscovered domain inference)
    """

    def __init__(self, config, renderer):
        super().__init__(config, renderer)
        self._total_phases = 43
        from argus.intelligence.http_smuggling import HTTPSmugglingProbe
        from argus.intelligence.cross_org import CrossOrgCorrelation
        from argus.intelligence.gnn_predict import SubdomainPredictor
        from argus.intelligence.bgp_intel import BGPIntelligence
        from argus.intelligence.ssrf_chain import SSRFChainDetector
        from argus.intelligence.stealth import StealthEngine
        from argus.intelligence.protocol_fuzzer import ProtocolFuzzer
        from argus.intelligence.threat_intel import ThreatIntelligence
        from argus.intelligence.cloud_enum import CloudStorageEnumerator
        from argus.intelligence.api_enum import APIEnumerator
        from argus.intelligence.cve_deep import DeepCVECorrelator
        self.smuggling  = HTTPSmugglingProbe(self.graph, timeout=self.config.timeout)
        self.cross_org  = CrossOrgCorrelation(self.http, self.dns, self.graph)
        self.gnn        = SubdomainPredictor(self.graph, self.dns)
        self.bgp        = BGPIntelligence(self.http, self.graph)
        self.ssrf_chain = SSRFChainDetector(self.http, self.graph)
        self.stealth    = StealthEngine(self.http, self.graph,
                                        profile=getattr(self.config, "stealth_profile", "normal"))
        self.proto_fuzz = ProtocolFuzzer(self.http, self.graph)
        self.threat     = ThreatIntelligence(self.http, self.graph)
        self.cloud_enum = CloudStorageEnumerator(self.http, self.graph)
        self.api_enum   = APIEnumerator(self.http, self.graph)
        self.cve_deep   = DeepCVECorrelator(self.http, self.graph)

    async def run(self, domain: str) -> "ScanResult":

        result = await super().run(domain)

        N = self._total_phases
        async with self.http:

            self.renderer.phase(31, N, "HTTP Request Smuggling (CL.TE, TE.CL, TE.TE desync)")
            smug_r = await self.smuggling.run()
            if smug_r["smuggling_candidates"] > 0:
                self.renderer.warning(
                    f"SMUGGLING: {smug_r['smuggling_candidates']} candidate(s) — "
                    f"CL.TE/TE.CL desync detected"
                )
            else:
                self.renderer.success(f"Smuggling: {smug_r['domains_probed']} hosts probed — none vulnerable")

            if self.config.deep:
                self.renderer.phase(32, N, "Cross-organization correlation (ASN infrastructure mapping)")
                co_r = await self.cross_org.run(domain)
                self.renderer.success(
                    f"Cross-org: {co_r['orgs_found']} orgs — "
                    f"{co_r['related_domains']} related domains — "
                    f"{co_r['shared_ips']} shared IPs"
                )
            else:
                self.renderer.phase(32, N, "Cross-org skipped (--deep)")

            self.renderer.phase(33, N, "GNN subdomain prediction (pattern inference → DNS verification)")
            gnn_r = await self.gnn.predict_and_verify(domain, top_n=100)
            if gnn_r["verified"] > 0:
                self.renderer.warning(
                    f"GNN: {gnn_r['predicted']} candidates — "
                    f"{gnn_r['verified']} NEW subdomains verified via DNS: "
                    + ", ".join(gnn_r["new_domains"][:3])
                )
            else:
                self.renderer.success(
                    f"GNN: {gnn_r['predicted']} candidates generated — "
                    f"none resolved (domain fully enumerated)"
                )

        self.renderer.phase(34, N, "Authentication & JWT analysis")
        from argus.intelligence.auth import AuthIntelligence
        auth_intel  = AuthIntelligence(
            self.http, self.graph,
            credentials=getattr(self.config, "credentials", [])
        )
        auth_r = await auth_intel.run()
        if auth_r.get("login_forms"):
            self.renderer.success(
                f"Auth: {auth_r['login_forms']} forms — "
                f"{auth_r['weak_creds']} weak creds — "
                f"{auth_r['jwt_findings']} JWT issues"
            )
        else:
            self.renderer.info("Auth: no login forms detected")

        if getattr(self.config, "fuzz", False):
            self.renderer.phase(35, N, "Parameter fuzzing (SQLi, XSS, SSRF, IDOR, traversal)")
            session = auth_intel.sessions[0] if auth_intel.sessions else None
            from argus.intelligence.fuzzer import ParameterFuzzer
            fuzzer  = ParameterFuzzer(self.http, self.graph,
                                      concurrency=6, timeout=12,
                                      auth_session=session)
            fuzz_r  = await fuzzer.run()
            self.renderer.warning(
                f"Fuzz: {fuzz_r['findings']} findings — "
                f"SQLi:{fuzz_r['sqli']} XSS:{fuzz_r['xss']} "
                f"SSRF:{fuzz_r['ssrf']} Traversal:{fuzz_r['traversal']} "
                f"IDOR:{fuzz_r['idor']}"
            ) if fuzz_r['findings'] else self.renderer.info("Fuzz: no injection points detected")
        else:
            self.renderer.phase(35, N, "Fuzzing skipped (--fuzz)")

        self.renderer.phase(36, N, "BGP + AS path + cloud provider correlation")
        try:
            bgp_r = await asyncio.wait_for(self.bgp.run(), timeout=60)
            self.renderer.success(
                f"BGP: {bgp_r['asns_analyzed']} ASNs — "
                f"{bgp_r['prefixes_found']} prefixes — "
                f"{bgp_r['cloud_mapped']} cloud-mapped — "
                f"{bgp_r['hijack_candidates']} route anomalies"
            )
        except Exception as e:
            self.renderer.info(f"BGP: skipped ({type(e).__name__})")

        self.renderer.phase(37, N, "SSRF chain + internal service pivot detection")
        try:
            ssrf_r = await asyncio.wait_for(self.ssrf_chain.run(), timeout=90)
            if ssrf_r["ssrf_found"] or ssrf_r["chains_found"]:
                self.renderer.warning(
                    f"SSRF: {ssrf_r['ssrf_found']} endpoints — "
                    f"{ssrf_r['chains_found']} chains — "
                    f"{ssrf_r['cloud_meta_found']} cloud metadata — "
                    f"{ssrf_r['gopher_viable']} gopher pivots"
                )
            else:
                self.renderer.info("SSRF chains: no pivot paths detected")
        except Exception as e:
            self.renderer.info(f"SSRF chain: skipped ({type(e).__name__})")

        self.renderer.phase(38, N, "Protocol fuzzing — OAuth / GraphQL / WebSocket")
        try:
            proto_r = await asyncio.wait_for(self.proto_fuzz.run(), timeout=120)
            if proto_r["total"]:
                self.renderer.warning(
                    f"Protocol: {proto_r['oauth_issues']} OAuth — "
                    f"{proto_r['graphql_issues']} GraphQL — "
                    f"{proto_r['ws_issues']} WebSocket"
                )
            else:
                self.renderer.info("Protocol: no OAuth/GraphQL/WebSocket issues found")
        except Exception as e:
            self.renderer.info(f"Protocol fuzzer: skipped ({type(e).__name__})")

        self.renderer.phase(39, N, "Honeypot detection + infrastructure deception analysis")
        try:
            stealth_r = await asyncio.wait_for(self.stealth.run(), timeout=60)
            if stealth_r["honeypots_found"]:
                self.renderer.warning(
                    f"Stealth: {stealth_r['honeypots_found']} honeypot(s) detected — "
                    f"{stealth_r['honeypot_hosts']}"
                )
            else:
                self.renderer.info(f"Stealth: {stealth_r['hosts_analyzed']} hosts analyzed — no honeypots")
        except Exception as e:
            self.renderer.info(f"Stealth: skipped ({type(e).__name__})")

        self.renderer.phase(40, N, "Deep CVE correlation — version fingerprinting + exploit matching")
        try:
            cve_r = await asyncio.wait_for(self.cve_deep.run(), timeout=60)
            if cve_r["cves_matched"]:
                self.renderer.warning(
                    f"CVE deep: {cve_r['technologies_found']} techs — "
                    f"{cve_r['cves_matched']} CVEs — "
                    f"{cve_r['critical_cves']} CRITICAL"
                )
            else:
                self.renderer.info(
                    f"CVE deep: {cve_r['technologies_found']} techs fingerprinted — "
                    f"no known vulnerable versions"
                )
        except Exception as e:
            self.renderer.info(f"CVE deep: skipped ({type(e).__name__})")

        self.renderer.phase(41, N, "API REST + OpenAPI/Swagger enumeration")
        try:
            api_r = await asyncio.wait_for(self.api_enum.run(), timeout=90)
            if api_r["specs_found"]:
                self.renderer.warning(
                    f"API: {api_r['specs_found']} specs — "
                    f"{api_r['endpoints_discovered']} endpoints — "
                    f"{api_r['sensitive_endpoints']} sensitive — "
                    f"{api_r['api_keys_exposed']} keys exposed"
                )
            else:
                self.renderer.info(
                    f"API: {api_r['versions_found']} versions probed — no specs found"
                )
        except Exception as e:
            self.renderer.info(f"API enum: skipped ({type(e).__name__})")

        self.renderer.phase(42, N, "Cloud storage enumeration — S3 / Azure / GCS / DO")
        try:
            cloud_r = await asyncio.wait_for(self.cloud_enum.run(), timeout=120)
            if cloud_r["public_buckets"]:
                self.renderer.warning(
                    f"Cloud: {cloud_r['buckets_found']} buckets found — "
                    f"{cloud_r['public_buckets']} PUBLIC — "
                    f"S3:{cloud_r['buckets_found']} "
                    f"Azure:{cloud_r['azure_found']} "
                    f"GCS:{cloud_r['gcs_found']}"
                )
            elif cloud_r["buckets_found"]:
                self.renderer.info(
                    f"Cloud: {cloud_r['buckets_found']} buckets exist — "
                    f"all access restricted"
                )
            else:
                self.renderer.info("Cloud: no buckets found")
        except Exception as e:
            self.renderer.info(f"Cloud enum: skipped ({type(e).__name__})")

        self.renderer.phase(43, N, "Threat intelligence — reputation + breach data + blacklists")
        try:
            threat_r = await asyncio.wait_for(self.threat.run(), timeout=90)
            parts = []
            if threat_r["blacklisted"]:     parts.append(f"{threat_r['blacklisted']} blacklisted")
            if threat_r["tor_exits"]:        parts.append(f"{threat_r['tor_exits']} Tor exits")
            if threat_r["bad_asns"]:         parts.append(f"{threat_r['bad_asns']} bad ASNs")
            if threat_r["breached_domains"]: parts.append(f"{threat_r['breached_domains']} breached domains")
            if threat_r["malicious_ips"]:    parts.append(f"{threat_r['malicious_ips']} malicious IPs")
            if parts:
                self.renderer.warning(f"Threat intel: {' — '.join(parts)}")
            else:
                self.renderer.info(
                    f"Threat intel: {threat_r['ips_checked']} IPs checked — no threats found"
                )
        except Exception as e:
            self.renderer.info(f"Threat intel: skipped ({type(e).__name__})")

        return result
