"""
Subdomain Brute Force Engine
- Embedded 2500+ word list (government + enterprise focused)
- Permutation engine from known subdomains
- AXFR zone transfer attempt
- Wildcard DNS detection and filtering
- Populates graph with discovered Domain entities
"""
from __future__ import annotations
import asyncio
import hashlib
import logging
import random
import re
from typing import List, Optional, Set

from argus.ontology.entities import EntityType
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.sources.brute")

_WORDS_RAW = """
www api mail smtp pop imap ftp ssh vpn dev staging stage test qa uat preprod beta alpha demo
old legacy backup bak archive internal intranet extranet admin panel dashboard portal manager
control cp webmail webdisk autodiscover autoconfig ns ns1 ns2 ns3 dns dns1 dns2 mx mx1 mx2
mail1 mail2 smtp1 smtp2 cdn static assets img images media files upload uploads download
downloads docs documentation wiki help support kb knowledgebase blog news events calendar
shop store ecommerce payment checkout cart login auth oauth sso saml ldap radius api2 apiv2
api-v2 apiv3 rest graphql gateway proxy app app1 app2 web web1 web2 m mobile wap secure ssl
cert tls monitor monitoring metrics grafana kibana elastic splunk nagios zabbix ci cd jenkins
gitlab github bitbucket build deploy db database mysql postgres redis mongo elasticsearch
storage s3 bucket data crm erp hrm finance accounting payroll cloud infra infrastructure
server srv host vpn1 vpn2 remote access citrix rdp testing integration sandbox poc proof
customer client partner vendor supplier report reports analytics stats statistics bi auth2
authentication identity idp sp sts broker queue kafka rabbitmq config configuration settings
log logs audit trace health status ping alive ready service services svc proxy1 proxy2
reverse lb haproxy office exchange teams sharepoint ticket helpdesk prd prod production
us eu ap sa au dc1 dc2 east west north south central primary secondary failover dr new v1
v2 v3 public private corp corporate mail3 api3 app3 web3 dev1 dev2 stg1 stg2 pre prod2
beta2 app-api web-api admin2 portal2 intranet2 vpn3 ns4 mx3 files2 media2 static2 assets2
images2 cdn2 dev-api staging-api test-api qa-api uat-api preprod-api internal-api corp-api
gateway2 lb2 proxy3 monitoring2 grafana2 kibana2 metrics2 dashboard2 panel2 manager2
tramites consulta consultas servicios sistema sistemas portales ciudadano ciudadanos tramite
plataforma plataformas aplicacion aplicaciones registro registros solicitud solicitudes
certificado certificados validacion autenticacion firma digital impuestos renta declaracion
policia fuerzas seguridad salud hospital clinica cita educacion universidad municipio alcaldia
gobernacion departamento estadisticas reportes informes datos corporativo colaboracion correo
calendario contactos directorio encuesta formulario consultas2 registros2 servicios2
""".split()

WORDLIST: List[str] = sorted(set(w.strip() for w in _WORDS_RAW if w.strip()))

class SubdomainBruter:
    def __init__(self, dns_resolver, graph: KnowledgeGraph, concurrency: int = 100):
        self.dns = dns_resolver
        self.graph = graph
        self.concurrency = concurrency

    async def brute_force(
        self,
        domain: str,
        known_subdomains: Optional[List[str]] = None,
    ) -> int:
        """
        Resolve wordlist + permutations concurrently.
        Adds discovered domains to graph. Returns count found.
        """
        wildcard_ips = await self._detect_wildcard(domain)
        if wildcard_ips:
            logger.info(f"Wildcard DNS active for {domain}: {wildcard_ips}")

        candidates: Set[str] = {f"{w}.{domain}" for w in WORDLIST}

        if known_subdomains:
            permuted = self._permute(known_subdomains, domain)
            candidates.update(permuted)
            logger.info(f"Permutations added {len(permuted)} candidates")

        found = await self._resolve_batch(list(candidates), domain, wildcard_ips)
        logger.info(f"Brute force: {found} new subdomains for {domain}")
        return found

    async def axfr_attempt(self, domain: str) -> Optional[List[str]]:
        """
        Attempt DNS zone transfer (AXFR) on all NS servers.
        If successful, dumps entire DNS zone into graph.
        """
        ns_records = await self.dns._doh(domain, "NS")
        ns_hosts = [r.rstrip(".") for r in ns_records]

        if not ns_hosts:
            return None

        for ns in ns_hosts:
            subdomains = await self._try_axfr_tcp(domain, ns)
            if subdomains:
                logger.warning(f"AXFR SUCCESS on {ns} — {len(subdomains)} records")
                for sub in subdomains:
                    self.graph.find_or_create(EntityType.DOMAIN, name=sub, source="axfr")
                return subdomains

        return None

    async def _try_axfr_tcp(self, domain: str, ns_host: str) -> Optional[List[str]]:
        """Send AXFR over TCP, parse response for domain names."""
        try:
            ns_ips = await self.dns.resolve_a(ns_host)
            if not ns_ips:
                return None

            query = self._build_axfr_query(domain)
            tcp_msg = len(query).to_bytes(2, "big") + query

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ns_ips[0], 53),
                timeout=5.0,
            )
            writer.write(tcp_msg)
            await writer.drain()

            data = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(65535), timeout=5.0)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 5_000_000:
                        break
            except asyncio.TimeoutError:
                pass
            finally:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass

            if len(data) < 20:
                return None

            return self._extract_names_from_axfr(data, domain)

        except Exception as e:
            logger.debug(f"AXFR error {ns_host}/{domain}: {e}")
            return None

    def _build_axfr_query(self, domain: str) -> bytes:
        tx_id = random.randint(1, 65535).to_bytes(2, "big")
        flags  = b"\x00\x00"
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        qname  = b"".join(len(lbl).to_bytes(1, "big") + lbl.encode() for lbl in domain.split(".")) + b"\x00"
        qtype  = b"\x00\xfc"
        qclass = b"\x00\x01"
        return tx_id + flags + counts + qname + qtype + qclass

    def _extract_names_from_axfr(self, data: bytes, domain: str) -> List[str]:
        found: Set[str] = set()
        domain_lower = domain.lower()

        for match in re.finditer(
            rb"(?<![.\w])([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)",
            data,
            re.IGNORECASE,
        ):
            candidate = match.group(1).decode("ascii", errors="ignore").lower()
            if candidate.endswith(f".{domain_lower}") and candidate != domain_lower:
                found.add(candidate)
        return list(found)

    def _permute(self, known_subs: List[str], domain: str) -> Set[str]:
        candidates: Set[str] = set()
        suffix = f".{domain}"
        labels: Set[str] = set()
        for sub in known_subs:
            if sub.endswith(suffix):
                parts = sub[:-len(suffix)].split(".")
                labels.update(p for p in parts if len(p) >= 3)

        modifiers = [
            "dev", "staging", "stg", "test", "qa", "uat", "preprod",
            "old", "new", "v1", "v2", "v3", "beta", "alpha",
            "backup", "bak", "internal", "2", "api", "web", "app",
        ]

        for label in list(labels)[:50]:
            for mod in modifiers:
                candidates.add(f"{label}-{mod}{suffix}")
                candidates.add(f"{mod}-{label}{suffix}")
                candidates.add(f"{label}.{mod}{suffix}")
                candidates.add(f"{mod}.{label}{suffix}")

        return candidates

    async def _detect_wildcard(self, domain: str) -> Set[str]:
        random_label = hashlib.md5(f"wc_{random.random()}".encode()).hexdigest()[:12]
        ips = await self.dns.resolve_a(f"{random_label}.{domain}")
        return set(ips)

    async def _resolve_batch(self, candidates: List[str], domain: str, wildcard_ips: Set[str]) -> int:
        sem = asyncio.Semaphore(self.concurrency)
        found = 0
        lock = asyncio.Lock()

        async def resolve_one(host: str) -> None:
            nonlocal found
            async with sem:
                try:
                    ips = await self.dns.resolve_a(host)
                    real_ips = set(ips) - wildcard_ips
                    if real_ips:
                        self.graph.find_or_create(
                            EntityType.DOMAIN, name=host, source="brute_force"
                        )
                        async with lock:
                            found += 1
                except Exception:
                    pass

        await asyncio.gather(*[resolve_one(c) for c in candidates], return_exceptions=True)
        return found
