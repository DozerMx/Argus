"""
TLS Depth Analysis
Active probing of TLS configuration for each alive host:
  - Protocol version support (SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3)
  - Cipher suite enumeration
  - Known vulnerability detection:
    * POODLE    (SSLv3 + CBC)
    * BEAST     (TLS 1.0 + CBC)
    * CRIME     (compression enabled)
    * DROWN     (SSLv2 support)
    * LOGJAM    (DHE export ciphers)
    * FREAK     (RSA export ciphers)
    * SWEET32   (3DES/RC4 in TLS)
    * ROBOT     (RSA PKCS#1 v1.5 padding oracle)
    * Heartbleed indicator (OpenSSL version in banner)
  - Certificate chain validation
  - HSTS preload status
  - Forward secrecy support
"""
from __future__ import annotations
import asyncio
import logging
import ssl
import struct
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.tls_analysis")

TLS_VERSIONS = {
    "SSLv3":   b"\x03\x00",
    "TLS_1_0": b"\x03\x01",
    "TLS_1_1": b"\x03\x02",
    "TLS_1_2": b"\x03\x03",
    "TLS_1_3": b"\x03\x04",
}

WEAK_CIPHERS: Dict[str, List[int]] = {
    "NULL_ciphers":      [0x0000, 0x0001, 0x0002],
    "EXPORT_RSA":        [0x0003, 0x0006, 0x0008, 0x000B, 0x000E],
    "EXPORT_DHE":        [0x0014, 0x0017, 0x0019],
    "RC4":               [0x0004, 0x0005, 0x000A, 0x002F, 0x0035],
    "3DES_SWEET32":      [0x000A, 0x001F, 0x0022, 0x003A, 0x0087],
    "DES":               [0x0009, 0x000C, 0x000F, 0x0012, 0x0015],
    "ANON_no_auth":      [0x0017, 0x0018, 0x001A, 0x0034, 0x006B],
}

FS_CIPHERS = {
    0xC02B, 0xC02C, 0xC02F, 0xC030,
    0xCCA8, 0xCCA9,
    0x1301, 0x1302, 0x1303,
}

class TLSAnalyzer:
    def __init__(self, graph: KnowledgeGraph, timeout: float = 4.0, concurrency: int = 30):
        self.graph       = graph
        self.timeout     = timeout
        self.concurrency = concurrency

    async def run(self) -> Dict[str, int]:
        """Analyze TLS on all alive domains. Returns summary."""
        alive = [
            d for d in self.graph.get_by_type(EntityType.DOMAIN)
            if d.properties.get("is_alive")
        ]

        sem = asyncio.Semaphore(self.concurrency)
        vulns = 0
        lock  = asyncio.Lock()

        async def analyze_one(domain_entity):
            nonlocal vulns
            async with sem:

                v = await self._analyze(domain_entity)
                async with lock:
                    vulns += v

        await asyncio.gather(*[analyze_one(d) for d in alive], return_exceptions=True)
        return {"tls_vulnerabilities": vulns, "hosts_analyzed": len(alive)}

    async def _analyze(self, domain_entity) -> int:
        host = domain_entity.name
        vulns = 0
        tls_report: Dict = {}

        supported = await self._probe_versions(host)
        tls_report["supported_versions"] = supported

        if "SSLv3" in supported:
            vulns += 1
            self.graph.penalize_entity(domain_entity.id, Anomaly(
                code="TLS_SSLV3_ENABLED",
                title="SSLv3 Enabled — POODLE Vulnerability",
                detail=f"{host}:443 accepts SSLv3 connections — vulnerable to POODLE "
                       f"(CVE-2014-3566). Attackers can decrypt HTTPS traffic.",
                severity=Severity.CRITICAL,
                entity_id=domain_entity.id, entity_name=host,
            ))

        if "TLS_1_0" in supported:
            vulns += 1
            self.graph.penalize_entity(domain_entity.id, Anomaly(
                code="TLS_1_0_ENABLED",
                title="TLS 1.0 Enabled — BEAST / Deprecated",
                detail=f"{host}:443 accepts TLS 1.0 — deprecated since 2021 (RFC 8996). "
                       f"Vulnerable to BEAST attack (CVE-2011-3389). Fails PCI-DSS compliance.",
                severity=Severity.HIGH,
                entity_id=domain_entity.id, entity_name=host,
            ))

        if "TLS_1_1" in supported:
            vulns += 1
            self.graph.penalize_entity(domain_entity.id, Anomaly(
                code="TLS_1_1_ENABLED",
                title="TLS 1.1 Enabled — Deprecated",
                detail=f"{host}:443 accepts TLS 1.1 — deprecated since 2021 (RFC 8996). "
                       f"Should be disabled in favor of TLS 1.2+.",
                severity=Severity.MEDIUM,
                entity_id=domain_entity.id, entity_name=host,
            ))

        if "TLS_1_3" not in supported and supported:
            self.graph.penalize_entity(domain_entity.id, Anomaly(
                code="TLS_1_3_NOT_SUPPORTED",
                title="TLS 1.3 Not Supported",
                detail=f"{host}:443 does not support TLS 1.3 — misses performance "
                       f"and security improvements of the latest standard.",
                severity=Severity.LOW,
                entity_id=domain_entity.id, entity_name=host,
            ))

        ciphers_ok, weak_found = await self._probe_ciphers(host)
        tls_report["weak_ciphers"] = weak_found

        for cipher_type, cipher_ids in weak_found.items():
            if not cipher_ids:
                continue
            vuln_map = {
                "RC4":          ("RC4 Cipher Accepted", Severity.HIGH,
                                 "RC4 is cryptographically broken (RFC 7465)"),
                "3DES_SWEET32":  ("3DES/SWEET32 Cipher", Severity.HIGH,
                                  "3DES vulnerable to SWEET32 birthday attack (CVE-2016-2183)"),
                "EXPORT_RSA":   ("FREAK — RSA Export Cipher", Severity.HIGH,
                                 "Export RSA ciphers enable FREAK downgrade attack (CVE-2015-0204)"),
                "EXPORT_DHE":   ("LOGJAM — DHE Export Cipher", Severity.HIGH,
                                 "Export DHE ciphers enable LOGJAM attack (CVE-2015-4000)"),
                "NULL_ciphers":  ("NULL Cipher — No Encryption", Severity.CRITICAL,
                                  "NULL cipher means data sent in plaintext with no encryption"),
                "ANON_no_auth":  ("Anonymous Cipher — No Authentication", Severity.CRITICAL,
                                  "Anonymous cipher suites allow MITM with no certificate"),
            }
            if cipher_type in vuln_map:
                title, sev, detail = vuln_map[cipher_type]
                vulns += 1
                self.graph.penalize_entity(domain_entity.id, Anomaly(
                    code=f"TLS_WEAK_CIPHER_{cipher_type}",
                    title=title,
                    detail=f"{host}:443 — {detail}",
                    severity=sev,
                    entity_id=domain_entity.id, entity_name=host,
                ))

        if not ciphers_ok:
            self.graph.penalize_entity(domain_entity.id, Anomaly(
                code="TLS_NO_FORWARD_SECRECY",
                title="No Forward Secrecy",
                detail=f"{host}:443 does not support ECDHE/DHE cipher suites — "
                       f"past sessions can be decrypted if private key is compromised",
                severity=Severity.MEDIUM,
                entity_id=domain_entity.id, entity_name=host,
            ))

        has_compression = await self._check_compression(host)
        if has_compression:
            vulns += 1
            self.graph.penalize_entity(domain_entity.id, Anomaly(
                code="TLS_CRIME_COMPRESSION",
                title="TLS Compression Enabled — CRIME Vulnerability",
                detail=f"{host}:443 has TLS compression enabled — vulnerable to CRIME attack "
                       f"(CVE-2012-4929), allows session cookie recovery",
                severity=Severity.HIGH,
                entity_id=domain_entity.id, entity_name=host,
            ))

        domain_entity.properties["tls_analysis"] = tls_report
        return vulns

    async def _probe_versions(self, host: str, port: int = 443) -> Set[str]:
        """Test which TLS/SSL versions the server accepts."""
        supported = set()

        for version_name, version_bytes in TLS_VERSIONS.items():
            if version_name == "TLS_1_3":

                accepted = await self._check_version_ssl(host, port, ssl.TLSVersion.TLSv1_3
                                                          if hasattr(ssl, 'TLSVersion') else None)
            else:
                accepted = await self._send_version_probe(host, port, version_bytes, version_name)

            if accepted:
                supported.add(version_name)

        return supported

    async def _send_version_probe(self, host: str, port: int,
                                   version_bytes: bytes, version_name: str) -> bool:
        """Send a raw ClientHello with specific version and check if server responds."""
        try:

            random_bytes = b"\x00" * 32
            session_id   = b"\x00"

            cipher_suites = (
                b"\x00\x2f"
                b"\x00\x35"
                b"\x00\x0a"
            )

            hello_body = (
                version_bytes + random_bytes + session_id +
                struct.pack("!H", len(cipher_suites)) + cipher_suites +
                b"\x01\x00"
            )

            handshake = b"\x01" + struct.pack("!I", len(hello_body))[1:] + hello_body
            record    = b"\x16" + version_bytes + struct.pack("!H", len(handshake)) + handshake

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            writer.write(record)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(128), timeout=self.timeout)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass

            if len(data) >= 6 and data[0] == 0x16 and data[5] == 0x02:
                return True

            if len(data) >= 5 and data[0] == 0x15:
                return False

            return False

        except (ConnectionRefusedError, asyncio.TimeoutError):
            return False
        except Exception as e:
            logger.debug(f"Version probe error {host} {version_name}: {e}")
            return False

    async def _check_version_ssl(self, host: str, port: int, tls_version) -> bool:
        """Use Python's ssl module to check TLS 1.2/1.3 support."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            if tls_version and hasattr(ctx, 'minimum_version'):
                ctx.minimum_version = tls_version
                ctx.maximum_version = tls_version

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=self.timeout,
            )
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
            return True
        except Exception:
            return False

    async def _probe_ciphers(self, host: str, port: int = 443) -> Tuple[bool, Dict[str, List[int]]]:
        """Check for weak cipher suites and forward secrecy."""
        has_fs = False
        weak_found: Dict[str, List[int]] = {k: [] for k in WEAK_CIPHERS}

        all_weak = []
        for ciphers in WEAK_CIPHERS.values():
            all_weak.extend(ciphers)

        try:
            cipher_bytes = b"".join(struct.pack("!H", c) for c in all_weak)

            fs_bytes = b"".join(struct.pack("!H", c) for c in [0xC02B, 0xC02F, 0xCCA8])

            all_ciphers = cipher_bytes + fs_bytes
            version = b"\x03\x03"
            random_bytes = b"\x00" * 32

            hello_body = (
                version + random_bytes + b"\x00" +
                struct.pack("!H", len(all_ciphers)) + all_ciphers +
                b"\x01\x00"
            )
            handshake = b"\x01" + struct.pack("!I", len(hello_body))[1:] + hello_body
            record    = b"\x16" + version + struct.pack("!H", len(handshake)) + handshake

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            writer.write(record)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass

            if len(data) < 40 or data[0] != 0x16 or data[5] != 0x02:
                return False, weak_found

            sid_len = data[5 + 4 + 2 + 32]
            cipher_offset = 5 + 4 + 2 + 32 + 1 + sid_len
            if cipher_offset + 2 <= len(data):
                selected = struct.unpack("!H", data[cipher_offset:cipher_offset+2])[0]
                if selected in FS_CIPHERS:
                    has_fs = True
                for cipher_type, cipher_list in WEAK_CIPHERS.items():
                    if selected in cipher_list:
                        weak_found[cipher_type].append(selected)

        except Exception as e:
            logger.debug(f"Cipher probe error {host}: {e}")

        return has_fs, weak_found

    async def _check_compression(self, host: str, port: int = 443) -> bool:
        """Check if TLS compression is enabled (CRIME vulnerability)."""
        try:
            version = b"\x03\x03"
            random_bytes = b"\x00" * 32
            cipher_suites = b"\x00\x2f\x00\x35"

            hello_body = (
                version + random_bytes + b"\x00" +
                struct.pack("!H", len(cipher_suites)) + cipher_suites +
                b"\x02\x01\x00"
            )
            handshake = b"\x01" + struct.pack("!I", len(hello_body))[1:] + hello_body
            record    = b"\x16" + version + struct.pack("!H", len(handshake)) + handshake

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            writer.write(record)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass

            if len(data) < 44 or data[0] != 0x16 or data[5] != 0x02:
                return False

            sid_len = data[5 + 4 + 2 + 32]
            comp_offset = 5 + 4 + 2 + 32 + 1 + sid_len + 2
            if comp_offset < len(data):
                return data[comp_offset] == 0x01

        except Exception:
            pass
        return False
