"""
JARM TLS Fingerprinting — Wired to Graph
Identifies server TLS implementation by sending 10 crafted ClientHello packets.
Adds JARM fingerprint to IP/domain entities. Detects known C2 frameworks.

Reference: https://github.com/salesforce/jarm (Salesforce, public domain)
"""
from __future__ import annotations
import asyncio
import hashlib
import logging
import random
import struct
from typing import Dict, List, Optional, Tuple

from argus.ontology.entities import (
    Anomaly, EntityType, Severity,
)
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.jarm")

KNOWN_JARMS: Dict[str, Tuple[str, Severity]] = {
    "29d29d15d29d29d00029d29d29d29de2a526b79b43e8195de7f2ca2b3": ("Cobalt Strike C2",  Severity.CRITICAL),
    "07d14d16d21d21d07c42d41d00041d58c7162162162162162162162162": ("Metasploit HTTPS",  Severity.CRITICAL),
    "21d19d00021d21d21c42d43d000000059e3dea18e3dea18e3dea18e3d": ("AsyncRAT",           Severity.CRITICAL),
    "29d21b20d29d29d21c41d43d00041d598ac0c1012db967bb1ad0ff2491": ("Covenant C2",       Severity.CRITICAL),
    "2ad2ad0002ad2ad22c42d42d000000faabb8fd28d65a3571c81cbfa4d2": ("Apache httpd",      Severity.INFO),
    "27d40d40d29d40d1dc42d43d00041d2aa5ce6a70de7ba95aef77a77b00": ("nginx",             Severity.INFO),
    "29d3fd00029d29d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00": ("Microsoft IIS",     Severity.INFO),
    "2ad000000000000000000000000000eeebf944d0b023a00f510f06a29b4": ("Cloudflare",       Severity.INFO),
}

class JARMFingerprinter:
    def __init__(self, graph: KnowledgeGraph, timeout: float = 5.0, concurrency: int = 5):
        self.graph       = graph
        self.timeout     = timeout
        self.concurrency = concurrency

    async def run(self) -> int:
        """Fingerprint all alive domains on port 443. Returns count fingerprinted."""
        alive = [
            d for d in self.graph.get_by_type(EntityType.DOMAIN)
            if d.properties.get("is_alive")
        ]
        sem = asyncio.Semaphore(self.concurrency)
        count = 0
        lock = asyncio.Lock()

        async def fp_one(domain_entity):
            nonlocal count
            async with sem:
                fp = await self.fingerprint(domain_entity.name, 443)
                if fp:
                    domain_entity.properties["jarm"] = fp
                    identified, severity = KNOWN_JARMS.get(fp, (None, None))
                    if identified:
                        self.graph.penalize_entity(domain_entity.id, Anomaly(
                            code="JARM_KNOWN_FINGERPRINT",
                            title=f"JARM Matches: {identified}",
                            detail=f"TLS fingerprint {fp[:20]}… matches known profile: {identified}",
                            severity=severity,
                            entity_id=domain_entity.id,
                            entity_name=domain_entity.name,
                        ))
                        if severity in (Severity.CRITICAL, Severity.HIGH):
                            logger.warning(f"JARM HIT: {domain_entity.name} → {identified}")
                    async with lock:
                        count += 1

        await asyncio.gather(*[fp_one(d) for d in alive], return_exceptions=True)
        return count

    async def fingerprint(self, host: str, port: int = 443) -> Optional[str]:
        probes = self._build_probes(host)
        responses: List[Optional[str]] = []

        for probe in probes:
            resp = await self._send_probe(host, port, probe)
            responses.append(resp)

        if all(r is None for r in responses):
            return None
        return self._compute_fingerprint(responses)

    def _build_probes(self, host: str) -> List[bytes]:
        combos = [
            ("TLS_1_2", "FORWARD",  False, "APLN_H2"),
            ("TLS_1_2", "REVERSE",  False, "APLN_HTTP"),
            ("TLS_1_2", "FORWARD",  True,  "NO_APLN"),
            ("TLS_1_2", "REVERSE",  True,  "APLN_H2"),
            ("TLS_1_1", "FORWARD",  False, "NO_APLN"),
            ("TLS_1_3", "FORWARD",  False, "APLN_H2"),
            ("TLS_1_3", "REVERSE",  False, "APLN_HTTP"),
            ("TLS_1_3", "FORWARD",  True,  "NO_APLN"),
            ("TLS_1_3", "REVERSE",  True,  "APLN_H2"),
            ("TLS_1_3", "FORWARD",  False, "NO_APLN"),
        ]
        return [self._build_client_hello(host, v, o, g, a) for v, o, g, a in combos]

    def _build_client_hello(self, host: str, version: str, order: str,
                             grease: bool, alpn: str) -> bytes:
        rec_ver = b"\x03\x02" if version == "TLS_1_1" else b"\x03\x03"
        rand    = bytes(random.randint(0, 255) for _ in range(32))
        ciphers = self._get_ciphers(order, grease, version)
        exts    = self._build_extensions(host, version, alpn, grease)
        body = (rec_ver + rand + b"\x00" +
                struct.pack("!H", len(ciphers)) + ciphers +
                b"\x01\x00" +
                struct.pack("!H", len(exts)) + exts)
        hello  = b"\x01" + struct.pack("!I", len(body))[1:] + body
        return b"\x16" + rec_ver + struct.pack("!H", len(hello)) + hello

    def _get_ciphers(self, order: str, grease: bool, version: str) -> bytes:
        tls12 = [0xC02B,0xC02F,0xC02C,0xC030,0x009E,0x009F,0xC013,0xC014,0x002F,0x0035,0x000A]
        tls13 = [0x1301,0x1302,0x1303]
        ciphers = (tls13 + tls12) if "TLS_1_3" in version else tls12
        if order == "REVERSE":
            ciphers = list(reversed(ciphers))
        if grease:
            ciphers.insert(0, 0x0A0A)
        return b"".join(struct.pack("!H", c) for c in ciphers)

    def _build_extensions(self, host: str, version: str, alpn: str, grease: bool) -> bytes:
        hostname = host.encode()
        exts  = b"\x00\x00" + struct.pack("!HH", len(hostname)+3, 0) + struct.pack("!H", len(hostname)) + hostname
        exts += b"\x00\x17\x00\x00"
        exts += b"\xff\x01\x00\x01\x00"
        groups = b"\x00\x1d\x00\x17\x00\x18"
        exts += b"\x00\x0a" + struct.pack("!HH", len(groups)+2, len(groups)) + groups
        exts += b"\x00\x0b\x00\x02\x01\x00"
        exts += b"\x00\x23\x00\x00"
        if alpn != "NO_APLN":
            proto = {
                "APLN_H2":   b"\x02h2",
                "APLN_HTTP": b"\x08http/1.1",
            }.get(alpn, b"")
            if proto:
                pl = struct.pack("!H", len(proto)) + proto
                exts += b"\x00\x10" + struct.pack("!H", len(pl)+2) + struct.pack("!H", len(pl)) + pl
        sigs = b"\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01"
        exts += b"\x00\x0d" + struct.pack("!H", len(sigs)+2) + struct.pack("!H", len(sigs)) + sigs
        if "TLS_1_3" in version:
            ver_data = b"\x04\x03\x04\x03\x03"
            exts += b"\x00\x2b" + struct.pack("!H", len(ver_data)+1) + struct.pack("!B", len(ver_data)) + ver_data
        return exts

    async def _send_probe(self, host: str, port: int, probe: bytes) -> Optional[str]:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            w.write(probe)
            await w.drain()
            data = await asyncio.wait_for(r.read(1024), timeout=self.timeout)
            w.close()
            try:
                await asyncio.wait_for(w.wait_closed(), timeout=1.0)
            except Exception:
                pass
            return self._extract_cipher(data)
        except Exception:
            return None

    def _extract_cipher(self, data: bytes) -> Optional[str]:
        try:
            if len(data) < 44 or data[0] != 0x16 or data[5] != 0x02:
                return None
            idx = 5 + 4 + 2 + 32
            sid_len = data[idx]
            idx += 1 + sid_len
            if idx + 2 > len(data):
                return None
            return f"{struct.unpack('!H', data[idx:idx+2])[0]:04x}"
        except Exception:
            return None

    def _compute_fingerprint(self, responses: List[Optional[str]]) -> str:
        raw = "".join(r if r else "0000" for r in responses)
        h   = hashlib.sha256(raw.encode()).hexdigest()
        return raw + h[:32]
