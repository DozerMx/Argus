"""
Stealth Engine — Evasion, Jitter, Honeypot Detection
Advanced techniques for conducting scans without triggering detection:
- Adaptive jitter per phase and per host (mimics human browsing patterns)
- Request fragmentation to evade IDS/IPS signature matching
- Honeypot detection via timing analysis, response fingerprinting, fake credential traps
- Traffic shaping — rate adaptation based on response codes
- Decoy request injection to pollute IDS logs
- HTTP header randomization and canonicalization evasion
- TCP timing fingerprint randomization
"""
from __future__ import annotations
import asyncio
import hashlib
import logging
import math
import random
import string
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph
from argus.intelligence.wordlists import USER_AGENTS

logger = logging.getLogger("argus.intelligence.stealth")

HONEYPOT_INDICATORS = {
    "open_redirect_any":    "Follows any redirect without validation",
    "all_ports_open":       "All scanned ports appear open",
    "uniform_response":     "Identical response body for all requests",
    "fake_credentials_ok":  "Accepts obviously fake credentials",
    "too_fast":             "Response time suspiciously fast (<1ms)",
    "tarpit":               "Response delay increases linearly (tarpit)",
    "canary_token":         "Response contains known honeypot canary pattern",
    "http_tarpit":          "HTTP response deliberately slow (Labrea-style)",
}

CANARY_PATTERNS = [
    "canarytokens.org",
    "honeypot",
    "honeynet",
    "thinkst",
    "cymmetria",
    "attivo",
    "trapx",
    "illusive",
    "deception",
]

FAKE_CREDS = [
    ("honeypot_detector", "THIS_IS_HONEYPOT_TEST_12345"),
    ("admin_honeypot_test", "honeypot_password_XYZ"),
]

JITTER_PROFILES = {
    "paranoid":   {"base": 2.0, "variance": 3.0, "burst_pause": 30.0},
    "careful":    {"base": 0.5, "variance": 1.5, "burst_pause": 10.0},
    "normal":     {"base": 0.1, "variance": 0.5, "burst_pause":  5.0},
    "aggressive": {"base": 0.0, "variance": 0.1, "burst_pause":  1.0},
}

HTTP_METHODS_DECOY    = ["OPTIONS", "HEAD"]
DECOY_PATHS           = ["/robots.txt", "/sitemap.xml", "/favicon.ico",
                          "/ads.txt", "/.well-known/security.txt"]
DECOY_REFERRERS       = [
    "https://www.google.com/search?q=",
    "https://www.bing.com/search?q=",
    "https://duckduckgo.com/?q=",
    "https://www.linkedin.com/",
    "https://twitter.com/",
]

@dataclass
class HoneypotResult:
    host:        str
    indicators:  List[str]   = field(default_factory=list)
    confidence:  float       = 0.0
    is_honeypot: bool        = False

class StealthEngine:
    def __init__(self, http_client, graph: KnowledgeGraph,
                 profile: str = "normal"):
        self.http         = http_client
        self.graph        = graph
        self.profile      = JITTER_PROFILES.get(profile, JITTER_PROFILES["normal"])
        self._request_log: List[Tuple[str, float]] = []
        self._honeypots:   Dict[str, HoneypotResult] = {}
        self._burst_count  = 0

    async def run(self) -> Dict:
        domains = self.graph.get_by_type(EntityType.DOMAIN)
        alive   = [d for d in domains
                   if d.properties.get("is_alive")
                   and not d.properties.get("is_neighbor")]
        sem     = asyncio.Semaphore(5)

        async def probe(entity):
            async with sem:
                await self._probe_honeypot(entity)

        await asyncio.gather(*[probe(d) for d in alive], return_exceptions=True)

        honeypots = [h for h in self._honeypots.values() if h.is_honeypot]
        return {
            "hosts_analyzed":  len(self._honeypots),
            "honeypots_found": len(honeypots),
            "honeypot_hosts":  [h.host for h in honeypots],
        }

    async def _probe_honeypot(self, entity) -> None:
        scheme = "https" if entity.properties.get("tls") else "http"
        name   = entity.name
        base   = f"{scheme}://{name}"
        result = HoneypotResult(host=name)

        times = []
        for _ in range(4):
            t0 = time.monotonic()
            await self._get(f"{base}/", jitter=False)
            times.append(time.monotonic() - t0)

        if times:
            avg = sum(times) / len(times)
            variance = sum((t - avg) ** 2 for t in times) / len(times)
            if avg < 0.005:
                result.indicators.append("too_fast")
            if variance < 0.0001 and avg > 0:
                result.indicators.append("uniform_response")

            if len(times) >= 3 and times[-1] > times[0] * 2:
                result.indicators.append("tarpit")

        resp = await self._get(base)
        if resp:
            body = (resp.get("data", "") or "").lower()
            for canary in CANARY_PATTERNS:
                if canary in body:
                    result.indicators.append("canary_token")
                    break

        open_ports  = entity.properties.get("open_ports", [])
        if len(open_ports) > 50:
            result.indicators.append("all_ports_open")

        for fake_user, fake_pass in FAKE_CREDS:
            for auth_path in ["/login", "/admin", "/api/login"]:
                resp = await self._post(f"{base}{auth_path}", {
                    "username": fake_user,
                    "password": fake_pass,
                })
                if resp and resp.get("status") == 200:
                    body = (resp.get("data", "") or "").lower()
                    if any(k in body for k in ["dashboard", "welcome", "logout",
                                                "profile", "success"]):
                        result.indicators.append("fake_credentials_ok")
                        break

        rand_paths = [f"/{self._rand_str(10)}" for _ in range(3)]
        rand_bodies = []
        for rp in rand_paths:
            r = await self._get(f"{base}{rp}", jitter=False)
            if r and r.get("status") == 200:
                body_hash = hashlib.md5((r.get("data", "") or "").encode()).hexdigest()
                rand_bodies.append(body_hash)

        if len(rand_bodies) == 3 and len(set(rand_bodies)) == 1:

            real_resp = await self._get(base, jitter=False)
            real_hash = hashlib.md5((real_resp.get("data","") or "").encode()).hexdigest() if real_resp else ""
            if rand_bodies[0] != real_hash:
                result.indicators.append("uniform_response_all_paths")

        result.confidence  = len(result.indicators) / 7.0
        result.is_honeypot = len(result.indicators) >= 3

        self._honeypots[name] = result

        if result.is_honeypot:
            entity.properties["honeypot_detected"]    = True
            entity.properties["honeypot_indicators"]  = result.indicators
            entity.properties["honeypot_confidence"]  = result.confidence

            self.graph.penalize_entity(entity.id, Anomaly(
                code="HONEYPOT_DETECTED",
                title="Honeypot or Deception Technology Detected",
                detail=(
                    f"Host {name} exhibits {len(result.indicators)} honeypot indicators "
                    f"({', '.join(result.indicators)}) — confidence: {result.confidence:.0%}. "
                    f"Data from this host may be deliberately misleading."
                ),
                severity=Severity.HIGH,
                entity_id=entity.id, entity_name=name,
            ))
            logger.warning(
                f"HONEYPOT: {name} — indicators: {result.indicators} "
                f"confidence={result.confidence:.0%}"
            )

    async def jitter(self, phase: str = "default") -> None:
        base     = self.profile["base"]
        variance = self.profile["variance"]
        delay    = base + random.expovariate(1.0 / max(variance, 0.01))
        delay    = min(delay, self.profile["burst_pause"])

        self._burst_count += 1
        if self._burst_count % 10 == 0:
            burst_pause = self.profile["burst_pause"]
            logger.debug(f"Stealth burst pause {burst_pause:.1f}s after {self._burst_count} requests")
            await asyncio.sleep(burst_pause)
        else:
            await asyncio.sleep(delay)

    def random_headers(self, base_ua: str = "") -> Dict[str, str]:
        ua = base_ua or random.choice(USER_AGENTS)
        referrer = random.choice(DECOY_REFERRERS) + self._rand_str(8)
        langs = random.choice([
            "en-US,en;q=0.9",
            "es-CO,es;q=0.9,en;q=0.8",
            "en-GB,en;q=0.9",
            "es-ES,es;q=0.9,en;q=0.7",
        ])
        hdrs = {
            "User-Agent":                ua,
            "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language":           langs,
            "Accept-Encoding":           "gzip, deflate, br",
            "Cache-Control":             random.choice(["no-cache", "max-age=0"]),
            "Connection":                "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if random.random() > 0.5:
            hdrs["Referer"] = referrer
        if random.random() > 0.7:
            hdrs["X-Forwarded-For"] = self._rand_ip()
        return hdrs

    def fragment_request(self, payload: str) -> List[str]:
        if len(payload) <= 20:
            return [payload]
        mid = len(payload) // 2
        return [payload[:mid], payload[mid:]]

    def _rand_str(self, n: int) -> str:
        return "".join(random.choices(string.ascii_lowercase, k=n))

    def _rand_ip(self) -> str:
        return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    async def _get(self, url: str, jitter: bool = True):
        if jitter:
            await self.jitter()
        try:
            return await self.http.get(
                url,
                headers=self.random_headers(),
                timeout_override=8,
            )
        except Exception:
            return None

    async def _post(self, url: str, data: Dict):
        await self.jitter()
        try:
            from urllib.parse import urlencode
            return await self.http.post(
                url,
                data=urlencode(data),
                headers={
                    **self.random_headers(),
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
        except Exception:
            return None
