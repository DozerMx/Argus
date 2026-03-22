"""
Smart parameter fuzzing engine.
Discovers parameters from forms, URLs, and JS endpoints.
Tests for SQLi, XSS, SSRF, IDOR, path traversal, and open redirect.
Uses differential analysis — compares response length, status, timing, content.
"""
from __future__ import annotations
import asyncio
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse, quote

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph
from argus.intelligence.wordlists import (
    SQLI_PAYLOADS, SQLI_ERRORS,
    XSS_PAYLOADS, XSS_INDICATORS,
    SSRF_PAYLOADS, SSRF_INDICATORS,
    TRAVERSAL_PAYLOADS, TRAVERSAL_INDICATORS,
    REDIRECT_PAYLOADS, REDIRECT_PARAMS,
    FUZZ_PARAMS, USER_AGENTS,
)

logger = logging.getLogger("argus.intelligence.fuzzer")

FORM_RE     = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.S)
INPUT_RE    = re.compile(r'<input[^>]*>', re.I | re.S)
ACTION_RE   = re.compile(r'action=["\']([^"\']*)["\']', re.I)
METHOD_RE   = re.compile(r'method=["\']([^"\']*)["\']', re.I)
NAME_RE     = re.compile(r'name=["\']([^"\']*)["\']', re.I)
TYPE_RE     = re.compile(r'type=["\']([^"\']*)["\']', re.I)
VALUE_RE    = re.compile(r'value=["\']([^"\']*)["\']', re.I)
URL_PARAM_RE = re.compile(r'[?&]([^=&]+)=([^&]*)')
JS_PARAM_RE  = re.compile(r'["\'](/[a-zA-Z0-9/_-]+\?[a-zA-Z0-9=&_-]+)["\']')
API_PATH_RE  = re.compile(r'["\']((?:/api|/v[0-9]|/rest)[a-zA-Z0-9/_-]+)["\']')

IDOR_MUTATIONS = ["0", "1", "2", "3", "10", "99", "100", "999", "1000", "-1", "-2", "0x1", "null", "undefined", "true", "false", "NaN", "Infinity", "00000000-0000-0000-0000-000000000001", "1e1", "1.0", "01"]

@dataclass
class FuzzResult:
    url:        str
    param:      str
    payload:    str
    vuln_type:  str
    evidence:   str
    severity:   Severity
    method:     str = "GET"

class ParameterFuzzer:
    def __init__(self, http_client, graph: KnowledgeGraph,
                 concurrency: int = 8, timeout: int = 10,
                 auth_session=None):
        self.http         = http_client
        self.graph        = graph
        self.concurrency  = concurrency
        self.timeout      = timeout
        self.auth_session = auth_session
        self._seen:       set = set()
        self._results:    List[FuzzResult] = []

    async def run(self) -> Dict:
        domains  = self.graph.get_by_type(EntityType.DOMAIN)
        alive    = [d for d in domains if d.properties.get("is_alive")
                    and not d.properties.get("is_neighbor")]
        sem      = asyncio.Semaphore(self.concurrency)
        total    = 0
        lock     = asyncio.Lock()

        async def fuzz_domain(entity):
            nonlocal total
            async with sem:
                n = await self._fuzz_domain(entity)
                async with lock:
                    total += n

        await asyncio.gather(*[fuzz_domain(d) for d in alive], return_exceptions=True)
        return {
            "findings":       total,
            "sqli":           sum(1 for r in self._results if r.vuln_type == "sqli"),
            "xss":            sum(1 for r in self._results if r.vuln_type == "xss"),
            "ssrf":           sum(1 for r in self._results if r.vuln_type == "ssrf"),
            "traversal":      sum(1 for r in self._results if r.vuln_type == "traversal"),
            "open_redirect":  sum(1 for r in self._results if r.vuln_type == "open_redirect"),
            "idor":           sum(1 for r in self._results if r.vuln_type == "idor"),
        }

    async def _fuzz_domain(self, entity) -> int:
        scheme  = "https" if entity.properties.get("tls") else "http"
        name    = entity.name
        base    = f"{scheme}://{name}"
        found   = 0

        paths   = entity.properties.get("discovered_paths", [])
        js_urls = entity.properties.get("js_urls", [])
        http_r  = entity.properties.get("http_body_sample", "")

        targets = set()

        for p in paths:
            path = p.get("path", "") if isinstance(p, dict) else str(p)
            if "?" in path:
                targets.add(urljoin(base, path))

        for js_url in (js_urls or []):
            resp = await self._get(js_url)
            if resp:
                body = resp.get("data", "") or ""
                for m in JS_PARAM_RE.finditer(body):
                    targets.add(urljoin(base, m.group(1)))
                for m in API_PATH_RE.finditer(body):
                    targets.add(urljoin(base, m.group(1)))

        if http_r:
            for m in URL_PARAM_RE.finditer(http_r):
                targets.add(urljoin(base, f"/?{m.group(1)}={m.group(2)}"))

        for param in FUZZ_PARAMS[:40]:
            targets.add(f"{base}/?{param}=1")
            targets.add(f"{base}/api?{param}=1")
            targets.add(f"{base}/api/v1?{param}=1")

        common = [
            f"{base}/search?q=test",
            f"{base}/user?id=1",
            f"{base}/users?id=1",
            f"{base}/page?id=1",
            f"{base}/post?id=1",
            f"{base}/article?id=1",
            f"{base}/product?id=1",
            f"{base}/item?id=1",
            f"{base}/order?id=1",
            f"{base}/api/user?id=1",
            f"{base}/api/users?id=1",
            f"{base}/api/v1/user?id=1",
            f"{base}/api/v1/users?id=1",
            f"{base}/api/v2/user?id=1",
            f"{base}/redirect?url=http://test.com",
            f"{base}/file?name=test.txt",
            f"{base}/download?file=test.pdf",
            f"{base}/include?page=home",
            f"{base}/view?template=home",
            f"{base}/load?module=home",
            f"{base}/index.php?page=home",
            f"{base}/index.php?id=1",
            f"{base}/admin?id=1",
            f"{base}/profile?id=1",
            f"{base}/account?id=1",
        ]
        targets.update(common)

        base_resp = await self._get(base)
        if base_resp:
            body = base_resp.get("data", "") or ""
            forms = self._extract_forms(body, base)
            for form in forms:
                n = await self._fuzz_form(form, entity)
                found += n

        for url in list(targets)[:30]:
            n = await self._fuzz_url(url, entity)
            found += n

        return found

    def _extract_forms(self, body: str, base_url: str) -> List[Dict]:
        forms = []
        for m in FORM_RE.finditer(body):
            form_html  = m.group(0)
            action_m   = ACTION_RE.search(form_html)
            method_m   = METHOD_RE.search(form_html)
            action     = urljoin(base_url, action_m.group(1) if action_m else "")
            method     = (method_m.group(1) if method_m else "GET").upper()
            fields     = {}
            for inp in INPUT_RE.finditer(form_html):
                name_m  = NAME_RE.search(inp.group(0))
                type_m  = TYPE_RE.search(inp.group(0))
                val_m   = VALUE_RE.search(inp.group(0))
                if name_m:
                    itype = (type_m.group(1) if type_m else "text").lower()
                    if itype not in ("submit", "button", "image", "reset", "hidden"):
                        fields[name_m.group(1)] = val_m.group(1) if val_m else "test"
            if fields:
                forms.append({"action": action, "method": method, "fields": fields})
        return forms

    async def _fuzz_form(self, form: Dict, entity) -> int:
        found  = 0
        action = form["action"]
        method = form["method"]
        fields = form["fields"]

        for field_name in fields:

            base_data  = {**fields}
            baseline   = await self._submit_form(action, method, base_data)
            if not baseline:
                continue

            r = await self._test_sqli_form(action, method, fields, field_name,
                                            baseline, entity)
            found += r

            r = await self._test_xss_form(action, method, fields, field_name,
                                           baseline, entity)
            found += r

        return found

    async def _fuzz_url(self, url: str, entity) -> int:
        found  = 0
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return 0

        baseline = await self._get(url)
        if not baseline:
            return 0

        for param in params:

            r = await self._test_sqli_url(url, param, baseline, entity)
            found += r

            r = await self._test_xss_url(url, param, baseline, entity)
            found += r

            r = await self._test_ssrf_url(url, param, baseline, entity)
            found += r

            r = await self._test_traversal_url(url, param, baseline, entity)
            found += r

            if any(k in param.lower() for k in ["url", "redirect", "next",
                                                  "return", "goto", "dest"]):
                r = await self._test_redirect_url(url, param, baseline, entity)
                found += r

            val = params[param][0] if params[param] else ""
            if val.isdigit():
                r = await self._test_idor_url(url, param, val, baseline, entity)
                found += r

        return found

    async def _test_sqli_form(self, action: str, method: str, fields: Dict,
                               target_field: str, baseline, entity) -> int:
        baseline_body = (baseline.get("data", "") or "").lower()
        baseline_len  = len(baseline_body)
        found = 0

        for payload, mode in SQLI_PAYLOADS:
            key = f"sqli:{action}:{target_field}:{payload[:20]}"
            if key in self._seen:
                continue
            self._seen.add(key)

            data = {**fields, target_field: payload}

            if mode == "time":
                t0   = time.monotonic()
                resp = await self._submit_form(action, method, data)
                elapsed = time.monotonic() - t0
                if elapsed >= 4.5:
                    self._report(entity, action, target_field, payload, "sqli",
                                 f"Time-based SQLi: {elapsed:.1f}s delay with payload '{payload}'",
                                 Severity.CRITICAL, method)
                    found += 1
            else:
                resp = await self._submit_form(action, method, data)
                if resp:
                    body = (resp.get("data", "") or "").lower()
                    if any(err in body for err in SQLI_ERRORS):
                        self._report(entity, action, target_field, payload, "sqli",
                                     f"Error-based SQLi: database error in response to '{payload}'",
                                     Severity.CRITICAL, method)
                        found += 1
        return found

    async def _test_sqli_url(self, url: str, param: str,
                              baseline, entity) -> int:
        baseline_body = (baseline.get("data", "") or "").lower()
        found = 0

        for payload, mode in SQLI_PAYLOADS:
            key = f"sqli:{url}:{param}:{payload[:20]}"
            if key in self._seen:
                continue
            self._seen.add(key)

            test_url = self._inject_param(url, param, payload)

            if mode == "time":
                t0      = time.monotonic()
                resp    = await self._get(test_url)
                elapsed = time.monotonic() - t0
                if elapsed >= 4.5:
                    self._report(entity, test_url, param, payload, "sqli",
                                 f"Time-based SQLi: {elapsed:.1f}s delay",
                                 Severity.CRITICAL)
                    found += 1
            else:
                resp = await self._get(test_url)
                if resp:
                    body = (resp.get("data", "") or "").lower()
                    if any(err in body for err in SQLI_ERRORS):
                        self._report(entity, test_url, param, payload, "sqli",
                                     f"Error-based SQLi: DB error in response",
                                     Severity.CRITICAL)
                        found += 1
        return found

    async def _test_xss_url(self, url: str, param: str,
                             baseline, entity) -> int:
        found = 0
        for payload, mode in XSS_PAYLOADS:
            key = f"xss:{url}:{param}:{payload[:20]}"
            if key in self._seen:
                continue
            self._seen.add(key)

            test_url = self._inject_param(url, param, payload)
            resp     = await self._get(test_url)
            if resp:
                body = resp.get("data", "") or ""

                if payload in body and any(ind in body.lower() for ind in XSS_INDICATORS + [payload[:15]]):
                    self._report(entity, test_url, param, payload, "xss",
                                 f"Reflected XSS: payload reflected unescaped in response",
                                 Severity.HIGH)
                    found += 1
                elif payload in body and "alert" in body.lower():
                    self._report(entity, test_url, param, payload, "xss",
                                 f"Possible reflected XSS: payload echoed in response",
                                 Severity.MEDIUM)
                    found += 1
        return found

    async def _test_xss_form(self, action: str, method: str, fields: Dict,
                              target_field: str, baseline, entity) -> int:
        found = 0
        for payload, mode in XSS_PAYLOADS:
            key = f"xss:{action}:{target_field}:{payload[:20]}"
            if key in self._seen:
                continue
            self._seen.add(key)

            data = {**fields, target_field: payload}
            resp = await self._submit_form(action, method, data)
            if resp:
                body = resp.get("data", "") or ""
                if payload in body and "<script" in body.lower():
                    self._report(entity, action, target_field, payload, "xss",
                                 f"Reflected XSS via form field '{target_field}'",
                                 Severity.HIGH, method)
                    found += 1
        return found

    async def _test_ssrf_url(self, url: str, param: str,
                              baseline, entity) -> int:
        found = 0
        baseline_status = baseline.get("status", 0)

        for payload, ptype in SSRF_PAYLOADS:
            key = f"ssrf:{url}:{param}:{ptype}"
            if key in self._seen:
                continue
            self._seen.add(key)

            test_url = self._inject_param(url, param, payload)
            resp     = await self._get(test_url)
            if resp:
                body   = (resp.get("data", "") or "").lower()
                status = resp.get("status", 0)
                if any(ind in body for ind in SSRF_INDICATORS):
                    self._report(entity, test_url, param, payload, "ssrf",
                                 f"SSRF confirmed: cloud metadata accessible via {ptype}",
                                 Severity.CRITICAL)
                    found += 1
                elif status == 200 and status != baseline_status and ptype == "localhost":
                    self._report(entity, test_url, param, payload, "ssrf",
                                 f"Potential SSRF: server fetched localhost URL",
                                 Severity.HIGH)
                    found += 1
        return found

    async def _test_traversal_url(self, url: str, param: str,
                                   baseline, entity) -> int:
        found = 0
        for payload, ptype in TRAVERSAL_PAYLOADS:
            key = f"trav:{url}:{param}:{ptype}"
            if key in self._seen:
                continue
            self._seen.add(key)

            test_url = self._inject_param(url, param, payload)
            resp     = await self._get(test_url)
            if resp:
                body = resp.get("data", "") or ""
                if any(ind in body for ind in TRAVERSAL_INDICATORS):
                    self._report(entity, test_url, param, payload, "traversal",
                                 f"Path traversal: sensitive file content in response ({ptype})",
                                 Severity.CRITICAL)
                    found += 1
        return found

    async def _test_redirect_url(self, url: str, param: str,
                                  baseline, entity) -> int:
        found = 0
        for payload, ptype in REDIRECT_PAYLOADS:
            key = f"redir:{url}:{param}:{ptype}"
            if key in self._seen:
                continue
            self._seen.add(key)

            test_url = self._inject_param(url, param, payload)
            resp     = await self._get(test_url)
            if resp:
                status = resp.get("status", 0)
                hdrs   = resp.get("headers", {}) or {}
                loc    = hdrs.get("location", hdrs.get("Location", ""))
                if status in (301, 302, 303, 307, 308) and "evil.com" in loc:
                    self._report(entity, test_url, param, payload, "open_redirect",
                                 f"Open redirect to {loc} via param '{param}'",
                                 Severity.HIGH)
                    found += 1
        return found

    async def _test_idor_url(self, url: str, param: str, orig_val: str,
                              baseline, entity) -> int:
        found = 0
        baseline_hash = hashlib.md5(
            (baseline.get("data", "") or "").encode()
        ).hexdigest()

        for mutation in IDOR_MUTATIONS:
            if mutation == orig_val:
                continue
            key = f"idor:{url}:{param}:{mutation}"
            if key in self._seen:
                continue
            self._seen.add(key)

            test_url = self._inject_param(url, param, mutation)
            resp     = await self._get(test_url)
            if resp:
                status  = resp.get("status", 0)
                content = resp.get("data", "") or ""
                rhash   = hashlib.md5(content.encode()).hexdigest()

                if (status == 200 and rhash != baseline_hash
                        and len(content) > 100):
                    self._report(entity, test_url, param, mutation, "idor",
                                 f"Potential IDOR: different resource returned for id={mutation}",
                                 Severity.HIGH)
                    found += 1
                    break
        return found

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))

    def _report(self, entity, url: str, param: str, payload: str,
                vuln_type: str, evidence: str, severity: Severity,
                method: str = "GET") -> None:
        result = FuzzResult(url=url, param=param, payload=payload[:60],
                            vuln_type=vuln_type, evidence=evidence,
                            severity=severity, method=method)
        self._results.append(result)
        code = {
            "sqli":         "SQL_INJECTION",
            "xss":          "XSS_REFLECTED",
            "ssrf":         "SSRF_VULNERABILITY",
            "traversal":    "PATH_TRAVERSAL",
            "open_redirect":"OPEN_REDIRECT",
            "idor":         "IDOR_VULNERABILITY",
        }.get(vuln_type, "FUZZ_FINDING")

        self.graph.penalize_entity(entity.id, Anomaly(
            code=code,
            title=code.replace("_", " ").title(),
            detail=f"{evidence} | param={param} | payload={payload[:40]}",
            severity=severity,
            entity_id=entity.id,
            entity_name=entity.name,
        ))
        logger.warning(f"FUZZ [{vuln_type.upper()}] {entity.name} — {param}: {evidence[:80]}")

    async def _get(self, url: str):
        try:
            import random
            hdrs = {"User-Agent": random.choice(USER_AGENTS)}
            if self.auth_session and self.auth_session.cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v
                                        in self.auth_session.cookies.items())
                hdrs["Cookie"] = cookie_str
            if self.auth_session and self.auth_session.headers:
                hdrs.update(self.auth_session.headers)
            return await self.http.get(url, headers=hdrs,
                                       timeout_override=self.timeout)
        except Exception:
            return None

    async def _submit_form(self, action: str, method: str,
                           data: Dict) -> Optional[Dict]:
        try:
            if method == "POST":
                return await self.http.post(
                    action,
                    data=urlencode(data),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            else:
                params = urlencode(data)
                return await self._get(f"{action}?{params}")
        except Exception:
            return None

    @property
    def results(self) -> List[FuzzResult]:
        return self._results
