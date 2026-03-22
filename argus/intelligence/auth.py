"""
Authentication and session management module.
Detects login forms, crawls authenticated sessions, analyzes JWT tokens,
probes Basic Auth endpoints, and enables credential-aware scanning.
"""
from __future__ import annotations
import asyncio
import base64
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.auth")

from argus.intelligence.wordlists import (
    WEAK_CREDS, AUTH_PATHS as COMMON_AUTH_PATHS,
    USER_AGENTS, JWT_WEAK_SECRETS,
)

JWT_PATTERN     = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
BEARER_PATTERN  = re.compile(r'Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)', re.I)
BASIC_AUTH_RE   = re.compile(r'Basic\s+([A-Za-z0-9+/=]+)', re.I)
INPUT_RE        = re.compile(r'<input[^>]*>', re.I | re.S)
FORM_RE         = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.S)
ACTION_RE       = re.compile(r'action=["\']([^"\']*)["\']', re.I)
METHOD_RE       = re.compile(r'method=["\']([^"\']*)["\']', re.I)
NAME_RE         = re.compile(r'name=["\']([^"\']*)["\']', re.I)
TYPE_RE         = re.compile(r'type=["\']([^"\']*)["\']', re.I)
VALUE_RE        = re.compile(r'value=["\']([^"\']*)["\']', re.I)

PASSWORD_FIELDS = {"password", "passwd", "pass", "pwd", "contraseña", "clave", "secret"}
USER_FIELDS     = {"user", "username", "email", "login", "usuario", "correo", "account"}

@dataclass
class LoginForm:
    url:          str
    action:       str
    method:       str
    user_field:   str
    pass_field:   str
    extra_fields: Dict[str, str] = field(default_factory=dict)

@dataclass
class AuthSession:
    url:          str
    cookies:      Dict[str, str]  = field(default_factory=dict)
    headers:      Dict[str, str]  = field(default_factory=dict)
    credentials:  Optional[Tuple] = None
    session_type: str             = "form"

@dataclass
class JWTFinding:
    token:       str
    header:      Dict
    payload:     Dict
    issues:      List[str] = field(default_factory=list)

class AuthIntelligence:
    def __init__(self, http_client, graph: KnowledgeGraph,
                 credentials: Optional[List[Tuple]] = None):
        self.http        = http_client
        self.graph       = graph
        self.credentials = credentials or []
        self._sessions:  List[AuthSession] = []
        self._jwt_cache: set = set()

    async def run(self) -> Dict:
        domains   = self.graph.get_by_type(EntityType.DOMAIN)
        alive     = [d for d in domains if d.properties.get("is_alive")]
        sem       = asyncio.Semaphore(10)
        results   = {
            "login_forms":   0,
            "weak_creds":    0,
            "jwt_findings":  0,
            "basic_auth":    0,
            "sessions":      0,
        }
        lock = asyncio.Lock()

        async def probe_domain(entity):
            scheme = "https" if entity.properties.get("tls") else "http"
            name   = entity.name
            async with sem:
                r = await self._probe_domain(scheme, name, entity)
                async with lock:
                    for k, v in r.items():
                        results[k] = results.get(k, 0) + v

        await asyncio.gather(*[probe_domain(d) for d in alive], return_exceptions=True)
        return results

    def _domain_creds(self, domain: str):
        """Generate domain-specific credentials."""
        apex   = domain.split(".")[-2] if "." in domain else domain
        extras = [
            (apex,         apex),
            (apex,         apex + "123"),
            (apex,         apex + "@2024"),
            ("admin",      apex),
            ("admin",      apex + "123"),
            ("admin",      apex.capitalize()),
        ]
        return WEAK_CREDS + extras

    async def _probe_domain(self, scheme: str, name: str, entity) -> Dict:
        found = {"login_forms": 0, "weak_creds": 0, "jwt_findings": 0,
                 "basic_auth": 0, "sessions": 0}

        for path in COMMON_AUTH_PATHS:
            resp = await self._get(f"{scheme}://{name}{path}")
            if not resp:
                continue
            status = resp.get("status", 0)
            body   = resp.get("data", "") or ""

            if status == 401:
                found["basic_auth"] += 1
                self._add_anomaly(entity, "BASIC_AUTH_EXPOSED",
                    f"Basic Auth prompt at {scheme}://{name}{path}",
                    Severity.MEDIUM)

                cracked = await self._brute_basic_auth(scheme, name, path)
                if cracked:
                    found["weak_creds"] += 1
                    self._add_anomaly(entity, "WEAK_CREDENTIALS",
                        f"Weak Basic Auth credentials at {path}: {cracked[0]}:{cracked[1]}",
                        Severity.CRITICAL)

            if status in (200, 302) and body:

                jwt_count = await self._extract_jwts(body, entity, f"{scheme}://{name}{path}")
                found["jwt_findings"] += jwt_count

                forms = self._extract_login_forms(body, f"{scheme}://{name}{path}")
                for form in forms:
                    found["login_forms"] += 1
                    self._add_anomaly(entity, "LOGIN_FORM_DETECTED",
                        f"Login form at {form.action} — fields: {form.user_field}, {form.pass_field}",
                        Severity.INFO)

                    all_creds = self._domain_creds(name) + self.credentials
                    session = await self._try_login(form, all_creds)
                    if session:
                        found["weak_creds"] += 1
                        found["sessions"]   += 1
                        self._sessions.append(session)
                        u, p = session.credentials or ("", "")
                        self._add_anomaly(entity, "WEAK_CREDENTIALS",
                            f"Valid credentials found at {form.action} — {u}:{p}",
                            Severity.CRITICAL)

        for oauth_path in ["/oauth/authorize", "/oauth2/authorize",
                           "/connect/authorize", "/.well-known/openid-configuration",
                           "/auth/realms", "/saml/login", "/sso/login"]:
            resp = await self._get(f"{scheme}://{name}{oauth_path}")
            if resp and resp.get("status", 0) in (200, 302):
                body = resp.get("data", "") or ""
                if any(k in body.lower() for k in
                       ("authorization_endpoint", "token_endpoint",
                        "client_id", "scope", "openid", "saml")):
                    self._add_anomaly(entity, "OAUTH_ENDPOINT_EXPOSED",
                        f"OAuth/SSO endpoint at {scheme}://{name}{oauth_path} — verify PKCE and token handling",
                        Severity.INFO)
                    break

        raw = entity.properties.get("http_headers", {})
        for hdr_val in raw.values():
            if isinstance(hdr_val, str):
                c = await self._extract_jwts(hdr_val, entity, f"{scheme}://{name}")
                found["jwt_findings"] += c

        return found

    def _extract_login_forms(self, body: str, base_url: str) -> List[LoginForm]:
        forms = []
        for m in FORM_RE.finditer(body):
            form_html  = m.group(0)
            action_m   = ACTION_RE.search(form_html)
            method_m   = METHOD_RE.search(form_html)
            action     = action_m.group(1) if action_m else base_url
            method     = (method_m.group(1) if method_m else "POST").upper()
            action     = urljoin(base_url, action)

            user_field  = None
            pass_field  = None
            extra       = {}

            for inp in INPUT_RE.finditer(form_html):
                inp_html   = inp.group(0)
                name_m     = NAME_RE.search(inp_html)
                type_m     = TYPE_RE.search(inp_html)
                value_m    = VALUE_RE.search(inp_html)
                field_name = (name_m.group(1) if name_m else "").lower()
                field_type = (type_m.group(1) if type_m else "text").lower()
                field_val  = value_m.group(1) if value_m else ""

                if field_type == "password" or field_name in PASSWORD_FIELDS:
                    pass_field = name_m.group(1) if name_m else "password"
                elif field_name in USER_FIELDS:
                    user_field = name_m.group(1) if name_m else "username"
                elif field_type not in ("submit", "button", "image", "reset"):
                    if field_name:
                        extra[field_name] = field_val

            if user_field and pass_field:
                forms.append(LoginForm(
                    url=base_url, action=action, method=method,
                    user_field=user_field, pass_field=pass_field,
                    extra_fields=extra,
                ))
        return forms

    _lockout_hosts: set = set()

    async def _try_login(self, form: LoginForm,
                         creds: List[Tuple]) -> Optional[AuthSession]:
        host = urlparse(form.action).netloc
        if host in self._lockout_hosts:
            return None

        csrf_token  = None
        csrf_field  = None
        page_resp   = await self._get(form.url)
        if page_resp:
            page_body = page_resp.get("data", "") or ""
            for inp in INPUT_RE.finditer(page_body):
                inp_html = inp.group(0)
                name_m   = NAME_RE.search(inp_html)
                type_m   = TYPE_RE.search(inp_html)
                value_m  = VALUE_RE.search(inp_html)
                if name_m and type_m:
                    itype = type_m.group(1).lower()
                    iname = name_m.group(1).lower()
                    if itype == "hidden" and any(k in iname for k in
                            ("csrf", "token", "_token", "authenticity",
                             "nonce", "__requestverificationtoken")):
                        csrf_field = name_m.group(1)
                        csrf_token = value_m.group(1) if value_m else ""

            if any(k in page_body.lower() for k in
                   ("recaptcha", "g-recaptcha", "hcaptcha",
                    "turnstile", "captcha")):
                logger.debug(f"CAPTCHA detected at {form.action} — skipping brute force")
                return None

        consec_fails = 0
        for username, password in creds:
            data = {**form.extra_fields,
                    form.user_field: username,
                    form.pass_field: password}
            if csrf_field and csrf_token is not None:
                data[csrf_field] = csrf_token
            try:
                resp = await self.http.post(
                    form.action,
                    data=urlencode(data),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if not resp:
                    continue
                status = resp.get("status", 0)
                body   = resp.get("data", "") or ""
                hdrs   = resp.get("headers", {}) or {}

                if self._login_success(status, body, hdrs, form.action):
                    cookies = self._extract_cookies(hdrs)
                    return AuthSession(
                        url=form.action,
                        cookies=cookies,
                        credentials=(username, password),
                        session_type="form",
                    )

                if status in (429, 423) or "locked" in body.lower() or                         "too many" in body.lower() or "account locked" in body.lower():
                    consec_fails += 3
                else:
                    consec_fails += 1
                if consec_fails >= 5:
                    logger.debug(f"Lockout detected at {form.action} — stopping")
                    self._lockout_hosts.add(host)
                    return None
            except Exception:
                pass
        return None

    def _login_success(self, status: int, body: str,
                       headers: Dict, form_url: str) -> bool:
        if status in (301, 302):
            loc = headers.get("location", headers.get("Location", ""))

            if loc and "login" not in loc.lower() and "error" not in loc.lower():
                return True
        if status == 200:
            body_lower = body.lower()

            if any(k in body_lower for k in ["invalid", "incorrect", "wrong",
                                              "failed", "error", "try again"]):
                return False

            if any(k in body_lower for k in ["logout", "sign out", "dashboard",
                                              "welcome", "profile", "account"]):
                return True
        return False

    async def _brute_basic_auth(self, scheme: str, name: str,
                                path: str) -> Optional[Tuple]:
        for username, password in WEAK_CREDS + self.credentials:
            cred   = base64.b64encode(f"{username}:{password}".encode()).decode()
            try:
                resp = await self.http.get(
                    f"{scheme}://{name}{path}",
                    headers={"Authorization": f"Basic {cred}"},
                )
                if resp and resp.get("status", 0) == 200:
                    return (username, password)
            except Exception:
                pass
        return None

    async def _extract_jwts(self, content: str, entity,
                            source_url: str) -> int:
        count = 0
        for m in JWT_PATTERN.finditer(content):
            token = m.group(0)
            if token in self._jwt_cache:
                continue
            self._jwt_cache.add(token)
            finding = self._analyze_jwt(token)
            if not finding:
                continue
            count += 1
            for issue in finding.issues:
                sev = Severity.CRITICAL if "none" in issue.lower() or "weak" in issue.lower() \
                      else Severity.HIGH
                self._add_anomaly(entity, "JWT_VULNERABILITY",
                    f"{issue} — token from {source_url}",
                    sev)
            if not finding.issues:
                self._add_anomaly(entity, "JWT_EXPOSED",
                    f"JWT token exposed in response at {source_url}",
                    Severity.MEDIUM)
        return count

    def _analyze_jwt(self, token: str) -> Optional[JWTFinding]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            def b64decode_pad(s):
                s += "=" * (-len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(s))

            header  = b64decode_pad(parts[0])
            payload = b64decode_pad(parts[1])
            issues  = []

            alg = header.get("alg", "").lower()
            if alg == "none":
                issues.append("JWT uses alg=none — signature not verified")
            elif alg in ("hs256", "hs384", "hs512"):

                cracked = self._brute_jwt_secret(token, alg)
                if cracked is not None:
                    issues.append(f"JWT secret cracked: '{cracked}' — token fully compromised")
                else:
                    issues.append("JWT uses symmetric HMAC — secret may be brute-forceable")

            exp = payload.get("exp")
            if exp and exp < time.time():
                issues.append("JWT token is expired but was found in response")

            sensitive_keys = {"password", "passwd", "secret", "key", "api_key",
                               "token", "credit_card", "ssn"}
            for key in payload:
                if key.lower() in sensitive_keys:
                    issues.append(f"Sensitive field '{key}' in JWT payload")

            return JWTFinding(token=token[:20] + "...",
                              header=header, payload=payload, issues=issues)
        except Exception:
            return None

    def _brute_jwt_secret(self, token: str, alg: str) -> "Optional[str]":
        """Try common weak secrets against JWT signature."""
        try:
            import hmac, hashlib, base64
            header_b64, payload_b64, sig_b64 = token.split(".")
            msg     = f"{header_b64}.{payload_b64}".encode()
            sig_b64 += "=" * (-len(sig_b64) % 4)
            real_sig = base64.urlsafe_b64decode(sig_b64)
            hash_fn  = {
                "hs256": hashlib.sha256,
                "hs384": hashlib.sha384,
                "hs512": hashlib.sha512,
            }.get(alg, hashlib.sha256)
            for secret in JWT_WEAK_SECRETS:
                test = hmac.new(secret.encode(), msg, hash_fn).digest()
                if test == real_sig:
                    return secret
        except Exception:
            pass
        return None

    def _extract_cookies(self, headers: Dict) -> Dict[str, str]:
        cookies = {}
        raw     = headers.get("set-cookie", headers.get("Set-Cookie", ""))
        if isinstance(raw, list):
            raw = "; ".join(raw)
        for part in raw.split(";"):
            kv = part.strip().split("=", 1)
            if len(kv) == 2:
                cookies[kv[0].strip()] = kv[1].strip()
        return cookies

    def _add_anomaly(self, entity, code: str, detail: str,
                     severity: Severity) -> None:
        self.graph.penalize_entity(entity.id, Anomaly(
            code=code,
            title=code.replace("_", " ").title(),
            detail=detail,
            severity=severity,
            entity_id=entity.id,
            entity_name=entity.name,
        ))
        if severity in (Severity.CRITICAL, Severity.HIGH):
            logger.warning(f"AUTH: {code} on {entity.name} — {detail[:80]}")

    async def _get(self, url: str):
        try:
            return await self.http.get(url, timeout_override=8)
        except Exception:
            return None

    @property
    def sessions(self) -> List[AuthSession]:
        return self._sessions
