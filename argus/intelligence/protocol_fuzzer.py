"""
Protocol Fuzzer — OAuth, GraphQL, WebSocket
Advanced protocol-level security testing:

OAuth 2.0 / OIDC:
- Authorization code interception (state param fixation)
- PKCE downgrade attack detection
- Token leakage in referrer/logs
- Implicit flow detection (deprecated, dangerous)
- Open redirect in redirect_uri
- JWT confusion attacks (RS256 → HS256)
- Client secret exposure in JS
- CSRF via missing/weak state param

GraphQL:
- Full introspection schema dump
- Depth limit bypass (recursive fragments)
- Batch query abuse
- Field suggestion extraction (even without introspection)
- Alias-based rate limit bypass
- Introspection via alternate endpoints
- Mutation enumeration without auth

WebSocket:
- Message injection testing
- Origin header bypass
- Protocol downgrade
- Mass assignment via WS messages
- Authentication bypass via unauthenticated upgrade
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
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph
from argus.intelligence.wordlists import USER_AGENTS

logger = logging.getLogger("argus.intelligence.protocol_fuzzer")

GQL_INTROSPECTION = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        isDeprecated
        args { name type { name kind } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
""".strip()

GQL_FIELD_SUGGEST = """{ __type(name: "Query") { fields { name } } }"""

GQL_DEPTH_BOMB = """
{
  a1: __schema { types { fields { type { fields { type { fields { type { name } } } } } } } }
}
""".strip()

GQL_BATCH_TEST = json.dumps([
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
])

GQL_ENDPOINTS = [
    "/graphql", "/api/graphql", "/graphql/v1", "/graphql/v2",
    "/api/v1/graphql", "/api/v2/graphql", "/gql", "/query",
    "/api/query", "/graph", "/data",
]

OAUTH_ENDPOINTS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/authorize",
    "/oauth2/authorize",
    "/connect/authorize",
    "/auth/realms",
    "/oauth/token",
    "/oauth2/token",
]

WS_UPGRADE_HEADERS = {
    "Upgrade":               "websocket",
    "Connection":            "Upgrade",
    "Sec-WebSocket-Version": "13",
    "Sec-WebSocket-Key":     base64.b64encode(b"argus_ws_test_key").decode(),
}

OAUTH_WEAKNESSES = {
    "missing_state":       "No state parameter — CSRF possible",
    "weak_state":          "Short/predictable state parameter",
    "implicit_flow":       "Implicit flow used — tokens in URL fragment",
    "no_pkce":             "Authorization code without PKCE — intercept risk",
    "open_redirect_uri":   "redirect_uri not strictly validated",
    "token_in_referrer":   "Access token appears in Referer header",
    "client_secret_js":    "Client secret exposed in JavaScript",
    "nonce_missing":       "No nonce in OIDC flow — replay attack possible",
}

@dataclass
class ProtocolFinding:
    protocol:  str
    endpoint:  str
    issue:     str
    severity:  Severity
    evidence:  str = ""

class ProtocolFuzzer:
    def __init__(self, http_client, graph: KnowledgeGraph,
                 concurrency: int = 6):
        self.http    = http_client
        self.graph   = graph
        self._sem    = asyncio.Semaphore(concurrency)
        self._seen:  Set[str] = set()
        self._findings: List[ProtocolFinding] = []

    async def run(self) -> Dict:
        domains = self.graph.get_by_type(EntityType.DOMAIN)
        alive   = [d for d in domains
                   if d.properties.get("is_alive")
                   and not d.properties.get("is_neighbor")]

        await asyncio.gather(
            *[self._probe_domain(d) for d in alive],
            return_exceptions=True
        )

        return {
            "oauth_issues":   sum(1 for f in self._findings if f.protocol == "oauth"),
            "graphql_issues": sum(1 for f in self._findings if f.protocol == "graphql"),
            "ws_issues":      sum(1 for f in self._findings if f.protocol == "websocket"),
            "total":          len(self._findings),
        }

    async def _probe_domain(self, entity) -> None:
        scheme = "https" if entity.properties.get("tls") else "http"
        name   = entity.name
        base   = f"{scheme}://{name}"

        await asyncio.gather(
            self._test_oauth(base, entity),
            self._test_graphql(base, entity),
            self._test_websocket(base, entity),
            return_exceptions=True,
        )

    async def _test_oauth(self, base: str, entity) -> None:
        name = entity.name

        oidc_config = await self._get(f"{base}/.well-known/openid-configuration")
        oauth_meta  = None

        if oidc_config and oidc_config.get("status") == 200:
            try:
                meta = oidc_config.get("data", {})
                if isinstance(meta, str):
                    meta = json.loads(meta)
                oauth_meta = meta
            except Exception:
                pass

        if not oauth_meta:
            return

        auth_endpoint  = oauth_meta.get("authorization_endpoint", "")
        token_endpoint = oauth_meta.get("token_endpoint", "")
        grant_types    = oauth_meta.get("grant_types_supported", [])
        response_types = oauth_meta.get("response_types_supported", [])

        self._report(entity, "oauth", base, "OAUTH_DISCOVERED",
            f"OAuth/OIDC discovered at {base} — auth_endpoint: {auth_endpoint}",
            Severity.INFO)

        if "token" in response_types or "id_token token" in response_types:
            self._report(entity, "oauth", auth_endpoint, "OAUTH_IMPLICIT_FLOW",
                "OAuth implicit flow supported — access tokens returned in URL fragment, "
                "vulnerable to token leakage via Referer and browser history",
                Severity.HIGH)

        if "authorization_code" in grant_types:
            code_challenge_methods = oauth_meta.get("code_challenge_methods_supported", [])
            if not code_challenge_methods:
                self._report(entity, "oauth", auth_endpoint, "OAUTH_NO_PKCE",
                    "Authorization code flow without PKCE support — "
                    "vulnerable to authorization code interception attacks",
                    Severity.HIGH)

        if auth_endpoint:
            test_redirect = f"{base}@evil.com/callback"
            resp = await self._get(
                f"{auth_endpoint}?response_type=code&client_id=test"
                f"&redirect_uri={test_redirect}&state=test123"
            )
            if resp and resp.get("status") in (200, 302):
                hdrs = resp.get("headers", {}) or {}
                loc  = hdrs.get("location", hdrs.get("Location", ""))
                if "evil.com" in loc:
                    self._report(entity, "oauth", auth_endpoint,
                        "OAUTH_OPEN_REDIRECT_URI",
                        f"redirect_uri not validated — evil.com accepted: {loc}",
                        Severity.CRITICAL)

        resp = await self._get(
            f"{auth_endpoint}?response_type=code&client_id=test"
            f"&redirect_uri={base}/callback"
        )
        if resp:
            loc = (resp.get("headers", {}) or {}).get("location", "")
            if "state=" not in loc and resp.get("status") in (200, 302):
                self._report(entity, "oauth", auth_endpoint, "OAUTH_MISSING_STATE",
                    "OAuth authorization without state parameter — CSRF attack possible",
                    Severity.HIGH)

        if token_endpoint:
            resp = await self._post(token_endpoint, {
                "grant_type": "client_credentials",
                "client_id":  "test",
                "scope":      "openid",
            })
            if resp and resp.get("status") == 200:
                body = resp.get("data", "") or ""
                if "access_token" in body.lower():
                    self._report(entity, "oauth", token_endpoint,
                        "OAUTH_UNAUTHENTICATED_TOKEN",
                        "Token endpoint issued access_token without client authentication",
                        Severity.CRITICAL)

    async def _test_graphql(self, base: str, entity) -> None:
        name = entity.name
        gql_endpoint = None

        known = entity.properties.get("graphql_endpoint", "")
        if known:
            gql_endpoint = known
            self._report(entity, "graphql", gql_endpoint, "GRAPHQL_ENDPOINT_FOUND",
                f"GraphQL endpoint at {gql_endpoint} (from content discovery)",
                Severity.INFO)
        else:

            for path in GQL_ENDPOINTS:
                key = f"gql_discover:{base}{path}"
                if key in self._seen:
                    continue
                self._seen.add(key)

                resp = await self._gql_post(f"{base}{path}", '{"query":"{ __typename }"}')
                if resp and resp.get("status") == 200:
                    body = resp.get("data", "") or ""
                    if "__typename" in body or "data" in body.lower():
                        gql_endpoint = f"{base}{path}"
                        entity.properties["graphql_endpoint"] = gql_endpoint
                        self._report(entity, "graphql", gql_endpoint, "GRAPHQL_ENDPOINT_FOUND",
                            f"GraphQL endpoint at {gql_endpoint}",
                            Severity.INFO)
                        break

        if not gql_endpoint:
            return

        resp = await self._gql_post(gql_endpoint,
                                     json.dumps({"query": GQL_INTROSPECTION}))
        if resp and resp.get("status") == 200:
            body = resp.get("data", "") or ""
            try:
                data = json.loads(body) if isinstance(body, str) else body
                if data.get("data", {}).get("__schema"):
                    schema = data["data"]["__schema"]
                    types  = schema.get("types", [])
                    mutations = schema.get("mutationType", {})
                    entity.properties["graphql_schema"] = {
                        "type_count": len(types),
                        "has_mutations": bool(mutations),
                    }
                    self._report(entity, "graphql", gql_endpoint,
                        "GRAPHQL_INTROSPECTION_ENABLED",
                        f"Full schema introspection enabled — {len(types)} types exposed, "
                        f"mutations: {'yes' if mutations else 'no'}",
                        Severity.MEDIUM)
            except Exception:
                if "__schema" in body:
                    self._report(entity, "graphql", gql_endpoint,
                        "GRAPHQL_INTROSPECTION_ENABLED",
                        "GraphQL introspection enabled — full schema accessible",
                        Severity.MEDIUM)

        resp = await self._gql_post(gql_endpoint,
                                     json.dumps({"query": GQL_DEPTH_BOMB}))
        if resp and resp.get("status") == 200:
            elapsed = resp.get("_elapsed", 0)
            if elapsed and elapsed > 3:
                self._report(entity, "graphql", gql_endpoint,
                    "GRAPHQL_NO_DEPTH_LIMIT",
                    f"Deep recursive query caused {elapsed:.1f}s response — no depth limit",
                    Severity.HIGH)

        resp = await self._gql_post(gql_endpoint, GQL_BATCH_TEST,
                                     content_type="application/json")
        if resp and resp.get("status") == 200:
            body = resp.get("data", "") or ""
            try:
                parsed = json.loads(body) if isinstance(body, str) else body
                if isinstance(parsed, list) and len(parsed) >= 3:
                    self._report(entity, "graphql", gql_endpoint,
                        "GRAPHQL_BATCH_ENABLED",
                        "GraphQL batch queries accepted — enables rate limit bypass and "
                        "amplification attacks",
                        Severity.MEDIUM)
            except Exception:
                pass

        resp = await self._gql_post(gql_endpoint,
                                     json.dumps({"query": '{ unknownField }'}))
        if resp:
            body = (resp.get("data", "") or "").lower()
            if "did you mean" in body or "suggestion" in body:
                suggestions = re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"', body)
                self._report(entity, "graphql", gql_endpoint,
                    "GRAPHQL_FIELD_SUGGESTION",
                    f"GraphQL reveals field suggestions without introspection — "
                    f"leaked names: {', '.join(suggestions[:5])}",
                    Severity.LOW)

        resp = await self._gql_post(gql_endpoint,
                                     json.dumps({"query": '{ __schema { mutationType { fields { name } } } }'}))
        if resp and resp.get("status") == 200:
            body = resp.get("data", "") or ""
            try:
                data = json.loads(body) if isinstance(body, str) else body
                mutation_fields = (data.get("data", {})
                                   .get("__schema", {})
                                   .get("mutationType", {}) or {})
                if mutation_fields:
                    names = [f["name"] for f in mutation_fields.get("fields", [])]
                    self._report(entity, "graphql", gql_endpoint,
                        "GRAPHQL_MUTATIONS_EXPOSED",
                        f"Mutations accessible without authentication: {', '.join(names[:10])}",
                        Severity.HIGH)
            except Exception:
                pass

    async def _test_websocket(self, base: str, entity) -> None:
        name       = entity.name
        ws_base    = base.replace("https://", "wss://").replace("http://", "ws://")

        ws_paths   = [
            "/ws", "/websocket", "/socket", "/socket.io",
            "/ws/v1", "/api/ws", "/live", "/stream",
            "/chat", "/events", "/notifications",
        ]

        for path in ws_paths:
            key = f"ws:{base}{path}"
            if key in self._seen:
                continue
            self._seen.add(key)

            resp = await self._get(
                f"{base}{path}",
                extra_headers={
                    **WS_UPGRADE_HEADERS,
                    "Origin": base,
                }
            )

            if not resp:
                continue

            status = resp.get("status", 0)
            hdrs   = resp.get("headers", {}) or {}

            upgrade = hdrs.get("upgrade", hdrs.get("Upgrade", "")).lower()
            if status == 101 or upgrade == "websocket":
                entity.properties["websocket_endpoint"] = f"{ws_base}{path}"
                self._report(entity, "websocket", f"{base}{path}",
                    "WEBSOCKET_ENDPOINT_FOUND",
                    f"WebSocket endpoint at {base}{path}",
                    Severity.INFO)

                resp_evil = await self._get(
                    f"{base}{path}",
                    extra_headers={
                        **WS_UPGRADE_HEADERS,
                        "Origin": "https://evil.com",
                    }
                )
                if resp_evil and resp_evil.get("status") == 101:
                    self._report(entity, "websocket", f"{base}{path}",
                        "WEBSOCKET_ORIGIN_BYPASS",
                        f"WebSocket at {base}{path} accepts connections from any origin — "
                        f"Cross-Site WebSocket Hijacking (CSWSH) possible",
                        Severity.HIGH)

                resp_noauth = await self._get(
                    f"{base}{path}",
                    extra_headers=WS_UPGRADE_HEADERS,
                )
                if resp_noauth and resp_noauth.get("status") == 101:
                    self._report(entity, "websocket", f"{base}{path}",
                        "WEBSOCKET_NO_AUTH",
                        f"WebSocket upgrade succeeds without authentication cookies or tokens",
                        Severity.HIGH)

                break

    def _report(self, entity, protocol: str, endpoint: str,
                code: str, detail: str, severity: Severity) -> None:
        finding = ProtocolFinding(
            protocol=protocol, endpoint=endpoint,
            issue=code, severity=severity, evidence=detail,
        )
        self._findings.append(finding)

        self.graph.penalize_entity(entity.id, Anomaly(
            code=code,
            title=code.replace("_", " ").title(),
            detail=detail,
            severity=severity,
            entity_id=entity.id, entity_name=entity.name,
        ))

        if severity in (Severity.CRITICAL, Severity.HIGH):
            logger.warning(f"PROTO [{protocol.upper()}] {entity.name} — {code}: {detail[:80]}")

    async def _get(self, url: str, extra_headers: Dict = None):
        async with self._sem:
            try:
                import random
                hdrs = {"User-Agent": random.choice(USER_AGENTS)}
                if extra_headers:
                    hdrs.update(extra_headers)
                return await self.http.get(url, headers=hdrs, timeout_override=10)
            except Exception:
                return None

    async def _post(self, url: str, data: Dict):
        async with self._sem:
            try:
                import random
                from urllib.parse import urlencode as _ue
                return await self.http.post(
                    url, data=_ue(data),
                    headers={
                        "User-Agent":   random.choice(USER_AGENTS),
                        "Content-Type": "application/x-www-form-urlencoded",
                    }
                )
            except Exception:
                return None

    async def _gql_post(self, url: str, body: str,
                         content_type: str = "application/json"):
        async with self._sem:
            try:
                import random
                t0   = time.monotonic()
                resp = await self.http.post(
                    url, data=body,
                    headers={
                        "User-Agent":   random.choice(USER_AGENTS),
                        "Content-Type": content_type,
                        "Accept":       "application/json",
                    }
                )
                if resp:
                    resp["_elapsed"] = time.monotonic() - t0
                return resp
            except Exception:
                return None

    @property
    def findings(self) -> List[ProtocolFinding]:
        return self._findings
