"""
Argus Pivot Engine
Graph analysis and pivot operations for the security knowledge graph.

Core operations:
  - search_around(entity)   → all entities within N hops
  - find_path(A, B)         → relationship chain between two entities
  - co_hosted(domain)       → other domains sharing same IP
  - key_reuse(spki)         → certificates sharing public key (possible infra pivot)
  - issuer_pivot(ca)        → all domains using same certificate authority
  - timeline(entity)        → chronological events for entity
  - cluster_analysis()      → detect infrastructure clusters
  - top_risk()              → entities ranked by risk score
  - bridge_nodes()          → entities connecting otherwise unrelated clusters
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from argus.ontology.entities import (
    Anomaly, Entity, EntityType, RelationType, Severity,
)
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.ontology.pivot")

class PivotEngine:
    def __init__(self, graph: KnowledgeGraph):
        self.g = graph

    def search_around(
        self,
        entity_id: str,
        radius: int = 2,
        entity_types: Optional[List[EntityType]] = None,
    ) -> Dict[str, Any]:
        """
        Returns the subgraph centered on an entity within the given radius.
        Optionally filtered by entity type.
        """
        subgraph = self.g.ego_graph(entity_id, radius=radius)
        center = self.g.get_entity(entity_id)

        entities = subgraph.to_dict()["nodes"]
        if entity_types:
            entities = [e for e in entities if e["type"] in {t.value for t in entity_types}]

        return {
            "center":         center.to_dict() if center else None,
            "radius":         radius,
            "entity_count":   len(entities),
            "entities":       entities,
            "graph":          subgraph.to_vis_js(),
        }

    def find_path(self, source_id: str, target_id: str) -> Optional[Dict[str, Any]]:
        """Find relationship chain between two entities."""
        path = self.g.shortest_path(source_id, target_id)
        if not path:
            return None

        source = self.g.get_entity(source_id)
        target = self.g.get_entity(target_id)
        return {
            "source":    source.name if source else source_id,
            "target":    target.name if target else target_id,
            "hops":      len(path) - 1,
            "chain":     [e.to_dict() for e in path],
            "chain_str": " → ".join(e.name for e in path),
        }

    def co_hosted_domains(self, domain_name: str) -> List[Entity]:
        """
        Find all domains sharing the same IP as the target.
        Reveals shared hosting, adjacent infrastructure.
        """
        domain = self.g.get_by_name(domain_name)
        if not domain:
            return []

        ips = self.g.successors(domain.id, RelationType.RESOLVES_TO)
        co_hosted: Set[str] = set()

        for ip in ips:
            domain_names = self.g.get_domains_on_ip(ip.name)
            co_hosted.update(domain_names)

        co_hosted.discard(domain_name.lower())

        result = []
        for name in co_hosted:
            e = self.g.get_by_name(name)
            if e:
                result.append(e)
        return result

    def domains_on_ip(self, ip_name: str) -> List[Entity]:
        """All domains that resolve to or historically resolved to this IP."""
        names = self.g.get_domains_on_ip(ip_name)
        result = []
        for name in names:
            e = self.g.get_by_name(name)
            if e:
                result.append(e)
        return result

    def key_reuse(self, spki_sha256: str) -> List[Entity]:
        """
        Find certificates sharing the same public key (SPKI).
        Critical finding: same key across different domains = possible infrastructure reuse
        or cert issuance without key rotation.
        """
        cert_ids = self.g.get_certs_sharing_key(spki_sha256)
        result = []
        for cid in cert_ids:
            e = self.g.get_entity(cid)
            if e:
                result.append(e)
        return result

    def issuer_pivot(self, ca_name: str) -> List[Entity]:
        """
        Find all domains/certs issued by the same CA.
        Reveals related infrastructure using private CAs.
        """
        ca_entity = self.g.get_by_name(ca_name)
        if not ca_entity:

            for entity in self.g.get_by_type(EntityType.ORGANIZATION):
                if ca_name.lower() in entity.name.lower():
                    ca_entity = entity
                    break
        if not ca_entity:
            return []
        return self.g.predecessors(ca_entity.id, RelationType.ISSUED_BY)

    def certs_for_domain(self, domain_name: str) -> List[Entity]:
        """All certificates that cover a domain."""
        domain = self.g.get_by_name(domain_name)
        if not domain:
            return []
        return self.g.successors(domain.id, RelationType.SECURED_BY)

    def asn_members(self, asn_name: str) -> List[Entity]:
        """All IPs in the same ASN."""
        asn = self.g.get_by_name(asn_name)
        if not asn:
            return []
        return self.g.predecessors(asn.id, RelationType.BELONGS_TO_ASN)

    def org_infrastructure(self, org_name: str) -> Dict[str, List[Entity]]:
        """Full infrastructure picture for an organization."""
        org = self.g.get_by_name(org_name)
        if not org:
            return {}

        return {
            "issued_certs": self.g.predecessors(org.id, RelationType.ISSUED_BY),
            "owned_certs":  self.g.predecessors(org.id, RelationType.OWNED_BY_ORG),
            "owned_asns":   self.g.predecessors(org.id, RelationType.ASN_OWNED_BY),
        }

    def cluster_analysis(self) -> List[Dict[str, Any]]:
        """
        Detect infrastructure clusters — groups of interconnected entities.
        Mirrors i2's network analysis for identifying organizational boundaries.
        """
        components = self.g.connected_components()
        clusters = []
        for i, component in enumerate(sorted(components, key=len, reverse=True)):
            entities = [self.g.get_entity(nid) for nid in component if self.g.get_entity(nid)]
            type_dist = {}
            for e in entities:
                key = e.entity_type.value
                type_dist[key] = type_dist.get(key, 0) + 1

            clusters.append({
                "cluster_id":    i + 1,
                "size":          len(component),
                "entity_types":  type_dist,
                "avg_risk":      int(sum(e.risk_score for e in entities) / len(entities)) if entities else 100,
                "domains":       [e.name for e in entities if e.entity_type == EntityType.DOMAIN][:10],
            })
        return clusters

    def bridge_nodes(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """
        Find entities that bridge otherwise unconnected clusters.
        High betweenness centrality = critical infrastructure pivot points.
        """
        centrality = self.g.betweenness_centrality()
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:top_n]
        result = []
        for nid, score in sorted_nodes:
            if score == 0:
                continue
            e = self.g.get_entity(nid)
            if e:
                result.append({
                    "entity":       e.to_dict(),
                    "bridge_score": round(score, 4),
                    "connections":  self.g._graph.degree(nid),
                })
        return result

    def top_risk_entities(self, top_n: int = 20) -> List[Entity]:
        """Entities with lowest risk scores that have at least one anomaly.
        Prioritizes domains and IPs. Excludes certs/ports with no real findings."""
        from argus.ontology.entities import Severity as _Sev
        all_entities = []
        for entity_type in EntityType:
            all_entities.extend(self.g.get_by_type(entity_type))

        def _qualifies(e) -> bool:
            if not e.anomalies:
                return False

            etype = e.entity_type.value
            if etype in ("certificate", "port_service", "nameserver"):
                return any(
                    a.severity in (_Sev.CRITICAL, _Sev.HIGH)
                    for a in e.anomalies
                )
            return True

        qualified = [e for e in all_entities if _qualifies(e)]
        if not qualified:
            qualified = [e for e in all_entities if e.anomalies] or all_entities
        return sorted(qualified, key=lambda e: e.risk_score)[:top_n]

    def key_reuse_groups(self) -> List[Dict[str, Any]]:
        """
        Find all public key reuse groups across the entire graph.
        Each group = set of certs sharing the same keypair.
        """
        groups = []
        for spki, cert_ids in self.g._spki_index.items():
            if len(cert_ids) < 2:
                continue
            entities = [self.g.get_entity(cid) for cid in cert_ids if self.g.get_entity(cid)]
            groups.append({
                "spki_sha256": spki,
                "count":       len(entities),
                "certs":       [e.to_dict() for e in entities],
            })
        return sorted(groups, key=lambda g: g["count"], reverse=True)

    def shared_infrastructure_report(self) -> Dict[str, Any]:
        """
        Comprehensive shared infrastructure analysis.
        Identifies IPs hosting multiple unrelated domains,
        CAs used by suspicious combinations, key reuse patterns.
        """

        shared_ips = []
        for ip_name, domain_names in self.g._ip_index.items():
            if len(domain_names) > 1:
                ip_entity = self.g.get_by_name(ip_name)
                shared_ips.append({
                    "ip":          ip_name,
                    "domain_count": len(domain_names),
                    "domains":     list(domain_names)[:20],
                    "risk_score":  ip_entity.risk_score if ip_entity else 100,
                })
        shared_ips.sort(key=lambda x: x["domain_count"], reverse=True)

        return {
            "shared_ips":      shared_ips[:20],
            "key_reuse_groups": self.key_reuse_groups(),
            "bridge_nodes":    self.bridge_nodes(top_n=10),
            "clusters":        self.cluster_analysis(),
        }

    def timeline(self) -> List[Dict[str, Any]]:
        """
        Chronological events across all entities.
        Certificate issuances, DNS changes, first-seen timestamps.
        """
        events = []

        for cert in self.g.get_by_type(EntityType.CERTIFICATE):
            if cert.properties.get("not_before"):
                events.append({
                    "timestamp":   cert.properties["not_before"],
                    "event":       "cert_issued",
                    "entity_type": "certificate",
                    "entity_name": cert.name,
                    "detail":      f"Issued by {cert.properties.get('issuer_o', 'Unknown CA')}",
                    "risk_score":  cert.risk_score,
                })
            if cert.properties.get("not_after") and cert.properties.get("is_expired"):
                events.append({
                    "timestamp":   cert.properties["not_after"],
                    "event":       "cert_expired",
                    "entity_type": "certificate",
                    "entity_name": cert.name,
                    "detail":      "Certificate expired",
                    "risk_score":  0,
                })

        return sorted(
            events,
            key=lambda e: e["timestamp"] if isinstance(e["timestamp"], str) else str(e["timestamp"])
        )

    def bridge_nodes_fast(self, top_n: int = 5) -> list:
        """Fast O(n) approximation using degree centrality."""
        try:
            degrees = dict(self.graph._graph.degree())
            sorted_nodes = sorted(degrees.items(), key=lambda x: x[1], reverse=True)
            result = []
            for node_id, degree in sorted_nodes[:top_n]:
                entity = self.graph.get_entity(node_id)
                if entity:
                    result.append({
                        "entity": {"name": entity.name, "type": entity.entity_type.value},
                        "degree": degree,
                    })
            return result
        except Exception:
            return []
