"""
Argus Knowledge Graph
Central in-memory graph of all discovered entities and relationships.

In-memory directed multigraph using NetworkX as the backing store.
Supports:
  - Multiple typed edges between same nodes
  - Directed relationships
  - Graph algorithms: centrality, path finding, clustering
  - Subgraph extraction for pivot operations

All modules write TO the graph. Output modules read FROM it.
The graph is the single source of truth.
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

import networkx as nx

from argus.ontology.entities import (
    Anomaly, Entity, EntityType, Relation, RelationType, Severity,
)

logger = logging.getLogger("argus.ontology.graph")

class KnowledgeGraph:
    """
    Multi-directed graph where nodes = Entities, edges = Relations.
    Thread-safe via Python's GIL for our async use case.
    """

    def __init__(self):
        self._graph: nx.MultiDiGraph = nx.MultiDiGraph()

        self._name_index:  Dict[str, str] = {}
        self._type_index:  Dict[EntityType, Set[str]] = {t: set() for t in EntityType}
        self._spki_index:  Dict[str, List[str]] = {}
        self._ip_index:    Dict[str, Set[str]] = {}
        self._anomalies:   List[Anomaly] = []

    def add_entity(self, entity: Entity) -> str:
        """Add or update an entity. Returns entity ID."""
        if entity.id in self._graph:

            existing = self.get_entity(entity.id)
            existing.properties.update(entity.properties)
            existing.risk_score = min(existing.risk_score, entity.risk_score)
            for a in entity.anomalies:
                existing.penalize(a)
        else:
            self._graph.add_node(entity.id, entity=entity)
            self._type_index[entity.entity_type].add(entity.id)

        if entity.name:
            self._name_index[entity.name.lower()] = entity.id

        return entity.id

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        node = self._graph.nodes.get(entity_id)
        return node["entity"] if node else None

    def get_by_name(self, name: str) -> Optional[Entity]:
        eid = self._name_index.get(name.lower())
        return self.get_entity(eid) if eid else None

    def get_by_type(self, entity_type: EntityType) -> List[Entity]:
        return [
            self._graph.nodes[eid]["entity"]
            for eid in self._type_index[entity_type]
            if eid in self._graph.nodes
        ]

    def find_or_create(
        self,
        entity_type: EntityType,
        name: str,
        properties: Optional[Dict[str, Any]] = None,
        source: str = "",
    ) -> Entity:
        """
        Idempotent entity creation. Returns existing if name matches.
        Idempotent node creation. Returns existing entity if name matches.
        """
        existing = self.get_by_name(name)
        if existing and existing.entity_type == entity_type:
            if properties:
                existing.properties.update(
                    {k: v for k, v in properties.items() if v is not None and v != ""}
                )
            return existing

        entity = Entity(
            entity_type=entity_type,
            name=name,
            properties=properties or {},
            source=source,
            first_seen=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        self.add_entity(entity)
        return entity

    def penalize_entity(self, entity_id: str, anomaly: Anomaly) -> None:
        """Apply anomaly to entity and record globally."""
        entity = self.get_entity(entity_id)
        if entity:
            entity.penalize(anomaly)
        self._anomalies.append(anomaly)

    def add_relation(self, relation: Relation) -> str:
        """Add a typed edge between two entities."""
        if relation.source_id not in self._graph or relation.target_id not in self._graph:
            logger.debug(
                f"Skipping relation {relation.relation_type.value}: "
                f"node(s) not in graph ({relation.source_id[:8]}→{relation.target_id[:8]})"
            )
            return relation.id

        existing_edges = self._graph.get_edge_data(relation.source_id, relation.target_id) or {}
        for key, data in existing_edges.items():
            if data.get("relation", {}).relation_type == relation.relation_type:

                data["relation"].properties.update(relation.properties)
                return data["relation"].id

        self._graph.add_edge(
            relation.source_id,
            relation.target_id,
            key=relation.id,
            relation=relation,
        )
        return relation.id

    def link(
        self,
        source_id: str,
        target_id: str,
        rel_type: RelationType,
        properties: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
        source: str = "",
    ) -> Optional[str]:
        """Convenience wrapper: create and add a relation."""
        if not source_id or not target_id:
            return None
        rel = Relation(
            relation_type=rel_type,
            source_id=source_id,
            target_id=target_id,
            properties=properties or {},
            confidence=confidence,
            timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
            source=source,
        )
        return self.add_relation(rel)

    def index_spki(self, spki_sha256: str, cert_id: str) -> None:
        if spki_sha256 not in self._spki_index:
            self._spki_index[spki_sha256] = []
        if cert_id not in self._spki_index[spki_sha256]:
            self._spki_index[spki_sha256].append(cert_id)

    def index_ip_domain(self, ip: str, domain_name: str) -> None:
        if ip not in self._ip_index:
            self._ip_index[ip] = set()
        self._ip_index[ip].add(domain_name)

    def get_domains_on_ip(self, ip: str) -> Set[str]:
        return self._ip_index.get(ip, set())

    def get_certs_sharing_key(self, spki_sha256: str) -> List[str]:
        return self._spki_index.get(spki_sha256, [])

    def neighbors(self, entity_id: str) -> List[Entity]:
        """All directly connected entities (in + out edges)."""
        result = []
        for nid in set(list(self._graph.successors(entity_id)) +
                       list(self._graph.predecessors(entity_id))):
            e = self.get_entity(nid)
            if e:
                result.append(e)
        return result

    def successors(self, entity_id: str, rel_type: Optional[RelationType] = None) -> List[Entity]:
        """Outgoing neighbors, optionally filtered by relation type."""
        result = []
        for nid in self._graph.successors(entity_id):
            if rel_type:
                edges = self._graph.get_edge_data(entity_id, nid) or {}
                has_type = any(
                    d.get("relation", Relation()).relation_type == rel_type
                    for d in edges.values()
                )
                if not has_type:
                    continue
            e = self.get_entity(nid)
            if e:
                result.append(e)
        return result

    def predecessors(self, entity_id: str, rel_type: Optional[RelationType] = None) -> List[Entity]:
        """Incoming neighbors."""
        result = []
        for nid in self._graph.predecessors(entity_id):
            if rel_type:
                edges = self._graph.get_edge_data(nid, entity_id) or {}
                has_type = any(
                    d.get("relation", Relation()).relation_type == rel_type
                    for d in edges.values()
                )
                if not has_type:
                    continue
            e = self.get_entity(nid)
            if e:
                result.append(e)
        return result

    def ego_graph(self, entity_id: str, radius: int = 2) -> "KnowledgeGraph":
        """
        Extract a subgraph centered on an entity within `radius` hops.
        Returns a subgraph centered on the given entity within radius hops.
        """
        subgraph_nx = nx.ego_graph(
            self._graph.to_undirected(as_view=True),
            entity_id,
            radius=radius,
        )
        sub = KnowledgeGraph()
        for nid in subgraph_nx.nodes:
            e = self.get_entity(nid)
            if e:
                sub._graph.add_node(nid, entity=e)
                sub._type_index[e.entity_type].add(nid)
                if e.name:
                    sub._name_index[e.name.lower()] = nid
        for u, v, data in subgraph_nx.edges(data=True):
            if self._graph.has_edge(u, v):
                for key, edata in (self._graph.get_edge_data(u, v) or {}).items():
                    sub._graph.add_edge(u, v, key=key, **edata)
        return sub

    def shortest_path(self, source_id: str, target_id: str) -> Optional[List[Entity]]:
        """Find shortest relationship path between two entities."""
        try:
            path = nx.shortest_path(self._graph.to_undirected(as_view=True), source_id, target_id)
            return [self.get_entity(nid) for nid in path if self.get_entity(nid)]
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def degree_centrality(self) -> Dict[str, float]:
        """Most connected entities — key pivot points."""
        return nx.degree_centrality(self._graph)

    def betweenness_centrality(self) -> Dict[str, float]:
        """Bridge entities — connecting different infrastructure clusters."""
        try:
            return nx.betweenness_centrality(self._graph, normalized=True)
        except Exception:
            return {}

    def connected_components(self) -> List[Set[str]]:
        """Find isolated infrastructure clusters."""
        undirected = self._graph.to_undirected()
        return [c for c in nx.connected_components(undirected)]

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    @property
    def all_anomalies(self) -> List[Anomaly]:
        return self._anomalies

    def stats(self) -> Dict[str, Any]:
        type_counts = {t.value: len(ids) for t, ids in self._type_index.items() if ids}
        return {
            "nodes":       self.node_count,
            "edges":       self.edge_count,
            "anomalies":   len(self._anomalies),
            "types":       type_counts,
            "components":  len(self.connected_components()),
        }

    def to_dict(self) -> Dict[str, Any]:
        nodes = [
            self._graph.nodes[nid]["entity"].to_dict()
            for nid in self._graph.nodes
        ]
        edges = []
        for u, v, key, data in self._graph.edges(keys=True, data=True):
            rel: Relation = data.get("relation")
            if rel:
                edges.append(rel.to_dict())

        return {
            "nodes":     nodes,
            "edges":     edges,
            "stats":     self.stats(),
            "anomalies": [a.to_dict() for a in self._anomalies],
        }

    def to_vis_js(self) -> Dict[str, Any]:
        """
        Export graph in vis.js Network format.
        Colors, shapes, and sizes encode entity type and risk score.
        """
        TYPE_CONFIG: Dict[EntityType, Dict[str, Any]] = {
            EntityType.DOMAIN:       {"color": "#58a6ff", "shape": "ellipse",   "group": "domain"},
            EntityType.IP:           {"color": "#3fb950", "shape": "box",       "group": "ip"},
            EntityType.CERTIFICATE:  {"color": "#e3b341", "shape": "diamond",   "group": "cert"},
            EntityType.ASN:          {"color": "#bc8cff", "shape": "hexagon",   "group": "asn"},
            EntityType.ORGANIZATION: {"color": "#f85149", "shape": "dot",       "group": "org"},
            EntityType.NAMESERVER:   {"color": "#79c0ff", "shape": "triangleDown", "group": "ns"},
            EntityType.MAIL_SERVER:  {"color": "#a8dadc", "shape": "triangle",  "group": "mx"},
            EntityType.TECHNOLOGY:   {"color": "#d2a8ff", "shape": "star",      "group": "tech"},
            EntityType.PORT_SERVICE: {"color": "#ffa657", "shape": "square",    "group": "port"},
        }

        RISK_BORDER: Dict[str, str] = {
            "CLEAN":    "#3fb950",
            "LOW":      "#58a6ff",
            "MEDIUM":   "#e3b341",
            "HIGH":     "#f97316",
            "CRITICAL": "#f85149",
        }

        REL_CONFIG: Dict[RelationType, Dict[str, Any]] = {
            RelationType.RESOLVES_TO:     {"color": "#3fb950", "width": 2, "dashes": False},
            RelationType.HISTORICALLY_AT: {"color": "#8b949e", "width": 1, "dashes": True},
            RelationType.ORIGIN_BEHIND:   {"color": "#f85149", "width": 3, "dashes": False},
            RelationType.SECURED_BY:      {"color": "#e3b341", "width": 1, "dashes": False},
            RelationType.ISSUED_BY:       {"color": "#bc8cff", "width": 1, "dashes": False},
            RelationType.CO_HOSTED_WITH:  {"color": "#58a6ff", "width": 1, "dashes": True},
            RelationType.SHARES_KEY_WITH: {"color": "#f85149", "width": 2, "dashes": True},
            RelationType.BELONGS_TO_ASN:  {"color": "#79c0ff", "width": 1, "dashes": False},
            RelationType.EXPOSES_SERVICE: {"color": "#ffa657", "width": 1, "dashes": False},
            RelationType.SERVED_BY_NS:    {"color": "#a8dadc", "width": 1, "dashes": False},
            RelationType.MAIL_HANDLED_BY: {"color": "#a8dadc", "width": 1, "dashes": False},
        }

        vis_nodes = []
        for nid in self._graph.nodes:
            e: Entity = self._graph.nodes[nid]["entity"]
            cfg = TYPE_CONFIG.get(e.entity_type, TYPE_CONFIG[EntityType.DOMAIN])
            risk_label = e.risk_label()
            border_color = RISK_BORDER.get(risk_label, "#8b949e")

            degree = self._graph.degree(nid)
            size = max(20, min(60, 20 + degree * 4))

            anom_html = ""
            if e.anomalies:
                anom_html = "<br><b>Anomalies:</b><ul>" + "".join(
                    f"<li>[{a.severity.value}] {a.title}</li>" for a in e.anomalies[:5]
                ) + "</ul>"

            title = (
                f"<div style='font-family:monospace;max-width:300px'>"
                f"<b>{e.entity_type.value.upper()}</b>: {e.name}<br>"
                f"Risk: <b style='color:{border_color}'>{risk_label} ({e.risk_score}/100)</b>"
                f"{anom_html}"
                f"</div>"
            )

            vis_nodes.append({
                "id":    nid,
                "label": e.name[:40] + ("…" if len(e.name) > 40 else ""),
                "title": title,
                "color": {
                    "background": cfg["color"],
                    "border":     border_color,
                    "highlight": {"background": cfg["color"], "border": "#ffffff"},
                    "hover":     {"background": cfg["color"], "border": "#ffffff"},
                },
                "shape":       cfg["shape"],
                "group":       cfg["group"],
                "value":       size,
                "risk_score":  e.risk_score,
                "risk_label":  risk_label,
                "entity_type": e.entity_type.value,
                "properties":  e.properties,
                "anomaly_count": len(e.anomalies),
                "borderWidth": 3 if e.anomalies else 1,
            })

        vis_edges = []
        for u, v, key, data in self._graph.edges(keys=True, data=True):
            rel: Relation = data.get("relation")
            if not rel:
                continue
            cfg = REL_CONFIG.get(rel.relation_type, {"color": "#8b949e", "width": 1, "dashes": False})
            vis_edges.append({
                "id":     rel.id,
                "from":   rel.source_id,
                "to":     rel.target_id,
                "label":  rel.relation_type.value.replace("_", " "),
                "color":  {"color": cfg["color"], "highlight": "#ffffff", "hover": "#ffffff"},
                "width":  cfg["width"],
                "dashes": cfg["dashes"],
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.6}},
                "smooth": {"type": "curvedCW", "roundness": 0.15},
                "title":  rel.relation_type.value.replace("_", " "),
            })

        return {"nodes": vis_nodes, "edges": vis_edges}
