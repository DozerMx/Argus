"""
Argus Ontology — Entity Definitions
Core data model for the security knowledge graph.

Each piece of discovered data is represented as a typed Entity.
Entities connect via typed Relations, forming a directed multigraph.
"""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

class EntityType(Enum):
    DOMAIN       = "domain"
    IP           = "ip"
    CERTIFICATE  = "certificate"
    ASN          = "asn"
    ORGANIZATION = "organization"
    NAMESERVER   = "nameserver"
    MAIL_SERVER  = "mail_server"
    TECHNOLOGY   = "technology"
    PORT_SERVICE = "port_service"

class RelationType(Enum):

    RESOLVES_TO        = "resolves_to"
    HISTORICALLY_AT    = "historically_at"
    ORIGIN_BEHIND      = "origin_behind"

    SECURED_BY         = "secured_by"

    ISSUED_BY          = "issued_by"
    OWNED_BY_ORG       = "owned_by_org"

    BELONGS_TO_ASN     = "belongs_to_asn"
    ASN_OWNED_BY       = "asn_owned_by"

    SERVED_BY_NS       = "served_by_ns"
    MAIL_HANDLED_BY    = "mail_handled_by"

    CO_HOSTED_WITH     = "co_hosted_with"
    SHARES_KEY_WITH    = "shares_key_with"
    SAME_ORG_AS        = "same_org_as"

    EXPOSES_SERVICE    = "exposes_service"

    USES_TECHNOLOGY    = "uses_technology"

    NEIGHBOR_ON_IP     = "neighbor_on_ip"

    EMAIL_SECURED_BY   = "email_secured_by"

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

SEVERITY_SCORE: Dict[str, int] = {
    "CRITICAL": 40,
    "HIGH":     25,
    "MEDIUM":   10,
    "LOW":       5,
    "INFO":      0,
}

@dataclass
class Anomaly:
    code:        str
    title:       str
    detail:      str
    severity:    Severity
    entity_id:   str
    entity_name: str
    timestamp:   datetime = field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code":        self.code,
            "title":       self.title,
            "detail":      self.detail,
            "severity":    self.severity.value,
            "entity_id":   self.entity_id,
            "entity_name": self.entity_name,
        }

@dataclass
class Entity:
    """
    Base class for all ontology objects.
    Base class for all graph nodes.
    """
    id:          str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: EntityType = EntityType.DOMAIN
    name:        str = ""
    properties:  Dict[str, Any] = field(default_factory=dict)
    risk_score:  int = 100
    anomalies:   List[Anomaly] = field(default_factory=list)
    first_seen:  Optional[datetime] = None
    last_seen:   Optional[datetime] = None
    source:      str = ""

    def add_property(self, key: str, value: Any) -> None:
        if value is not None and value != "" and value != []:
            self.properties[key] = value

    def penalize(self, anomaly: Anomaly) -> None:
        """Apply risk score penalty for an anomaly."""
        self.anomalies.append(anomaly)
        penalty = SEVERITY_SCORE.get(anomaly.severity.value, 0)
        self.risk_score = max(0, self.risk_score - penalty)

    def risk_label(self) -> str:
        if self.risk_score >= 80:
            return "CLEAN"
        if self.risk_score >= 60:
            return "LOW"
        if self.risk_score >= 40:
            return "MEDIUM"
        if self.risk_score >= 20:
            return "HIGH"
        return "CRITICAL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":          self.id,
            "type":        self.entity_type.value,
            "name":        self.name,
            "properties":  self.properties,
            "risk_score":  self.risk_score,
            "risk_label":  self.risk_label(),
            "anomalies":   [a.to_dict() for a in self.anomalies],
            "first_seen":  self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":   self.last_seen.isoformat() if self.last_seen else None,
            "source":      self.source,
        }

@dataclass
class Relation:
    """
    Typed, directional link between two entities.
    Typed, directional edge between two graph nodes.
    """
    id:            str = field(default_factory=lambda: str(uuid.uuid4()))
    relation_type: RelationType = RelationType.RESOLVES_TO
    source_id:     str = ""
    target_id:     str = ""
    properties:    Dict[str, Any] = field(default_factory=dict)
    confidence:    float = 1.0
    timestamp:     Optional[datetime] = None
    source:        str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":            self.id,
            "type":          self.relation_type.value,
            "source_id":     self.source_id,
            "target_id":     self.target_id,
            "properties":    self.properties,
            "confidence":    self.confidence,
            "timestamp":     self.timestamp.isoformat() if self.timestamp else None,
        }
