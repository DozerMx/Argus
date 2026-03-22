"""JSON and CSV output modules for Argus v3."""
from __future__ import annotations
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from argus.ontology.entities import EntityType
from argus.ontology.graph import KnowledgeGraph
from argus.ontology.pivot import PivotEngine

class JSONExporter:
    def write(self, graph: KnowledgeGraph, path: str) -> None:
        pivot = PivotEngine(graph)
        data = {
            "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
            "graph":        graph.to_dict(),
            "pivot": {
                "clusters":     pivot.cluster_analysis(),
                "bridge_nodes": pivot.bridge_nodes(),
                "key_reuse":    pivot.key_reuse_groups(),
                "shared_infra": pivot.shared_infrastructure_report(),
                "timeline":     pivot.timeline(),
                "top_risk":     [e.to_dict() for e in pivot.top_risk_entities()],
            },
        }
        Path(path).write_text(json.dumps(data, indent=2, default=str))

class CSVExporter:
    def write_domains(self, graph: KnowledgeGraph, path: str) -> None:
        domains = graph.get_by_type(EntityType.DOMAIN)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["name", "is_alive", "first_seen", "is_cdn", "cdn_provider",
                        "risk_score", "risk_label", "anomaly_count", "source"])
            for d in sorted(domains, key=lambda e: e.risk_score):
                p = d.properties
                w.writerow([
                    d.name,
                    p.get("is_alive", ""),
                    d.first_seen.isoformat() if d.first_seen else "",
                    p.get("is_cdn", False),
                    p.get("cdn_provider", ""),
                    d.risk_score,
                    d.risk_label(),
                    len(d.anomalies),
                    d.source,
                ])

    def write_ips(self, graph: KnowledgeGraph, path: str) -> None:
        ips = graph.get_by_type(EntityType.IP)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip", "is_cdn", "cdn_provider", "asn", "asn_name",
                        "country", "domains_count", "risk_score", "anomaly_count"])
            for ip_e in ips:
                p = ip_e.properties
                w.writerow([
                    ip_e.name,
                    p.get("is_cdn", False),
                    p.get("cdn_provider", ""),
                    p.get("asn", ""),
                    p.get("asn_name", ""),
                    p.get("country", ""),
                    len(graph.get_domains_on_ip(ip_e.name)),
                    ip_e.risk_score,
                    len(ip_e.anomalies),
                ])

    def write_anomalies(self, graph: KnowledgeGraph, path: str) -> None:
        anomalies = sorted(
            graph.all_anomalies,
            key=lambda a: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
                          .get(a.severity.value, 5),
        )
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["severity", "code", "title", "entity_name", "entity_type", "detail"])
            for a in anomalies:
                entity = graph.get_entity(a.entity_id)
                w.writerow([
                    a.severity.value,
                    a.code,
                    a.title,
                    a.entity_name,
                    entity.entity_type.value if entity else "",
                    a.detail,
                ])
