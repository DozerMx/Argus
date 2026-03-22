"""
Scan Diff Engine
Compares two KnowledgeGraph snapshots over time.
Detects infrastructure changes:
  - New subdomains appeared
  - Subdomains disappeared
  - IP changes (rotation, CDN added/removed)
  - New certificates issued
  - New open ports
  - New anomalies introduced
  - Risk score changes

Scans are persisted to disk as JSON snapshots.
"""
from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.scan_diff")

SNAPSHOTS_DIR = Path.home() / ".argus" / "snapshots"

class ScanSnapshot:
    """Serializable snapshot of a scan result."""

    def __init__(self, domain: str, graph: KnowledgeGraph, scan_time: Optional[datetime] = None):
        self.domain    = domain
        self.scan_time = scan_time or datetime.now(timezone.utc).replace(tzinfo=None)
        self._build(graph)

    def _build(self, graph: KnowledgeGraph) -> None:
        from argus.ontology.entities import EntityType
        self.domains: Dict[str, Dict] = {}
        self.ips:     Dict[str, Dict] = {}
        self.certs:   Dict[str, Dict] = {}
        self.ports:   Dict[str, List[int]] = {}
        self.anomaly_codes: Set[str] = set()
        self.risk_scores: Dict[str, int] = {}
        self.stats = graph.stats()

        for d in graph.get_by_type(EntityType.DOMAIN):
            self.domains[d.name] = {
                "is_alive":   d.properties.get("is_alive"),
                "risk_score": d.risk_score,
                "anomalies":  [a.code for a in d.anomalies],
            }
            self.risk_scores[d.name] = d.risk_score
            for a in d.anomalies:
                self.anomaly_codes.add(a.code)

        for ip in graph.get_by_type(EntityType.IP):
            self.ips[ip.name] = {
                "asn":        ip.properties.get("asn"),
                "is_cdn":     ip.properties.get("is_cdn", False),
                "risk_score": ip.risk_score,
            }

        for cert in graph.get_by_type(EntityType.CERTIFICATE):
            self.certs[cert.name] = {
                "common_name": cert.properties.get("common_name"),
                "not_after":   cert.properties.get("not_after"),
                "issuer_o":    cert.properties.get("issuer_o"),
            }

        for svc in graph.get_by_type(EntityType.PORT_SERVICE):
            ip_str = svc.properties.get("ip", "")
            port   = svc.properties.get("port")
            if ip_str and port:
                self.ports.setdefault(ip_str, []).append(port)

    def save(self) -> Path:
        SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
        ts  = self.scan_time.strftime("%Y%m%d_%H%M%S")
        path = SNAPSHOTS_DIR / f"{self.domain.replace('.', '_')}_{ts}.json"
        data = {
            "domain":       self.domain,
            "scan_time":    self.scan_time.isoformat(),
            "domains":      self.domains,
            "ips":          self.ips,
            "certs":        self.certs,
            "ports":        self.ports,
            "anomaly_codes":list(self.anomaly_codes),
            "risk_scores":  self.risk_scores,
            "stats":        self.stats,
        }
        path.write_text(json.dumps(data, indent=2, default=str))
        logger.info(f"Snapshot saved: {path}")
        return path

    @classmethod
    def load_latest(cls, domain: str) -> Optional["ScanSnapshot"]:
        """Load the most recent snapshot for a domain."""
        SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
        prefix = domain.replace(".", "_")
        snapshots = sorted(SNAPSHOTS_DIR.glob(f"{prefix}_*.json"), reverse=True)
        if not snapshots:
            return None
        try:
            snap = cls.__new__(cls)
            data = json.loads(snapshots[0].read_text())
            snap.domain       = data["domain"]
            snap.scan_time    = datetime.fromisoformat(data["scan_time"])
            snap.domains      = data.get("domains", {})
            snap.ips          = data.get("ips", {})
            snap.certs        = data.get("certs", {})
            snap.ports        = {k: list(v) for k, v in data.get("ports", {}).items()}
            snap.anomaly_codes= set(data.get("anomaly_codes", []))
            snap.risk_scores  = data.get("risk_scores", {})
            snap.stats        = data.get("stats", {})
            logger.info(f"Loaded snapshot from {snapshots[0].name}")
            return snap
        except Exception as e:
            logger.warning(f"Snapshot load error: {e}")
            return None

    @classmethod
    def list_snapshots(cls, domain: str) -> List[Path]:
        SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
        prefix = domain.replace(".", "_")
        return sorted(SNAPSHOTS_DIR.glob(f"{prefix}_*.json"), reverse=True)

class ScanDiffer:
    """Compares two snapshots and produces a structured diff report."""

    def diff(self, old: ScanSnapshot, new: ScanSnapshot) -> Dict[str, Any]:
        elapsed_days = (new.scan_time - old.scan_time).days

        old_domains = set(old.domains.keys())
        new_domains = set(new.domains.keys())
        appeared   = new_domains - old_domains
        disappeared= old_domains - new_domains
        persisted  = old_domains & new_domains

        old_ips = set(old.ips.keys())
        new_ips = set(new.ips.keys())
        new_ip_appeared   = new_ips - old_ips
        old_ip_disappeared= old_ips - new_ips

        old_certs = set(old.certs.keys())
        new_certs = set(new.certs.keys())
        new_cert_appeared = new_certs - old_certs

        new_ports_opened: Dict[str, List[int]] = {}
        ports_closed:     Dict[str, List[int]] = {}
        all_ips = set(old.ports.keys()) | set(new.ports.keys())
        for ip in all_ips:
            old_p = set(old.ports.get(ip, []))
            new_p = set(new.ports.get(ip, []))
            if new_p - old_p:
                new_ports_opened[ip] = list(new_p - old_p)
            if old_p - new_p:
                ports_closed[ip] = list(old_p - new_p)

        new_anomaly_codes = new.anomaly_codes - old.anomaly_codes
        resolved_anomalies = old.anomaly_codes - new.anomaly_codes

        risk_changes = []
        for domain in persisted:
            old_risk = old.risk_scores.get(domain, 100)
            new_risk = new.risk_scores.get(domain, 100)
            delta = new_risk - old_risk
            if abs(delta) >= 10:
                risk_changes.append({
                    "domain":    domain,
                    "old_score": old_risk,
                    "new_score": new_risk,
                    "delta":     delta,
                    "direction": "improved" if delta > 0 else "degraded",
                })
        risk_changes.sort(key=lambda x: x["delta"])

        went_down = []
        came_up   = []
        for domain in persisted:
            was_alive = old.domains[domain].get("is_alive")
            is_alive  = new.domains[domain].get("is_alive")
            if was_alive and not is_alive:
                went_down.append(domain)
            elif not was_alive and is_alive:
                came_up.append(domain)

        return {
            "summary": {
                "domain":         new.domain,
                "old_scan":       old.scan_time.isoformat(),
                "new_scan":       new.scan_time.isoformat(),
                "elapsed_days":   elapsed_days,
                "total_changes":  len(appeared) + len(disappeared) + len(new_anomaly_codes),
            },
            "domains": {
                "appeared":    sorted(appeared),
                "disappeared": sorted(disappeared),
                "went_down":   sorted(went_down),
                "came_up":     sorted(came_up),
            },
            "infrastructure": {
                "new_ips":            sorted(new_ip_appeared),
                "removed_ips":        sorted(old_ip_disappeared),
                "new_certs":          len(new_cert_appeared),
                "new_ports_opened":   new_ports_opened,
                "ports_closed":       ports_closed,
            },
            "security": {
                "new_anomalies":      sorted(new_anomaly_codes),
                "resolved_anomalies": sorted(resolved_anomalies),
                "risk_changes":       risk_changes[:10],
            },
            "stats": {
                "old": old.stats,
                "new": new.stats,
            },
        }

    def render_terminal(self, diff: Dict) -> str:
        """Render diff as colored terminal text."""
        lines = []
        s = diff["summary"]
        lines.append('')
        lines.append(f"  Scan Diff: {s['domain']}")
        lines.append(f"  {s['old_scan'][:10]} → {s['new_scan'][:10]} ({s['elapsed_days']} days)")
        lines.append('-'*60)

        d = diff["domains"]
        if d["appeared"]:
            lines.append(f"\n[+] NEW SUBDOMAINS ({len(d['appeared'])}):")
            for sub in d["appeared"][:20]:
                lines.append(f"    + {sub}")
        if d["disappeared"]:
            lines.append(f"\n[-] DISAPPEARED ({len(d['disappeared'])}):")
            for sub in d["disappeared"][:20]:
                lines.append(f"    - {sub}")

        i = diff["infrastructure"]
        if i["new_ips"]:
            lines.append(f"\n[+] NEW IPs: {', '.join(i['new_ips'][:10])}")
        if i["new_ports_opened"]:
            lines.append(f"\n[!] NEW PORTS OPENED:")
            for ip, ports in list(i["new_ports_opened"].items())[:5]:
                lines.append(f"    {ip}: {ports}")

        sec = diff["security"]
        if sec["new_anomalies"]:
            lines.append(f"\n[!] NEW ANOMALY TYPES ({len(sec['new_anomalies'])}):")
            for code in sec["new_anomalies"][:10]:
                lines.append(f"    [!] {code}")
        if sec["resolved_anomalies"]:
            lines.append(f"\n[+] RESOLVED ({len(sec['resolved_anomalies'])}):")
            for code in sec["resolved_anomalies"][:5]:
                lines.append(f"    [+] {code}")

        return "\n".join(lines)
