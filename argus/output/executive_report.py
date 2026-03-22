"""
Executive Report Generator
Produces a professional security assessment report combining:
  - AI-generated executive summary
  - Attack path visualization
  - Compliance violation mapping
  - Prioritized remediation roadmap
  - Risk matrix
  - Technical findings
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Dict, List, Any

from argus.ontology.graph import KnowledgeGraph
from argus.ontology.entities import Severity

class ExecutiveReport:
    def render(
        self,
        graph: KnowledgeGraph,
        domain: str,
        scan_start: datetime,
        attack_paths: List[Dict],
        compliance: Dict,
        scan_diff: Optional[Dict] = None,
    ) -> str:
        stats    = graph.stats()
        anomalies = sorted(
            graph.all_anomalies,
            key=lambda a: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
                          .get(a.severity.value, 5)
        )
        elapsed = (datetime.now(timezone.utc).replace(tzinfo=None) - scan_start).total_seconds()

        critical_n = sum(1 for a in anomalies if a.severity == Severity.CRITICAL)
        high_n     = sum(1 for a in anomalies if a.severity == Severity.HIGH)
        medium_n   = sum(1 for a in anomalies if a.severity == Severity.MEDIUM)

        if critical_n > 0:
            overall_risk = "CRITICAL"
            risk_color   = "#ff0040"
        elif high_n > 5:
            overall_risk = "HIGH"
            risk_color   = "#f85149"
        elif high_n > 0:
            overall_risk = "MEDIUM-HIGH"
            risk_color   = "#f97316"
        elif medium_n > 0:
            overall_risk = "MEDIUM"
            risk_color   = "#e3b341"
        else:
            overall_risk = "LOW"
            risk_color   = "#3fb950"

        j_paths      = json.dumps(attack_paths[:10], default=str)
        j_compliance = json.dumps(compliance.get("by_framework", {}), default=str)
        j_owasp      = json.dumps(
            {k: v for k, v in compliance.get("by_framework", {}).items() if "OWASP" in k},
            default=str
        )

        fw_summary_html = ""
        for fw, count in (compliance.get("summary") or {}).items():
            color = "#f85149" if count > 5 else "#e3b341" if count > 0 else "#3fb950"
            fw_short = fw.split(" ")[0] if len(fw) > 20 else fw
            fw_summary_html += f"""
            <div class="fw-card">
              <div class="fw-count" style="color:{color}">{count}</div>
              <div class="fw-name">{fw_short}</div>
            </div>"""

        paths_html = ""
        for p in attack_paths[:8]:
            sev_color = {"CRITICAL":"#ff0040","HIGH":"#f85149","MEDIUM":"#e3b341","LOW":"#3fb950"}.get(p["severity"], "#8b949e")
            steps_html = "".join(
                f'<div class="step"><span class="step-n">{s["step"]}</span>'
                f'<span class="step-action">{s["action"]}</span>'
                f'<span class="step-score">CVSS {s["cvss"]}</span></div>'
                for s in p.get("steps", [])
            )
            paths_html += f"""
            <div class="path-card">
              <div class="path-header">
                <span class="sev" style="background:rgba(255,0,0,.1);color:{sev_color};border:1px solid {sev_color}">{p["severity"]}</span>
                <span class="path-score">{p["composite_score"]}</span>
                <span class="path-title">{p["title"]}</span>
              </div>
              <div class="path-desc">{p.get("description","")[:200]}</div>
              <div class="path-steps">{steps_html}</div>
            </div>"""

        compliance_html = ""
        for fw, violations in (compliance.get("by_framework") or {}).items():
            items_html = "".join(
                f'<tr><td class="mono" style="font-size:11px">{v["ref"]}</td>'
                f'<td>{v["title"]}</td>'
                f'<td class="mono" style="font-size:10px;color:var(--muted)">{v["entity_name"][:30]}</td>'
                f'<td><span class="sev sev-{v["severity"]}">{v["severity"]}</span></td></tr>'
                for v in violations[:15]
            )
            compliance_html += f"""
            <div class="card" style="margin-bottom:16px">
              <h3 style="font-size:13px;color:var(--blue);margin-bottom:12px">{fw} ({len(violations)} violations)</h3>
              <table style="width:100%;font-size:12px;border-collapse:collapse">
                <thead><tr>
                  <th style="padding:6px;text-align:left;border-bottom:1px solid var(--border);color:var(--muted);font-size:10px">REF</th>
                  <th style="padding:6px;text-align:left;border-bottom:1px solid var(--border);color:var(--muted);font-size:10px">CONTROL</th>
                  <th style="padding:6px;text-align:left;border-bottom:1px solid var(--border);color:var(--muted);font-size:10px">ENTITY</th>
                  <th style="padding:6px;text-align:left;border-bottom:1px solid var(--border);color:var(--muted);font-size:10px">SEV</th>
                </tr></thead>
                <tbody>{items_html}</tbody>
              </table>
            </div>"""

        ai_exec  = self._generate_exec_summary(graph, domain, anomalies, attack_paths)
        ai_remed = self._generate_remediation(attack_paths, anomalies)
        ai_narr  = self._generate_narrative(attack_paths)
        ai_infra = self._generate_infra_summary(graph, domain)

        diff_html = ""
        if scan_diff:
            d = scan_diff.get("domains", {})
            s = scan_diff.get("security", {})
            appeared = d.get("appeared", [])
            new_anom = s.get("new_anomalies", [])
            diff_html = f"""
            <div class="card">
              <h2>Scan Diff (vs previous scan {scan_diff.get('summary',{}).get('old_scan','')[:10]})</h2>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
                <div>
                  <div style="color:var(--green);font-size:12px;margin-bottom:8px">+ {len(appeared)} NEW SUBDOMAINS</div>
                  {''.join(f'<div class="mono" style="font-size:11px;color:var(--muted)">{s}</div>' for s in appeared[:10])}
                </div>
                <div>
                  <div style="color:var(--red);font-size:12px;margin-bottom:8px">{len(new_anom)} NEW ANOMALY TYPES</div>
                  {''.join(f'<div style="font-size:11px;color:var(--muted)">{a}</div>' for a in new_anom[:10])}
                </div>
              </div>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Argus — Security Assessment: {domain}</title>
<style>
:root{{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;--blue:#58a6ff;--green:#3fb950;--yellow:#e3b341;--red:#f85149;--orange:#ffa657;--purple:#bc8cff}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;line-height:1.6}}
.container{{max-width:1100px;margin:0 auto;padding:32px 24px}}
.report-header{{border-bottom:2px solid var(--border);padding-bottom:24px;margin-bottom:32px}}
.report-title{{font-size:26px;font-weight:700;color:var(--blue);font-family:monospace}}
.report-meta{{color:var(--muted);font-size:12px;margin-top:8px}}
.risk-badge{{display:inline-block;padding:8px 20px;border-radius:6px;font-size:18px;font-weight:700;margin-top:12px;border:2px solid {risk_color};color:{risk_color};background:rgba(255,0,0,.05)}}
.card{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:24px}}
.card h2{{font-size:15px;color:var(--blue);margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid var(--border)}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:12px;margin-bottom:24px}}
.metric{{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:14px;text-align:center}}
.metric .val{{font-size:26px;font-weight:700}}
.metric .lbl{{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:2px}}
.ai-text{{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:16px;white-space:pre-wrap;font-size:13px;line-height:1.7;color:var(--text)}}
.path-card{{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:12px}}
.path-header{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
.path-title{{font-weight:600;font-size:13px}}
.path-score{{background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:2px 8px;font-size:11px;color:var(--orange);font-family:monospace;white-space:nowrap}}
.path-desc{{font-size:12px;color:var(--muted);margin-bottom:10px}}
.step{{display:flex;align-items:baseline;gap:8px;padding:4px 0;border-bottom:1px solid var(--border);font-size:11px}}
.step:last-child{{border-bottom:none}}
.step-n{{background:var(--blue);color:#000;border-radius:10px;padding:1px 6px;font-weight:700;font-size:10px;flex-shrink:0}}
.step-action{{flex:1;color:var(--text)}}
.step-score{{color:var(--orange);font-family:monospace;font-size:10px;white-space:nowrap}}
.fw-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin-bottom:16px}}
.fw-card{{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:12px;text-align:center}}
.fw-count{{font-size:22px;font-weight:700}}
.fw-name{{font-size:10px;color:var(--muted);margin-top:4px}}
.sev{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700}}
.sev-CRITICAL{{background:rgba(255,0,64,.15);color:#ff0040;border:1px solid rgba(255,0,64,.3)}}
.sev-HIGH{{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}}
.sev-MEDIUM{{background:rgba(227,179,65,.15);color:var(--yellow);border:1px solid rgba(227,179,65,.3)}}
.sev-LOW{{background:rgba(88,166,255,.1);color:var(--blue);border:1px solid rgba(88,166,255,.2)}}
.mono{{font-family:monospace}}
.section-nav{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:24px}}
.nav-btn{{background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:6px 14px;border-radius:6px;cursor:pointer;font-size:12px;text-decoration:none}}
.nav-btn:hover{{background:var(--blue);color:#000;border-color:var(--blue)}}
footer{{text-align:center;color:var(--muted);font-size:11px;padding:32px 0 16px;border-top:1px solid var(--border);margin-top:40px}}
@media print{{body{{background:#fff;color:#000}}.card{{border:1px solid #ccc;background:#fff}}}}
</style>
</head>
<body>
<div class="container">

<div class="report-header">
  <div class="report-title">Argus Security Assessment</div>
  <div class="report-meta">
    Target: <strong>{domain}</strong> &nbsp;|&nbsp;
    Date: {scan_start.strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp;
    Duration: {elapsed:.0f}s &nbsp;|&nbsp;
    Tool: Argus v3.4 — github.com/DozerMx/Argus
  </div>
  <div class="risk-badge">OVERALL RISK: {overall_risk}</div>
</div>

<div class="section-nav">
  <a class="nav-btn" href="#executive">Executive Summary</a>
  <a class="nav-btn" href="#metrics">Metrics</a>
  <a class="nav-btn" href="#attack-paths">Attack Paths</a>
  <a class="nav-btn" href="#compliance">Compliance</a>
  <a class="nav-btn" href="#remediation">Remediation</a>
  <a class="nav-btn" href="#narrative">Attack Narrative</a>
  <a class="nav-btn" href="#infrastructure">Infrastructure</a>
</div>

<!-- Executive Summary -->
<div class="card" id="executive">
  <h2>Executive Summary</h2>
  <div class="ai-text">{ai_exec}</div>
</div>

<!-- Metrics -->
<div id="metrics">
<div class="metrics">
  <div class="metric"><div class="val" style="color:{'var(--red)' if critical_n else 'var(--green)'}">{critical_n}</div><div class="lbl">Critical</div></div>
  <div class="metric"><div class="val" style="color:{'var(--red)' if high_n else 'var(--green)'}">{high_n}</div><div class="lbl">High</div></div>
  <div class="metric"><div class="val" style="color:{'var(--yellow)' if medium_n else 'var(--green)'}">{medium_n}</div><div class="lbl">Medium</div></div>
  <div class="metric"><div class="val">{stats['types'].get('domain',0)}</div><div class="lbl">Subdomains</div></div>
  <div class="metric"><div class="val">{stats['types'].get('ip',0)}</div><div class="lbl">IPs</div></div>
  <div class="metric"><div class="val">{stats['types'].get('port_service',0)}</div><div class="lbl">Services</div></div>
  <div class="metric"><div class="val">{len(attack_paths)}</div><div class="lbl">Attack Paths</div></div>
  <div class="metric"><div class="val">{compliance.get('total_violations',0)}</div><div class="lbl">Compliance Violations</div></div>
</div>
</div>

{diff_html}

<!-- Attack Paths -->
<div class="card" id="attack-paths">
  <h2>Attack Path Analysis ({len(attack_paths)} paths identified)</h2>
  {paths_html if paths_html else '<p style="color:var(--muted)">No significant attack paths identified.</p>'}
</div>

<!-- Compliance -->
<div class="card" id="compliance">
  <h2>Compliance Violations</h2>
  <div class="fw-grid">{fw_summary_html}</div>
  {compliance_html}
</div>

<!-- Remediation -->
<div class="card" id="remediation">
  <h2>Remediation Roadmap</h2>
  <div class="ai-text">{ai_remed}</div>
</div>

<!-- Attack Narrative -->
<div class="card" id="narrative">
  <h2>Attack Narrative</h2>
  <div class="ai-text">{ai_narr}</div>
</div>

<!-- Infrastructure Analysis -->
<div class="card" id="infrastructure">
  <h2>Infrastructure Analysis</h2>
  <div class="ai-text">{ai_infra}</div>
</div>

<footer>
  Argus v3.4 Security Assessment — {domain} — {scan_start.strftime('%Y-%m-%d')}<br>
  For authorized security testing only — github.com/DozerMx/Argus
</footer>
</div>
</body>
</html>"""

    def _generate_exec_summary(self, graph, domain, anomalies, attack_paths) -> str:
        critical = [a for a in anomalies if a.severity.value == "CRITICAL"]
        high     = [a for a in anomalies if a.severity.value == "HIGH"]
        stats    = graph.stats()
        lines = [
            f"Security Assessment — {domain}",
            f"",
            f"Infrastructure: {stats['types'].get('domain',0)} subdomains, "
            f"{stats['types'].get('ip',0)} IPs, "
            f"{stats['types'].get('port_service',0)} exposed services.",
            f"",
        ]
        if critical:
            lines.append(f"CRITICAL FINDINGS ({len(critical)}):")
            for a in critical[:5]:
                lines.append(f"  • [{a.entity_name}] {a.title}")
            lines.append("")
        if high:
            lines.append(f"HIGH SEVERITY ({len(high)}):")
            for a in high[:5]:
                lines.append(f"  • [{a.entity_name}] {a.title}")
            lines.append("")
        if attack_paths:
            lines.append(f"Attack paths identified: {len(attack_paths)}")
            lines.append(f"Highest risk: {attack_paths[0]['title']}")
        return "\n".join(lines)

    def _generate_remediation(self, attack_paths, anomalies) -> str:
        critical = [a for a in anomalies if a.severity.value == "CRITICAL"]
        high     = [a for a in anomalies if a.severity.value == "HIGH"]
        lines    = ["PHASE 1 — Critical (fix within 24-48h):"]
        for a in critical[:5]:
            lines.append(f"  • {a.title} on {a.entity_name}")
        lines += ["", "PHASE 2 — High Priority (fix within 2 weeks):"]
        for a in high[:5]:
            lines.append(f"  • {a.title} on {a.entity_name}")
        lines += ["", "PHASE 3 — Hardening (90 days):"]
        lines += ["  • Enable HSTS preloading on all subdomains",
                  "  • Implement DMARC p=reject policy",
                  "  • Remove staging/dev environments from public DNS",
                  "  • Enforce TLS 1.2+ minimum across all services"]
        return "\n".join(lines)

    def _generate_narrative(self, attack_paths) -> str:
        if not attack_paths:
            return "No significant attack chains identified from current scan data."
        p = attack_paths[0]
        lines = [
            f"Primary attack vector: {p['title']}",
            f"Severity: {p['severity']} | CVSS composite: {p['composite_score']}",
            f"",
            f"Entry point: {p['entry_point']}",
            f"Target: {p['target']}",
            f"",
            p.get('description', ''),
            f"",
            "Attack steps:",
        ]
        for step in p.get('steps', []):
            lines.append(f"  {step['step']}. {step['action']}")
        return "\n".join(lines)

    def _generate_infra_summary(self, graph, domain) -> str:
        from argus.ontology.entities import EntityType
        orgs  = [e.name for e in graph.get_by_type(EntityType.ORGANIZATION)]
        techs = [e.name for e in graph.get_by_type(EntityType.TECHNOLOGY)]
        stats = graph.stats()
        lines = [
            f"Domain: {domain}",
            f"Infrastructure clusters: {stats.get('components', 0)}",
            f"Detected technologies: {', '.join(techs[:8]) if techs else 'None detected'}",
            f"Organizations in graph: {', '.join(orgs[:5]) if orgs else 'None identified'}",
            f"Total graph relationships: {stats.get('edges', 0)}",
        ]
        return "\n".join(lines)

from typing import Optional
