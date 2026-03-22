"""
Argus v3.4 — HTML Report Generator
Self-contained dark-theme report with:
  - Interactive vis.js knowledge graph (nodes = entities, edges = relations)
  - Anomaly table with severity filtering
  - Pivot analysis panels (co-hosted, key reuse, clusters, bridge nodes)
  - Risk-scored entity tables per type
  - Timeline view
  - All data embedded — no CDN dependency except vis.js from cdnjs
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from argus.ontology.entities import EntityType, Severity
from argus.ontology.graph import KnowledgeGraph
from argus.ontology.pivot import PivotEngine

class HTMLReport:
    def render(self, graph: KnowledgeGraph, domain: str, scan_start: datetime) -> str:
        pivot = PivotEngine(graph)
        vis_data = graph.to_vis_js()
        graph_data = graph.to_dict()
        stats = graph.stats()

        anomalies = sorted(
            graph.all_anomalies,
            key=lambda a: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
                          .get(a.severity.value, 5),
        )

        clusters        = pivot.cluster_analysis()
        bridge_nodes    = pivot.bridge_nodes(top_n=10)
        top_risk        = pivot.top_risk_entities(top_n=20)
        key_reuse       = pivot.key_reuse_groups()
        shared_infra    = pivot.shared_infrastructure_report()
        timeline_events = pivot.timeline()

        elapsed = (datetime.now(timezone.utc).replace(tzinfo=None) - scan_start).total_seconds()

        j_vis     = json.dumps(vis_data, default=str)
        j_stats   = json.dumps(stats, default=str)
        j_anom    = json.dumps([a.to_dict() for a in anomalies], default=str)
        j_risk    = json.dumps([e.to_dict() for e in top_risk], default=str)
        j_cluster = json.dumps(clusters, default=str)
        j_bridge  = json.dumps(bridge_nodes, default=str)
        j_keyreuse= json.dumps(key_reuse, default=str)
        j_shared  = json.dumps(shared_infra["shared_ips"][:20], default=str)
        j_timeline= json.dumps(timeline_events, default=str)

        entity_tables = self._entity_tables_html(graph)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Argus v3.4 — {domain}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
:root{{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;
  --text:#c9d1d9;--muted:#8b949e;--blue:#58a6ff;--green:#3fb950;
  --yellow:#e3b341;--red:#f85149;--orange:#ffa657;--purple:#bc8cff;
  --teal:#a8dadc;--critical:#ff0040;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,monospace;font-size:13px;overflow-x:hidden}}
a{{color:var(--blue);text-decoration:none}}
/* layout */
.app{{display:grid;grid-template-columns:260px 1fr;grid-template-rows:56px 1fr;min-height:100vh}}
.topbar{{grid-column:1/-1;background:var(--bg2);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 20px;gap:16px;position:sticky;top:0;z-index:100}}
.topbar .logo{{font-size:18px;font-weight:700;color:var(--blue);font-family:monospace;white-space:nowrap}}
.topbar .domain{{color:var(--yellow);font-family:monospace;font-size:13px}}
.topbar .stats-bar{{display:flex;gap:16px;margin-left:auto}}
.stat-badge{{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:4px 12px;font-size:11px;color:var(--muted)}}
.stat-badge span{{color:var(--text);font-weight:700}}
.sidebar{{background:var(--bg2);border-right:1px solid var(--border);overflow-y:auto;padding:12px 0}}
.nav-section{{padding:8px 16px 4px;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);font-weight:600}}
.nav-item{{display:flex;align-items:center;gap:10px;padding:8px 20px;cursor:pointer;transition:background .15s;border-left:3px solid transparent;font-size:13px}}
.nav-item:hover{{background:var(--bg3)}}
.nav-item.active{{background:var(--bg3);border-left-color:var(--blue);color:var(--blue)}}
.nav-item .badge{{margin-left:auto;background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:1px 7px;font-size:10px}}
.nav-item .badge.danger{{background:rgba(248,81,73,.15);border-color:rgba(248,81,73,.4);color:var(--red)}}
.main{{overflow-y:auto;padding:24px}}
.page{{display:none}}
.page.active{{display:block}}
/* cards */
.card{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:20px}}
.card h2{{font-size:14px;color:var(--blue);margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:8px;display:flex;align-items:center;gap:8px}}
/* summary grid */
.summary-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:20px}}
.metric{{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:16px;text-align:center}}
.metric .val{{font-size:28px;font-weight:700;color:var(--green)}}
.metric .val.warn{{color:var(--yellow)}}
.metric .val.danger{{color:var(--red)}}
.metric .lbl{{font-size:10px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}
/* graph */
#graph-container{{width:100%;height:640px;background:var(--bg3);border:1px solid var(--border);border-radius:8px;position:relative}}
#network{{width:100%;height:100%;border-radius:8px}}
.graph-controls{{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}}
.btn{{background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:6px 14px;border-radius:6px;cursor:pointer;font-size:12px;transition:all .2s}}
.btn:hover,.btn.active{{background:var(--blue);color:#000;border-color:var(--blue)}}
.legend{{display:flex;flex-wrap:wrap;gap:12px;margin-top:12px}}
.legend-item{{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--muted)}}
.legend-dot{{width:10px;height:10px;border-radius:50%}}
/* tables */
.filter-bar{{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}}
input[type=text]{{background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:6px 12px;border-radius:6px;font-size:12px;width:260px;outline:none}}
input[type=text]:focus{{border-color:var(--blue)}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:var(--bg3);color:var(--muted);font-weight:600;padding:9px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border);position:sticky;top:0}}
td{{padding:7px 12px;border-bottom:1px solid var(--border);vertical-align:middle;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
tr:hover td{{background:var(--bg3)}}
/* badges */
.sev{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;white-space:nowrap}}
.sev-CRITICAL{{background:rgba(255,0,64,.2);color:var(--critical);border:1px solid rgba(255,0,64,.4)}}
.sev-HIGH{{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}}
.sev-MEDIUM{{background:rgba(227,179,65,.15);color:var(--yellow);border:1px solid rgba(227,179,65,.3)}}
.sev-LOW{{background:rgba(88,166,255,.1);color:var(--blue);border:1px solid rgba(88,166,255,.2)}}
.sev-INFO{{background:rgba(139,148,158,.1);color:var(--muted);border:1px solid var(--border)}}
.tag{{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10px;background:var(--bg3);color:var(--muted);border:1px solid var(--border);font-family:monospace;margin:1px}}
.tag.ip{{color:var(--green)}}
.tag.origin{{color:var(--red);border-color:var(--red);font-weight:700}}
.tag.cdn{{color:var(--yellow)}}
.risk-bar{{width:60px;height:6px;border-radius:3px;background:var(--bg3);display:inline-block;position:relative;vertical-align:middle}}
.risk-fill{{height:100%;border-radius:3px;transition:width .3s}}
/* timeline */
.timeline{{position:relative;padding-left:24px}}
.timeline::before{{content:'';position:absolute;left:8px;top:0;bottom:0;width:2px;background:var(--border)}}
.tl-event{{position:relative;margin-bottom:12px;padding:10px 14px;background:var(--bg3);border:1px solid var(--border);border-radius:6px}}
.tl-event::before{{content:'';position:absolute;left:-20px;top:14px;width:10px;height:10px;border-radius:50%;background:var(--blue);border:2px solid var(--bg)}}
.tl-event .tl-date{{font-size:10px;color:var(--muted);margin-bottom:4px}}
.tl-event .tl-title{{font-size:12px;font-weight:600}}
.tl-event .tl-detail{{font-size:11px;color:var(--muted);margin-top:2px}}
/* */
.pivot-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
.pivot-list{{list-style:none}}
.pivot-list li{{padding:6px 10px;border-bottom:1px solid var(--border);font-family:monospace;font-size:12px;display:flex;justify-content:space-between;align-items:center}}
.pivot-list li:hover{{background:var(--bg3)}}
/* */
#detail-panel{{position:fixed;right:0;top:56px;bottom:0;width:380px;background:var(--bg2);border-left:1px solid var(--border);z-index:200;transform:translateX(100%);transition:transform .25s;overflow-y:auto;padding:16px}}
#detail-panel.open{{transform:translateX(0)}}
#detail-panel .close-btn{{position:absolute;top:12px;right:16px;cursor:pointer;color:var(--muted);font-size:18px}}
#detail-panel h3{{font-size:14px;color:var(--blue);margin-bottom:12px;padding-right:30px}}
.prop-row{{display:flex;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px}}
.prop-key{{color:var(--muted);min-width:120px;flex-shrink:0}}
.prop-val{{color:var(--text);font-family:monospace;word-break:break-all}}
footer{{text-align:center;color:var(--muted);font-size:10px;padding:20px 0 8px;border-top:1px solid var(--border);margin-top:32px}}
@media(max-width:900px){{.app{{grid-template-columns:1fr}}.sidebar{{display:none}}.pivot-grid{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div class="app">

<!-- Top Bar -->
<div class="topbar">
  <div class="logo">Argus v3.4</div>
  <div class="domain">{domain}</div>
  <div class="stats-bar" id="topbar-stats"></div>
</div>

<!-- Sidebar -->
<nav class="sidebar">
  <div class="nav-section">Analysis</div>
  <div class="nav-item active" onclick="showPage('graph')" id="nav-graph">
    <span></span> Knowledge Graph
  </div>
  <div class="nav-item" onclick="showPage('anomalies')" id="nav-anomalies">
    <span>#</span> Anomalies
    <span class="badge danger" id="anom-badge">0</span>
  </div>
  <div class="nav-item" onclick="showPage('pivot')" id="nav-pivot">
    <span></span> Pivot Analysis
  </div>
  <div class="nav-item" onclick="showPage('timeline')" id="nav-timeline">
    <span></span> Timeline
  </div>
  <div class="nav-section">Entities</div>
  <div class="nav-item" onclick="showPage('domains')" id="nav-domains">
    <span></span> Domains
  </div>
  <div class="nav-item" onclick="showPage('ips')" id="nav-ips">
    <span></span> IP Addresses
  </div>
  <div class="nav-item" onclick="showPage('certs')" id="nav-certs">
    <span></span> Certificates
  </div>
  <div class="nav-item" onclick="showPage('services')" id="nav-services">
    <span></span> Services
  </div>
  <div class="nav-section">Intelligence</div>
  <div class="nav-item" onclick="showPage('risk')" id="nav-risk">
    <span>#</span> Risk Ranking
  </div>
  <div class="nav-item" onclick="showPage('export')" id="nav-export">
    <span>⬇</span> Export
  </div>
</nav>

<!-- Main Content -->
<main class="main">

<!-- ── Knowledge Graph ── -->
<div class="page active" id="page-graph">
  <div class="card">
    <h2>Knowledge Graph
      <span style="color:var(--muted);font-size:11px;font-weight:400">
        — Click node to inspect • Drag to rearrange • Scroll to zoom
      </span>
    </h2>
    <div class="graph-controls">
      <button class="btn active" data-filter="all" onclick="filterGraph('all',this)">All</button>
      <button class="btn" data-filter="domain" onclick="filterGraph('domain',this)">Domains</button>
      <button class="btn" data-filter="ip" onclick="filterGraph('ip',this)">IPs</button>
      <button class="btn" data-filter="certificate" onclick="filterGraph('certificate',this)">Certs</button>
      <button class="btn" data-filter="asn" onclick="filterGraph('asn',this)">ASN</button>
      <button class="btn" data-filter="organization" onclick="filterGraph('organization',this)">Orgs</button>
      <button class="btn" data-filter="port_service" onclick="filterGraph('port_service',this)">Services</button>
      <button class="btn" style="margin-left:auto" onclick="network && network.fit()">⊡ Fit</button>
      <button class="btn" id="physics-btn" onclick="togglePhysics()">Physics</button>
    </div>
    <div id="graph-limit-warn" style="display:none;background:rgba(227,179,65,.1);border:1px solid var(--yellow);border-radius:6px;padding:6px 12px;font-size:11px;color:var(--yellow);margin-bottom:8px"></div>
    <div id="graph-container"><div id="network"></div></div>
    <div class="legend">
      <div class="legend-item"><div class="legend-dot" style="background:#58a6ff"></div>Domain</div>
      <div class="legend-item"><div class="legend-dot" style="background:#3fb950"></div>IP</div>
      <div class="legend-item"><div class="legend-dot" style="background:#e3b341"></div>Certificate</div>
      <div class="legend-item"><div class="legend-dot" style="background:#bc8cff"></div>ASN</div>
      <div class="legend-item"><div class="legend-dot" style="background:#f85149"></div>Organization</div>
      <div class="legend-item"><div class="legend-dot" style="background:#a8dadc"></div>NS/MX</div>
      <div class="legend-item"><div class="legend-dot" style="background:#ffa657"></div>Service</div>
    </div>
  </div>
</div>

<!-- ── Anomalies ── -->
<div class="page" id="page-anomalies">
  <div class="card">
    <h2>Anomalies</h2>
    <div class="filter-bar">
      <input type="text" id="anom-search" placeholder="Search anomalies…" oninput="filterAnomalies()">
      <button class="btn active" onclick="filterAnomSev('ALL',this)">All</button>
      <button class="btn" onclick="filterAnomSev('CRITICAL',this)">CRITICAL</button>
      <button class="btn" onclick="filterAnomSev('HIGH',this)">HIGH</button>
      <button class="btn" onclick="filterAnomSev('MEDIUM',this)">MEDIUM</button>
      <button class="btn" onclick="filterAnomSev('LOW',this)">LOW</button>
    </div>
    <table id="anom-table">
      <thead><tr>
        <th style="width:110px">Severity</th>
        <th style="width:180px">Code</th>
        <th style="width:200px">Entity</th>
        <th>Detail</th>
      </tr></thead>
      <tbody id="anom-tbody"></tbody>
    </table>
  </div>
</div>

<!-- ── Pivot Analysis ── -->
<div class="page" id="page-pivot">
  <div class="pivot-grid">
    <div class="card">
      <h2>Shared Hosting</h2>
      <ul class="pivot-list" id="shared-ip-list"></ul>
    </div>
    <div class="card">
      <h2>Public Key Reuse</h2>
      <ul class="pivot-list" id="key-reuse-list"></ul>
    </div>
  </div>
  <div class="pivot-grid">
    <div class="card">
      <h2>Infrastructure Clusters</h2>
      <ul class="pivot-list" id="cluster-list"></ul>
    </div>
    <div class="card">
      <h2>Bridge Nodes</h2>
      <ul class="pivot-list" id="bridge-list"></ul>
    </div>
  </div>
</div>

<!-- ── Timeline ── -->
<div class="page" id="page-timeline">
  <div class="card">
    <h2>Certificate Timeline</h2>
    <div class="timeline" id="timeline-container"></div>
  </div>
</div>

<!-- ── Domains ── -->
<div class="page" id="page-domains">
  <div class="card">
    <h2>Domains</h2>
    <div class="filter-bar">
      <input type="text" id="domain-search" placeholder="Filter domains…" oninput="filterTable('domain-search','domain-table')">
    </div>
    {entity_tables.get("domain", "<p style='color:var(--muted)'>No domains found.</p>")}
  </div>
</div>

<!-- ── IPs ── -->
<div class="page" id="page-ips">
  <div class="card">
    <h2>IP Addresses</h2>
    <div class="filter-bar">
      <input type="text" id="ip-search" placeholder="Filter IPs…" oninput="filterTable('ip-search','ip-table')">
    </div>
    {entity_tables.get("ip", "<p style='color:var(--muted)'>No IPs resolved.</p>")}
  </div>
</div>

<!-- ── Certificates ── -->
<div class="page" id="page-certs">
  <div class="card">
    <h2>Certificates</h2>
    <div class="filter-bar">
      <input type="text" id="cert-search" placeholder="Filter certificates…" oninput="filterTable('cert-search','cert-table')">
    </div>
    {entity_tables.get("certificate", "<p style='color:var(--muted)'>No certificates found.</p>")}
  </div>
</div>

<!-- ── Services ── -->
<div class="page" id="page-services">
  <div class="card">
    <h2>Discovered Services</h2>
    <div class="filter-bar">
      <input type="text" id="svc-search" placeholder="Filter services…" oninput="filterTable('svc-search','svc-table')">
    </div>
    {entity_tables.get("port_service", "<p style='color:var(--muted)'>No services found (run with --ports).</p>")}
  </div>
</div>

<!-- ── Risk Ranking ── -->
<div class="page" id="page-risk">
  <div class="card">
    <h2>Risk-Ranked Entities</h2>
    <table>
      <thead><tr>
        <th>Type</th><th>Entity</th><th style="width:100px">Score</th>
        <th style="width:90px">Label</th><th>Anomalies</th>
      </tr></thead>
      <tbody id="risk-tbody"></tbody>
    </table>
  </div>
</div>

<!-- ── Export ── -->
<div class="page" id="page-export">
  <div class="card">
    <h2>⬇ Export</h2>
    <div style="display:flex;gap:12px;flex-wrap:wrap">
      <button class="btn" onclick="exportJSON()">Export Full Graph JSON</button>
      <button class="btn" onclick="exportAnomaliesCSV()">Export Anomalies CSV</button>
      <button class="btn" onclick="exportDomainsCSV()">Export Domains CSV</button>
      <button class="btn" onclick="exportIPsCSV()">Export IPs CSV</button>
    </div>
    <div id="export-info" style="margin-top:16px;color:var(--muted);font-size:12px">
      Select an export format above.
    </div>
  </div>
  <div class="card">
    <h2>ℹ Scan Metadata</h2>
    <div class="prop-row"><div class="prop-key">Target Domain</div><div class="prop-val">{domain}</div></div>
    <div class="prop-row"><div class="prop-key">Scan Start</div><div class="prop-val">{scan_start.strftime('%Y-%m-%d %H:%M:%S UTC')}</div></div>
    <div class="prop-row"><div class="prop-key">Duration</div><div class="prop-val">{elapsed:.1f}s</div></div>
    <div class="prop-row"><div class="prop-key">Total Nodes</div><div class="prop-val" id="meta-nodes"></div></div>
    <div class="prop-row"><div class="prop-key">Total Edges</div><div class="prop-val" id="meta-edges"></div></div>
    <div class="prop-row"><div class="prop-key">Tool</div><div class="prop-val">Argus v3.4 — github.com/DozerMx/Argus</div></div>
  </div>
</div>

</main><!-- end main -->
</div><!-- end app -->

<!-- Detail Side Panel -->
<div id="detail-panel">
  <span class="close-btn" onclick="closePanel()">x</span>
  <h3 id="panel-title">Entity Details</h3>
  <div id="panel-content"></div>
</div>

<script>
// ── Embedded Data ──────────────────────────────────────────────────────────
const VIS_DATA    = {j_vis};
const STATS       = {j_stats};
const ANOMALIES   = {j_anom};
const TOP_RISK    = {j_risk};
const CLUSTERS    = {j_cluster};
const BRIDGE_NODES= {j_bridge};
const KEY_REUSE   = {j_keyreuse};
const SHARED_IPS  = {j_shared};
const TIMELINE    = {j_timeline};

// ── Navigation ────────────────────────────────────────────────────────────
function showPage(id) {{
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  document.getElementById('nav-'+id).classList.add('active');
  if (id === 'graph') setTimeout(() => network && network.fit(), 100);
}}

// ── Top bar stats ─────────────────────────────────────────────────────────
function initTopbar() {{
  const bar = document.getElementById('topbar-stats');
  const items = [
    ['Domains',  STATS.types?.domain       || 0, false],
    ['IPs',      STATS.types?.ip           || 0, false],
    ['Certs',    STATS.types?.certificate  || 0, false],
    ['Anomalies',STATS.anomalies           || 0, true],
    ['Edges',    STATS.edges               || 0, false],
  ];
  bar.innerHTML = items.map(([lbl,val,danger]) =>
    `<div class="stat-badge">${{lbl}}: <span style="${{danger&&val>0?'color:var(--red)':''}}">${{val}}</span></div>`
  ).join('');
  document.getElementById('anom-badge').textContent = STATS.anomalies || 0;
  document.getElementById('meta-nodes') && (document.getElementById('meta-nodes').textContent = STATS.nodes || 0);
  document.getElementById('meta-edges') && (document.getElementById('meta-edges').textContent = STATS.edges || 0);
}}

// ── vis.js Knowledge Graph ────────────────────────────────────────────────
const GRAPH_NODE_LIMIT = 150; // Max nodes rendered at once — keeps mobile smooth
let network, physicsEnabled = false;
let allNodes, allEdges, currentFilter = 'all';

// Build a trimmed, performance-safe subset of the graph
// Priority: anomalous nodes > high-degree nodes > rest
function buildDisplaySubset(typeFilter) {{
  let nodes = VIS_DATA.nodes || [];
  if (typeFilter && typeFilter !== 'all') {{
    nodes = nodes.filter(n => n.entity_type === typeFilter);
  }}
  // Sort: anomalous first, then by risk score asc (lower = riskier), then name
  nodes = [...nodes].sort((a, b) => {{
    const aAnom = (a.anomaly_count || 0);
    const bAnom = (b.anomaly_count || 0);
    if (bAnom !== aAnom) return bAnom - aAnom;
    return (a.risk_score || 100) - (b.risk_score || 100);
  }});

  const limited = nodes.length > GRAPH_NODE_LIMIT;
  const display = nodes.slice(0, GRAPH_NODE_LIMIT);
  const displayIds = new Set(display.map(n => n.id));

  // Only include edges where both endpoints are in display set
  const edges = (VIS_DATA.edges || []).filter(
    e => displayIds.has(e.from) && displayIds.has(e.to)
  );

  // Strip edge labels for large graphs — major perf win
  const cleanEdges = edges.map(e => ({{
    ...e,
    label: display.length > 80 ? '' : e.label,
    smooth: display.length > 80
      ? {{ type: 'continuous' }}
      : {{ type: 'curvedCW', roundness: 0.15 }},
  }}));

  return {{ nodes: display, edges: cleanEdges, limited, total: nodes.length }};
}}

function initGraph() {{
  const container = document.getElementById('network');
  const subset = buildDisplaySubset('all');

  allNodes = new vis.DataSet(subset.nodes);
  allEdges = new vis.DataSet(subset.edges);

  const isMobile = window.innerWidth < 768;
  const isLarge  = subset.nodes.length > 80;

  // Show warning if graph was trimmed
  if (subset.limited) {{
    document.getElementById('graph-limit-warn').style.display = 'block';
    document.getElementById('graph-limit-warn').textContent =
      `Showing top ${{GRAPH_NODE_LIMIT}} of ${{subset.total}} nodes (sorted by risk). Use filters to explore.`;
  }}

  const options = {{
    nodes: {{
      font: {{ color: '#c9d1d9', size: isMobile ? 9 : 11, face: 'monospace' }},
      scaling: {{ min: 14, max: 40 }},
      borderWidthSelected: 3,
    }},
    edges: {{
      font: {{ color: '#8b949e', size: 8, strokeWidth: 0, align: 'middle' }},
      smooth: isLarge ? {{ type: 'continuous' }} : {{ type: 'curvedCW', roundness: 0.15 }},
      selectionWidth: 2,
    }},
    physics: {{
      enabled: false,  // Off by default — user enables manually
    }},
    interaction: {{
      hover:         !isMobile,
      tooltipDelay:  200,
      navigationButtons: false,
      keyboard:      {{ enabled: !isMobile }},
      zoomView:      true,
      dragView:      true,
    }},
    layout: {{
      improvedLayout: subset.nodes.length <= 80,
      hierarchical:   false,
    }},
  }};

  network = new vis.Network(container, {{ nodes: allNodes, edges: allEdges }}, options);

  // Auto-fit after render
  network.once('afterDrawing', () => network.fit({{ animation: false }}));

  network.on('selectNode', params => {{
    if (params.nodes.length > 0) showEntityPanel(params.nodes[0]);
  }});
  network.on('deselectNode', () => closePanel());
}}

function filterGraph(type, btn) {{
  currentFilter = type;
  document.querySelectorAll('.graph-controls .btn[data-filter]').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');

  const subset = buildDisplaySubset(type);
  allNodes.clear();
  allEdges.clear();
  allNodes.add(subset.nodes);
  allEdges.add(subset.edges);

  const warn = document.getElementById('graph-limit-warn');
  if (subset.limited) {{
    warn.style.display = 'block';
    warn.textContent = `Showing top ${{GRAPH_NODE_LIMIT}} of ${{subset.total}} nodes.`;
  }} else {{
    warn.style.display = 'none';
  }}
  setTimeout(() => network && network.fit({{ animation: {{ duration: 300 }} }}), 50);
}}

function togglePhysics() {{
  physicsEnabled = !physicsEnabled;
  network.setOptions({{ physics: {{ enabled: physicsEnabled,
    solver: 'forceAtlas2Based',
    forceAtlas2Based: {{ gravitationalConstant: -40, springLength: 100, damping: 0.5 }},
    stabilization: {{ iterations: 80, updateInterval: 50 }},
  }} }});
  document.getElementById('physics-btn').textContent = physicsEnabled ? 'Stop' : 'Physics';
}}

// ── Entity detail panel ────────────────────────────────────────────────────
function showEntityPanel(nodeId) {{
  const node = VIS_DATA.nodes.find(n => n.id === nodeId);
  if (!node) return;
  const panel = document.getElementById('detail-panel');
  const title = document.getElementById('panel-title');
  const content = document.getElementById('panel-content');

  title.textContent = `${{node.entity_type?.toUpperCase()}} — ${{node.label}}`;

  let html = '';
  // Properties
  const props = node.properties || {{}};
  for (const [k,v] of Object.entries(props)) {{
    if (v === null || v === '' || (Array.isArray(v) && v.length === 0)) continue;
    const display = Array.isArray(v) ? v.join(', ') : String(v);
    html += `<div class="prop-row">
      <div class="prop-key">${{k}}</div>
      <div class="prop-val">${{escHtml(display.substring(0,200))}}</div>
    </div>`;
  }}
  // Risk
  const riskColor = {{CLEAN:'#3fb950',LOW:'#58a6ff',MEDIUM:'#e3b341',HIGH:'#f97316',CRITICAL:'#f85149'}}[node.risk_label] || '#8b949e';
  html += `<div class="prop-row">
    <div class="prop-key">Risk Score</div>
    <div class="prop-val" style="color:${{riskColor}};font-weight:700">${{node.risk_score}}/100 — ${{node.risk_label}}</div>
  </div>`;
  // Anomalies
  if (node.anomaly_count > 0) {{
    const nodeAnomalies = ANOMALIES.filter(a => a.entity_id === nodeId);
    if (nodeAnomalies.length > 0) {{
      html += `<div style="margin-top:12px;font-size:11px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.5px">Anomalies</div>`;
      nodeAnomalies.forEach(a => {{
        html += `<div style="padding:6px 0;border-bottom:1px solid var(--border)">
          <span class="sev sev-${{a.severity}}">${{a.severity}}</span>
          <span style="margin-left:6px;font-size:11px;color:var(--text)">${{escHtml(a.title)}}</span>
          <div style="font-size:10px;color:var(--muted);margin-top:2px">${{escHtml(a.detail)}}</div>
        </div>`;
      }});
    }}
  }}

  content.innerHTML = html;
  panel.classList.add('open');
}}

function closePanel() {{
  document.getElementById('detail-panel').classList.remove('open');
}}

// ── Anomalies Table ────────────────────────────────────────────────────────
let currentSevFilter = 'ALL';

function initAnomalies() {{
  renderAnomalies(ANOMALIES);
}}

function renderAnomalies(data) {{
  const tbody = document.getElementById('anom-tbody');
  if (!data.length) {{
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--green);padding:20px">No anomalies detected</td></tr>';
    return;
  }}
  tbody.innerHTML = data.map(a => `
    <tr data-sev="${{a.severity}}" onclick="highlightEntity('${{a.entity_id}}')" style="cursor:pointer">
      <td><span class="sev sev-${{a.severity}}">${{a.severity}}</span></td>
      <td style="font-family:monospace;font-size:11px">${{escHtml(a.code)}}</td>
      <td style="font-family:monospace;color:var(--blue)">${{escHtml(a.entity_name?.substring(0,40))}}</td>
      <td style="color:var(--muted)">${{escHtml(a.detail?.substring(0,120))}}</td>
    </tr>`).join('');
}}

function filterAnomSev(sev, btn) {{
  currentSevFilter = sev;
  document.querySelectorAll('#page-anomalies .btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  applyAnomFilters();
}}

function filterAnomalies() {{ applyAnomFilters(); }}

function applyAnomFilters() {{
  const q = (document.getElementById('anom-search').value || '').toLowerCase();
  let filtered = ANOMALIES;
  if (currentSevFilter !== 'ALL') filtered = filtered.filter(a => a.severity === currentSevFilter);
  if (q) filtered = filtered.filter(a =>
    (a.code+a.entity_name+a.detail).toLowerCase().includes(q)
  );
  renderAnomalies(filtered);
}}

// ── Pivot Analysis ─────────────────────────────────────────────────────────
function initPivot() {{
  // Shared IPs
  const sipList = document.getElementById('shared-ip-list');
  if (SHARED_IPS.length === 0) {{
    sipList.innerHTML = '<li style="color:var(--muted)">No shared hosting detected.</li>';
  }} else {{
    sipList.innerHTML = SHARED_IPS.map(s =>
      `<li><span class="tag ip">${{escHtml(s.ip)}}</span>
       <span style="color:var(--muted)">${{s.domain_count}} domains</span></li>`
    ).join('');
  }}

  // Key reuse
  const krList = document.getElementById('key-reuse-list');
  if (KEY_REUSE.length === 0) {{
    krList.innerHTML = '<li style="color:var(--muted)">No key reuse detected.</li>';
  }} else {{
    krList.innerHTML = KEY_REUSE.map(g =>
      `<li><span class="tag" style="color:var(--red)">${{g.count}} certs</span>
       <span style="font-family:monospace;font-size:10px;color:var(--muted)">${{g.spki_sha256.substring(0,24)}}…</span></li>`
    ).join('');
  }}

  // Clusters
  const clList = document.getElementById('cluster-list');
  clList.innerHTML = (CLUSTERS.slice(0,10)).map(c =>
    `<li><span class="tag">#${{c.cluster_id}}</span>
     <span style="color:var(--muted)">${{c.size}} nodes</span>
     <span style="color:var(--blue);font-size:10px">${{c.domains.slice(0,2).join(', ')}}</span></li>`
  ).join('') || '<li style="color:var(--muted)">No clusters.</li>';

  // Bridge nodes
  const bnList = document.getElementById('bridge-list');
  bnList.innerHTML = BRIDGE_NODES.map(b =>
    `<li onclick="highlightEntity('${{b.entity.id}}')" style="cursor:pointer">
     <span class="tag">${{b.entity.type}}</span>
     <span style="font-family:monospace">${{escHtml(b.entity.name?.substring(0,30))}}</span>
     <span style="color:var(--yellow);font-size:10px">β=${{b.bridge_score}}</span></li>`
  ).join('') || '<li style="color:var(--muted)">No bridge nodes.</li>';
}}

// ── Timeline ───────────────────────────────────────────────────────────────
function initTimeline() {{
  const container = document.getElementById('timeline-container');
  if (!TIMELINE.length) {{
    container.innerHTML = '<p style="color:var(--muted)">No timeline events.</p>';
    return;
  }}
  container.innerHTML = TIMELINE.slice(0, 100).map(e => {{
    const date = (e.timestamp || '').substring(0, 10);
    const icon = e.event === 'cert_expired' ? '' : '';
    return `<div class="tl-event">
      <div class="tl-date">${{date}}</div>
      <div class="tl-title">${{icon}} ${{escHtml(e.entity_name?.substring(0,50))}}</div>
      <div class="tl-detail">${{escHtml(e.detail || '')}}</div>
    </div>`;
  }}).join('');
}}

// ── Risk Table ─────────────────────────────────────────────────────────────
function initRisk() {{
  const tbody = document.getElementById('risk-tbody');
  tbody.innerHTML = TOP_RISK.map(e => {{
    const riskColor = {{CLEAN:'#3fb950',LOW:'#58a6ff',MEDIUM:'#e3b341',HIGH:'#f97316',CRITICAL:'#f85149'}}[e.risk_label] || '#8b949e';
    const pct = e.risk_score;
    return `<tr onclick="highlightEntity('${{e.id}}')" style="cursor:pointer">
      <td><span class="tag">${{e.type}}</span></td>
      <td style="font-family:monospace;color:var(--blue)">${{escHtml(e.name?.substring(0,50))}}</td>
      <td>
        <div class="risk-bar">
          <div class="risk-fill" style="width:${{pct}}%;background:${{riskColor}}"></div>
        </div>
        <span style="font-size:10px;color:${{riskColor}};margin-left:4px">${{pct}}</span>
      </td>
      <td><span class="sev sev-${{e.risk_label === 'CLEAN' ? 'INFO' : e.risk_label}}">${{e.risk_label}}</span></td>
      <td style="color:var(--muted)">${{e.anomalies?.length || 0}} anomalies</td>
    </tr>`;
  }}).join('');
}}

// ── Graph highlight helper ─────────────────────────────────────────────────
function highlightEntity(nodeId) {{
  showPage('graph');
  setTimeout(() => {{
    if (network) {{
      network.selectNodes([nodeId]);
      network.focus(nodeId, {{ scale: 1.5, animation: {{ duration: 600, easingFunction: 'easeInOutCubic' }} }});
      showEntityPanel(nodeId);
    }}
  }}, 150);
}}

// ── Table filter ───────────────────────────────────────────────────────────
function filterTable(inputId, tableId) {{
  const q = (document.getElementById(inputId)?.value || '').toLowerCase();
  document.querySelectorAll(`#${{tableId}} tbody tr`).forEach(row => {{
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}

// ── Export ─────────────────────────────────────────────────────────────────
function exportJSON() {{
  download('argus_graph_{domain}.json', JSON.stringify({{
    nodes: VIS_DATA.nodes, edges: VIS_DATA.edges, anomalies: ANOMALIES,
    stats: STATS, timeline: TIMELINE, clusters: CLUSTERS
  }}, null, 2), 'application/json');
}}

function exportAnomaliesCSV() {{
  const rows = [['severity','code','entity_name','detail']].concat(
    ANOMALIES.map(a => [a.severity, a.code, a.entity_name, a.detail].map(csvCell))
  );
  download('argus_anomalies_{domain}.csv', rows.map(r=>r.join(',')).join('\\n'), 'text/csv');
}}

function exportDomainsCSV() {{
  const domains = VIS_DATA.nodes.filter(n => n.entity_type === 'domain');
  const rows = [['name','risk_score','risk_label','anomaly_count']].concat(
    domains.map(d => [d.label, d.risk_score, d.risk_label, d.anomaly_count].map(csvCell))
  );
  download('argus_domains_{domain}.csv', rows.map(r=>r.join(',')).join('\\n'), 'text/csv');
}}

function exportIPsCSV() {{
  const ips = VIS_DATA.nodes.filter(n => n.entity_type === 'ip');
  const rows = [['ip','is_cdn','cdn_provider','asn','country','risk_score']].concat(
    ips.map(n => [
      n.label,
      n.properties?.is_cdn || false,
      n.properties?.cdn_provider || '',
      n.properties?.asn || '',
      n.properties?.country || '',
      n.risk_score,
    ].map(csvCell))
  );
  download('argus_ips_{domain}.csv', rows.map(r=>r.join(',')).join('\\n'), 'text/csv');
}}

function download(filename, content, type) {{
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], {{type}}));
  a.download = filename;
  a.click();
  document.getElementById('export-info').textContent = `Downloaded ${{filename}}`;
}}

function csvCell(v) {{ return `"${{String(v||'').replace(/"/g,'""')}}"` }}
function escHtml(s) {{
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

// ── Bootstrap ─────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {{
  initTopbar();
  initGraph();
  initAnomalies();
  initPivot();
  initTimeline();
  initRisk();
}});
</script>

<footer style="grid-column:1/-1">
  Argus v3.4 by DozerMx — github.com/DozerMx/Argus — For authorized security testing only
</footer>
</body>
</html>"""

    def _entity_tables_html(self, graph: KnowledgeGraph) -> Dict[str, str]:
        tables: Dict[str, str] = {}

        domains = sorted(graph.get_by_type(EntityType.DOMAIN), key=lambda e: e.risk_score)
        if domains:
            rows = ""
            for d in domains:
                p = d.properties
                is_alive = p.get("is_alive")
                status = ('<span style="color:var(--green)">●</span>' if is_alive
                          else '<span style="color:var(--muted)">○</span>' if is_alive is False
                          else '<span style="color:var(--muted)">?</span>')
                cdn = f'<span class="tag cdn">{p.get("cdn_provider","")}</span>' if p.get("cdn_provider") else ""
                risk_color = {"CLEAN":"#3fb950","LOW":"#58a6ff","MEDIUM":"#e3b341","HIGH":"#f97316","CRITICAL":"#f85149"}.get(d.risk_label(),"#8b949e")
                anoms = len(d.anomalies)
                rows += f"""<tr onclick="highlightEntity('{d.id}')" style="cursor:pointer">
                  <td style="font-family:monospace;color:var(--blue)">{d.name}</td>
                  <td style="text-align:center">{status}</td>
                  <td style="font-size:11px;color:var(--muted)">{d.first_seen.strftime('%Y-%m-%d') if d.first_seen else '—'}</td>
                  <td>{cdn}</td>
                  <td><span style="color:{risk_color};font-weight:700">{d.risk_score}</span></td>
                  <td style="color:{'var(--red)' if anoms else 'var(--muted)'}">{anoms}</td>
                </tr>"""
            tables["domain"] = f"""<table id="domain-table">
              <thead><tr><th>Subdomain</th><th>Alive</th><th>First Seen</th><th>CDN</th><th>Risk</th><th>Anomalies</th></tr></thead>
              <tbody>{rows}</tbody></table>"""

        ips = sorted(graph.get_by_type(EntityType.IP), key=lambda e: e.risk_score)
        if ips:
            rows = ""
            for ip_e in ips:
                p = ip_e.properties
                cdn_badge = f'<span class="tag cdn">{p.get("cdn_provider","CDN")}</span>' if p.get("is_cdn") else ""
                origin_badge = '<span class="tag origin">ORIGIN</span>' if p.get("role") == "origin" else ""
                rows += f"""<tr onclick="highlightEntity('{ip_e.id}')" style="cursor:pointer">
                  <td style="font-family:monospace;color:var(--green)">{ip_e.name}</td>
                  <td>{cdn_badge}{origin_badge}</td>
                  <td style="color:var(--muted)">{p.get('asn','')}</td>
                  <td style="color:var(--muted)">{p.get('asn_name','')[:30]}</td>
                  <td style="color:var(--muted)">{p.get('country','')}</td>
                  <td style="color:var(--muted)">{len(graph.get_domains_on_ip(ip_e.name))}</td>
                </tr>"""
            tables["ip"] = f"""<table id="ip-table">
              <thead><tr><th>IP</th><th>Type</th><th>ASN</th><th>Organization</th><th>Country</th><th>Domains</th></tr></thead>
              <tbody>{rows}</tbody></table>"""

        certs = sorted(graph.get_by_type(EntityType.CERTIFICATE), key=lambda e: e.risk_score)
        if certs:
            rows = ""
            for c in certs:
                p = c.properties
                exp_style = "color:var(--red)" if p.get("is_expired") else "color:var(--muted)"
                wc_badge = '<span class="tag" style="color:var(--yellow)">wildcard</span>' if p.get("is_wildcard") else ""
                rows += f"""<tr onclick="highlightEntity('{c.id}')" style="cursor:pointer">
                  <td style="font-family:monospace;font-size:11px">{p.get('common_name','')[:45]}</td>
                  <td style="color:var(--muted);font-size:11px">{p.get('issuer_o','')[:30]}</td>
                  <td style="{exp_style};font-size:11px">{(p.get('not_after') or '')[:10]}</td>
                  <td>{wc_badge}</td>
                  <td style="color:var(--muted)">{len(p.get('sans',[]))}</td>
                </tr>"""
            tables["certificate"] = f"""<table id="cert-table">
              <thead><tr><th>Common Name</th><th>Issued By</th><th>Expires</th><th>Type</th><th>SANs</th></tr></thead>
              <tbody>{rows}</tbody></table>"""

        services = graph.get_by_type(EntityType.PORT_SERVICE)
        if services:
            rows = ""
            for s in sorted(services, key=lambda e: e.properties.get("port", 0)):
                p = s.properties
                tls_badge = '<span class="tag" style="color:var(--green)">TLS</span>' if p.get("is_tls") else ""
                rows += f"""<tr>
                  <td style="font-family:monospace;color:var(--green)">{p.get('ip','')}</td>
                  <td style="color:var(--orange);font-weight:700">{p.get('port','')}</td>
                  <td style="color:var(--blue)">{p.get('service','')}</td>
                  <td style="color:var(--muted);font-size:11px">{p.get('server','')[:40]}</td>
                  <td>{tls_badge}</td>
                  <td style="color:var(--muted);font-size:10px;font-family:monospace">{p.get('banner','')[:60]}</td>
                </tr>"""
            tables["port_service"] = f"""<table id="svc-table">
              <thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Server</th><th>TLS</th><th>Banner</th></tr></thead>
              <tbody>{rows}</tbody></table>"""

        return tables
