"""
Argus Web UI — FastAPI real-time dashboard.
Serves a live dashboard with WebSocket progress updates,
interactive graph, findings management, and export.
"""
from __future__ import annotations
import asyncio
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("argus.web")

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
    from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

STATIC_DIR   = Path(__file__).parent / "static"
TEMPLATE_DIR = Path(__file__).parent / "templates"

class ScanManager:
    def __init__(self):
        self._scans:   Dict[str, Dict]              = {}
        self._clients: Dict[str, List[WebSocket]]   = {}
        self._lock     = asyncio.Lock()

    async def create_scan(self, domain: str, options: Dict) -> str:
        scan_id = str(uuid.uuid4())[:8]
        async with self._lock:
            self._scans[scan_id] = {
                "id":         scan_id,
                "domain":     domain,
                "options":    options,
                "status":     "queued",
                "progress":   0,
                "phase":      0,
                "total":      33,
                "log":        [],
                "findings":   [],
                "graph":      {"nodes": [], "edges": []},
                "stats":      {},
                "started_at": time.time(),
                "ended_at":   None,
                "error":      None,
            }
            self._clients[scan_id] = []
        return scan_id

    async def update(self, scan_id: str, patch: Dict) -> None:
        async with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id].update(patch)
        await self._broadcast(scan_id, {"type": "update", **patch})

    async def log(self, scan_id: str, level: str, msg: str) -> None:
        entry = {"ts": time.time(), "level": level, "msg": msg}
        async with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id]["log"].append(entry)

                if len(self._scans[scan_id]["log"]) > 500:
                    self._scans[scan_id]["log"] = self._scans[scan_id]["log"][-500:]
        await self._broadcast(scan_id, {"type": "log", **entry})

    async def add_finding(self, scan_id: str, finding: Dict) -> None:
        async with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id]["findings"].append(finding)
        await self._broadcast(scan_id, {"type": "finding", **finding})

    async def set_graph(self, scan_id: str, nodes: List, edges: List) -> None:
        data = {"nodes": nodes, "edges": edges}
        async with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id]["graph"] = data
        await self._broadcast(scan_id, {"type": "graph", **data})

    async def connect(self, scan_id: str, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            if scan_id not in self._clients:
                self._clients[scan_id] = []
            self._clients[scan_id].append(ws)

        async with self._lock:
            scan = self._scans.get(scan_id)
        if scan:
            await ws.send_json({"type": "state", **scan})

    async def disconnect(self, scan_id: str, ws: WebSocket) -> None:
        async with self._lock:
            if scan_id in self._clients:
                try:
                    self._clients[scan_id].remove(ws)
                except ValueError:
                    pass

    async def _broadcast(self, scan_id: str, msg: Dict) -> None:
        async with self._lock:
            clients = list(self._clients.get(scan_id, []))
        dead = []
        for ws in clients:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    try:
                        self._clients[scan_id].remove(ws)
                    except ValueError:
                        pass

    def get(self, scan_id: str) -> Optional[Dict]:
        return self._scans.get(scan_id)

    def list(self) -> List[Dict]:
        return [
            {k: v for k, v in s.items() if k not in ("graph",)}
            for s in self._scans.values()
        ]

manager = ScanManager()

def create_app() -> "FastAPI":
    if not HAS_FASTAPI:
        raise RuntimeError("FastAPI not installed. Run: pip install fastapi uvicorn")

    app = FastAPI(title="Argus Security Intelligence", version="3.4", docs_url=None)

    app.add_middleware(CORSMiddleware,
        allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        html_file = TEMPLATE_DIR / "index.html"
        if html_file.exists():
            return HTMLResponse(html_file.read_text())
        return HTMLResponse(_inline_dashboard())

    @app.get("/api/scans")
    async def list_scans():
        return JSONResponse(manager.list())

    @app.get("/api/scan/{scan_id}")
    async def get_scan(scan_id: str):
        scan = manager.get(scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        return JSONResponse({k: v for k, v in scan.items() if k != "graph"})

    @app.get("/api/graph/{scan_id}")
    async def get_graph(scan_id: str):
        scan = manager.get(scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        return JSONResponse(scan.get("graph", {}))

    @app.get("/api/findings/{scan_id}")
    async def get_findings(scan_id: str):
        scan = manager.get(scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        return JSONResponse(scan.get("findings", []))

    @app.post("/api/scan")
    async def start_scan(body: dict, background_tasks: BackgroundTasks):
        domain  = body.get("domain", "").strip()
        if not domain:
            raise HTTPException(400, "domain required")
        options = {
            "full":       body.get("full",       False),
            "deep":       body.get("deep",       False),
            "brute":      body.get("brute",      False),
            "ports":      body.get("ports",      False),
            "fuzz":       body.get("fuzz",       False),
            "auth":       body.get("auth",       False),
            "credentials":body.get("credentials",[]),
            "output":     body.get("output",     "html"),
        }
        scan_id = await manager.create_scan(domain, options)
        background_tasks.add_task(_run_scan_task, scan_id, domain, options)
        return JSONResponse({"scan_id": scan_id})

    @app.delete("/api/scan/{scan_id}")
    async def cancel_scan(scan_id: str):
        scan = manager.get(scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        await manager.update(scan_id, {"status": "cancelled"})
        return JSONResponse({"ok": True})

    @app.get("/api/export/{scan_id}/{fmt}")
    async def export_scan(scan_id: str, fmt: str):
        scan = manager.get(scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        domain   = scan["domain"]
        safe     = domain.replace(".", "_")
        out_path = Path(f"argus_{safe}.{fmt}")
        if out_path.exists():
            return FileResponse(str(out_path),
                                filename=out_path.name,
                                media_type="application/octet-stream")
        raise HTTPException(404, f"Export file not found — run scan with --output {fmt} first")

    @app.websocket("/ws/{scan_id}")
    async def websocket_endpoint(websocket: WebSocket, scan_id: str):
        await manager.connect(scan_id, websocket)
        try:
            while True:

                msg = await websocket.receive_text()
                if msg == "ping":
                    await websocket.send_text("pong")
        except WebSocketDisconnect:
            await manager.disconnect(scan_id, websocket)

    return app

async def _run_scan_task(scan_id: str, domain: str, options: Dict) -> None:
    """
    Bridge between the web UI and the Argus scan engine.
    Runs the full scan and streams progress to connected WebSocket clients.
    """
    await manager.update(scan_id, {"status": "running"})
    await manager.log(scan_id, "info", f"Starting scan of {domain}")

    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))

        from argus.utils.config import Config
        from argus.utils.http_client import HTTPClient
        from argus.utils.rate_limiter import PerHostRateLimiter, RetryHandler
        from argus.core import ArgusEngineV4
        from argus.output.terminal import TerminalRenderer

        loop = asyncio.get_event_loop()

        def _fire(coro):
            """Schedule coroutine on the running event loop safely."""
            try:
                loop.create_task(coro)
            except RuntimeError:
                pass

        class WebRenderer:
            """Renderer that streams to WebSocket instead of terminal."""
            def __init__(self):
                self.quiet = False
                self.color = False

            def phase(self, n, total, desc):
                pct = int((n / total) * 100)
                _fire(manager.update(scan_id, {
                    "phase": n, "total": total, "progress": pct,
                    "phase_desc": f"[{n}/{total}] {desc}",
                }))
                _fire(manager.log(scan_id, "info", f"[{n}/{total}] {desc}"))

            def info(self, msg):
                _fire(manager.log(scan_id, "info", msg))

            def success(self, msg):
                _fire(manager.log(scan_id, "success", msg))

            def warning(self, msg):
                _fire(manager.log(scan_id, "warning", msg))

            def error(self, msg):
                _fire(manager.log(scan_id, "error", msg))

            def section(self, title):
                _fire(manager.log(scan_id, "info", f"--- {title} ---"))

            def render_summary(self, graph):
                stats = graph.stats()
                _fire(manager.update(scan_id, {"stats": stats}))
                nodes, edges = _graph_to_visjs(graph)
                _fire(manager.set_graph(scan_id, nodes, edges))
                for a in graph.all_anomalies:
                    _fire(manager.add_finding(scan_id, {
                        "code":     a.code,
                        "severity": a.severity.value,
                        "entity":   a.entity_name,
                        "detail":   a.detail,
                    }))

        config   = Config()
        config.full        = options.get("full",  False)
        config.deep        = options.get("deep",  False)
        config.brute       = options.get("brute", False)
        config.ports       = options.get("ports", False)
        config.fuzz        = options.get("fuzz",  False)
        config.auth        = options.get("auth",  False)
        config.credentials = options.get("credentials", [])
        config.diff        = True
        config.axfr        = False
        config.jarm        = False

        renderer = WebRenderer()
        http     = HTTPClient(
            timeout=config.timeout,
            proxy=None,
        )

        async with http:
            engine = ArgusEngineV4(config, renderer)
            result = await engine.run(domain)

        from argus.output.html_report import HTMLReport
        safe     = domain.replace(".", "_")
        out_path = f"argus_{safe}.html"
        html     = HTMLReport().render(result.graph, domain, result.scan_start)
        Path(out_path).write_text(html, encoding="utf-8")

        await manager.update(scan_id, {
            "status":   "complete",
            "progress": 100,
            "ended_at": time.time(),
        })
        await manager.log(scan_id, "success",
            f"Scan complete — report: {out_path}")

    except Exception as e:
        import traceback
        await manager.update(scan_id, {
            "status":   "error",
            "error":    str(e),
            "ended_at": time.time(),
        })
        await manager.log(scan_id, "error", f"Scan failed: {e}")
        logger.exception(f"Scan {scan_id} failed: {e}")

def _graph_to_visjs(graph) -> tuple:
    from argus.ontology.entities import EntityType
    COLOR_MAP = {
        "domain":       "#5b21b6",
        "ip":           "#1e40af",
        "certificate":  "#065f46",
        "organization": "#92400e",
        "nameserver":   "#374151",
        "technology":   "#7c3aed",
    }
    nodes = []
    edges = []
    seen_nodes = set()

    for entity in graph.get_all_entities():
        if entity.id in seen_nodes:
            continue
        seen_nodes.add(entity.id)
        etype = entity.entity_type.value
        color = COLOR_MAP.get(etype, "#374151")

        size = max(8, min(30, 8 + entity.risk_score // 10))
        nodes.append({
            "id":    entity.id,
            "label": entity.name[:30],
            "group": etype,
            "color": {"background": color, "border": "#1f2937"},
            "size":  size,
            "title": f"{etype}: {entity.name}\nRisk: {entity.risk_label()}",
        })

    for src_id, tgt_id, rel in graph.get_all_edges():
        edges.append({
            "from":  src_id,
            "to":    tgt_id,
            "label": rel.relation_type.value if hasattr(rel, "relation_type") else "",
        })

    return nodes, edges

def _inline_dashboard() -> str:
    """Fallback inline dashboard if template file not found."""
    return (TEMPLATE_DIR / "index.html").read_text() \
        if (TEMPLATE_DIR / "index.html").exists() \
        else "<html><body>Argus — template not found</body></html>"

def run_server(host: str = "0.0.0.0", port: int = 8080,
               reload: bool = False) -> None:
    if not HAS_FASTAPI:
        print("FastAPI not installed. Run: pip install fastapi uvicorn websockets")
        return
    app = create_app()
    uvicorn.run(app, host=host, port=port, reload=reload,
                log_level="warning")
