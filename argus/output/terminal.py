"""Terminal renderer — fully centered, full ANSI color, no Rich dependency."""
from __future__ import annotations
import os
import sys
import shutil

from argus.ontology.entities import EntityType, Severity
from argus.ontology.graph import KnowledgeGraph
from argus.ontology.pivot import PivotEngine

R = "\033[0m"

COLORS = [
    "\033[38;2;180;30;30m",
    "\033[38;2;30;160;60m",
    "\033[38;2;40;100;210m",
    "\033[38;2;150;30;180m",
    "\033[38;2;200;130;0m",
    "\033[38;2;0;160;180m",
    "\033[38;2;180;60;120m",
    "\033[38;2;80;180;80m",
]

C_GREEN  = "\033[38;2;30;160;60m"
C_YELLOW = "\033[38;2;200;150;0m"
C_RED    = "\033[38;2;180;30;30m"
C_CYAN   = "\033[38;2;0;180;200m"
C_PURPLE = "\033[38;2;150;30;180m"
C_BLUE   = "\033[38;2;40;100;210m"
C_ORANGE = "\033[38;2;210;120;0m"

SEV_COLOR = {
    "CRITICAL": "\033[38;2;220;40;40m",
    "HIGH":     "\033[38;2;210;100;0m",
    "MEDIUM":   "\033[38;2;200;170;0m",
    "LOW":      "\033[38;2;60;160;60m",
    "INFO":     "\033[38;2;80;140;200m",
}

def _cols() -> int:
    try:
        with open("/dev/tty") as t:
            return os.get_terminal_size(t.fileno()).columns
    except Exception:
        return shutil.get_terminal_size((80, 20)).columns

def _out(text: str) -> None:
    sys.stderr.write(text + "\n")
    sys.stderr.flush()

def _center(text: str, color: str = "") -> None:
    cols  = _cols()
    clean = text
    padded = clean.center(cols)
    _out(f"{color}{padded}{R}" if color else padded)

class TerminalRenderer:
    def __init__(self, color: bool = True, quiet: bool = False):
        self.quiet  = quiet
        self.color  = True
        self._cycle = 0

    def _next_color(self) -> str:
        c = COLORS[self._cycle % len(COLORS)]
        self._cycle += 1
        return c

    def phase(self, n: int, total: int, desc: str) -> None:
        if self.quiet:
            return
        _center("")
        _center(f"[{n}/{total}] {desc}\u2026", self._next_color())

    def info(self, msg: str) -> None:
        if self.quiet:
            return
        _center(f"[*] {msg}", C_CYAN)

    def success(self, msg: str) -> None:
        if self.quiet:
            return
        _center(f"[+] {msg}", C_GREEN)

    def warning(self, msg: str) -> None:
        if self.quiet:
            return
        _center(f"[!] {msg}", C_YELLOW)

    def error(self, msg: str) -> None:
        _center(f"[-] {msg}", C_RED)

    def section(self, title: str) -> None:
        pass

    def render_summary(self, graph: KnowledgeGraph) -> None:
        if self.quiet:
            return
        cols      = _cols()
        stats     = graph.stats()
        pivot     = PivotEngine(graph)
        top_risk  = pivot.top_risk_entities(top_n=5)
        anomalies = graph.all_anomalies

        _out("")
        _center("Graph Summary", C_BLUE)
        _center("-" * 30, C_BLUE)

        stat_colors = [C_CYAN, C_PURPLE, C_GREEN, C_ORANGE, C_RED, C_YELLOW, C_BLUE, C_CYAN]
        stat_items = [
            ("Domains",     stats["types"].get("domain",      0)),
            ("IPs",         stats["types"].get("ip",          0)),
            ("Certs",       stats["types"].get("certificate", 0)),
            ("Total Nodes", stats["nodes"]),
            ("Total Edges", stats["edges"]),
            ("Anomalies",   stats["anomalies"]),
            ("Clusters",    stats["components"]),
        ]
        for i, (label, value) in enumerate(stat_items):
            col   = stat_colors[i % len(stat_colors)]
            line  = f"{label:<16} {value}"
            _out(f"{col}{line.center(cols)}{R}")

        sys.stderr.flush()

        if anomalies:
            _out("")
            _center(f"Anomalies ({len(anomalies)})", C_RED)

            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_a  = sorted(anomalies, key=lambda a: sev_order.get(a.severity.value, 5))
            shown     = min(40, len(sorted_a))

            for a in sorted_a[:shown]:
                sev   = a.severity.value
                col   = SEV_COLOR.get(sev, R)
                sev_s = sev[:4].upper()
                line  = f"{sev_s:<6}  {a.code:<32}  {a.entity_name[:24]:<24}  {a.detail[:48]}"
                _out(f"{col}{line.center(cols)}{R}")

            if len(sorted_a) > shown:
                _center(f"... and {len(sorted_a) - shown} more (see HTML report for full list)", C_PURPLE)

            sys.stderr.flush()

        if top_risk:
            _out("")
            _center("Highest Risk Entities", C_ORANGE)

            for e in top_risk:
                col  = SEV_COLOR.get(e.risk_label(), C_RED)
                line = f"{e.entity_type.value:<10}  {e.name[:48]:<48}  {e.risk_score}  {e.risk_label()}"
                _out(f"{col}{line.center(cols)}{R}")

            sys.stderr.flush()

        _out("")
        sys.stderr.flush()
