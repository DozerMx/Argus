#!/usr/bin/env python3
"""
Argus v3.4 — Knowledge Graph Intelligence Framework
Author : DozerMx | github.com/DozerMx/Argus
License: MIT

Argus v3.4 — security reconnaissance framework.
Inspired by Palantir Gotham / IBM i2 Analyst's Notebook.
"""
from __future__ import annotations
import argparse
import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_ART = (
    " ▄▄▄       ██▀███    ▄████  █    ██   ██████ ",
    "▒████▄    ▓██ ▒ ██▒ ██▒ ▀█▒ ██  ▓██▒▒██    ▒ ",
    "▒██  ▀█▄  ▓██ ░▄█ ▒▒██░▄▄▄░▓██  ▒██░░ ▓██▄   ",
    "░██▄▄▄▄██ ▒██▀▀█▄  ░▓█  ██▓▓▓█  ░██░  ▒   ██▒",
    " ▓█   ▓██▒░██▓ ▒██▒░▒▓███▀▒▒▒█████▓ ▒██████▒▒",
    " ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ░▒   ▒ ░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░",
    "  ▒   ▒▒ ░  ░▒ ░ ▒░  ░   ░ ░░▒░ ░ ░ ░ ░▒  ░ ░",
    "  ░   ▒     ░░   ░ ░ ░   ░  ░░░ ░ ░ ░  ░  ░  ",
    "      ░  ░   ░           ░    ░           ░   ",
)

_COLORS = [
    ( 55,   0,  15),
    ( 55,   0,  50),
    ( 45,   0,  80),
    ( 30,   0, 110),
    ( 15,   0, 130),
]


def _gradient_banner() -> str:
    import shutil, os, os

    def lerp(a, b, t): return int(a + (b - a) * t)

    def row_color(i, total):
        p = i / max(total - 1, 1)
        n = len(_COLORS) - 1
        idx = p * n
        ci = min(int(idx), n - 1)
        t  = idx - ci
        r = lerp(_COLORS[ci][0], _COLORS[ci+1][0], t)
        g = lerp(_COLORS[ci][1], _COLORS[ci+1][1], t)
        b = lerp(_COLORS[ci][2], _COLORS[ci+1][2], t)
        return f"\033[38;2;{r};{g};{b}m"

    reset  = "\033[0m"
    cols = 80
    try:
        with open("/dev/tty") as _tty:
            cols = os.get_terminal_size(_tty.fileno()).columns
    except Exception:
        for fd in (2, 1, 0):
            try:
                cols = os.get_terminal_size(fd).columns
                break
            except Exception:
                pass
    art_w  = max(len(l) for l in _ART)
    pad    = " " * max(0, (cols - art_w) // 2)
    total  = len(_ART)
    lines  = [""]

    for i, line in enumerate(_ART):
        lines.append(f"{row_color(i, total)}{pad}{line}{reset}")

    mid    = row_color(total // 2, total)
    sub    = "v3.5 — Security Intelligence Framework"
    github = "github.com/DozerMx/Argus"
    lines.append(f"{mid}{' ' * max(0, (cols - len(sub)) // 2)}{sub}{reset}")
    lines.append(f"{mid}{' ' * max(0, (cols - len(github)) // 2)}{github}{reset}")
    lines.append("")
    lines.append("")
    return "\n".join(lines)




def _render_banner() -> str:
    return _gradient_banner()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="argus",
        description="Argus v3.5 — Security Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python argus.py -d target.com
  python argus.py -d target.com --full --output executive
  python argus.py -d target.com --full --fuzz --auth
  python argus.py -d target.com --deep --cdn-bypass --ports
  python argus.py -d target.com --brute --axfr
  python argus.py -d target.com --full --stealth-profile paranoid
  python argus.py -d target.com --daemon --webhook https://hooks.slack.com/...
  python argus.py -f targets.txt --full --proxy socks5://127.0.0.1:9050
  python argus.py --serve --ui-port 8080

Scan phases (43 total):
  1-9    Reconnaissance    CT logs, passive DNS, AXFR, brute force, DNS resolution,
                           ASN intel, CDN bypass
  10-17  Analysis          TLS, HTTP headers, content discovery, JS secrets,
                           supply chain, advanced probes
  18-30  Intelligence      Email security, Wayback, reverse IP, JARM, anomaly
                           detection, CVSS scoring, attack paths, compliance,
                           CVE correlation, graph analytics, scan diff, risk scoring
  31-35  Active            HTTP smuggling, cross-org correlation, GNN prediction,
                           auth analysis, parameter fuzzing
  36-39  Advanced          BGP/ASN correlation, SSRF chain pivoting,
                           OAuth/GraphQL/WebSocket fuzzing, honeypot detection
  40-43  Intelligence+     Deep CVE fingerprinting, API/Swagger enumeration,
                           cloud storage (S3/Azure/GCS), threat intelligence

Output formats:
  terminal    Colored terminal output (default)
  html        Interactive graph report
  executive   Executive summary with attack paths and compliance
  json        Machine-readable full output
  csv         Spreadsheet-compatible findings
        """,
    )

    tgt = p.add_mutually_exclusive_group(required=False)
    tgt.add_argument("-d", "--domain", metavar="DOMAIN",
                     help="Target domain (e.g. example.gov.co)")
    tgt.add_argument("-f", "--file", metavar="FILE",
                     help="File with one domain per line")

    mod = p.add_argument_group("Scan Modules")
    mod.add_argument("--full",       action="store_true", help="Enable all scan modules")
    mod.add_argument("--deep",       action="store_true", help="ASN, Cloud, Wayback, Reverse IP")
    mod.add_argument("--brute",      action="store_true", help="Subdomain brute force + permutations")
    mod.add_argument("--axfr",       action="store_true", help="DNS zone transfer attempt")
    mod.add_argument("--cdn-bypass", action="store_true", help="CDN/WAF origin IP discovery")
    mod.add_argument("--ports",      action="store_true", help="TCP port scan + banner grab")
    mod.add_argument("--jarm",       action="store_true", help="JARM TLS fingerprinting")
    mod.add_argument("--fuzz",       action="store_true", help="Parameter fuzzing (SQLi, XSS, SSRF, IDOR, traversal)")
    mod.add_argument("--auth",       action="store_true", help="Authentication analysis (login forms, JWT, Basic Auth)")
    mod.add_argument("--user",       default="", metavar="USER", help="Username for authenticated scanning")
    mod.add_argument("--password",   default="", metavar="PASS", help="Password for authenticated scanning")
    mod.add_argument("--no-diff",    action="store_true", help="Disable scan diff / snapshot")
    mod.add_argument("--no-live-certs", action="store_true", help="Skip live TLS cert grabbing")

    daemon = p.add_argument_group("Daemon Mode")
    daemon.add_argument("--daemon",   action="store_true",
                        help="Run continuously, alert on new findings")
    daemon.add_argument("--webhook",  metavar="URL",
                        help="Slack/Telegram webhook URL for daemon alerts")
    daemon.add_argument("--interval", type=float, default=6.0,
                        help="Daemon scan interval in hours (default: 6)")

    out = p.add_argument_group("Output")
    out.add_argument("--output",
                     choices=["terminal", "json", "html", "csv", "executive"],
                     default="html",
                     help="Output format (default: html)")
    out.add_argument("--outfile", metavar="PATH", help="Output file path")
    out.add_argument("--no-color",  action="store_true", help="Disable terminal colors")
    out.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    out.add_argument("-q", "--quiet",   action="store_true", help="Suppress progress output")

    perf = p.add_argument_group("Performance")
    perf.add_argument("--threads",           type=int,   default=30)
    perf.add_argument("--timeout",           type=int,   default=10)
    perf.add_argument("--delay",             type=float, default=0.0)
    perf.add_argument("--brute-concurrency", type=int,   default=100)
    perf.add_argument("--port-concurrency",  type=int,   default=150)
    perf.add_argument("--proxy",             metavar="URL",
                      help="Proxy URL (socks5://host:port or http://host:port)")

    cache = p.add_argument_group("Cache")
    cache.add_argument("--no-cache",  action="store_true",
                       help="Disable disk cache (~/.argus/cache)")
    cache.add_argument("--cache-ttl", type=int, default=3600,
                       help="Cache TTL seconds (default: 3600)")

    web = p.add_argument_group("Web UI")
    web.add_argument("--serve",          action="store_true", help="Launch web UI dashboard (no domain required)")
    web.add_argument("--ui-port",         type=int, default=8080, dest="ui_port", help="Web UI port (default: 8080)")


    return p


async def run_scan(args: argparse.Namespace) -> None:
    from argus.utils.config import Config
    from argus.output.terminal import TerminalRenderer
    from argus.core import ArgusEngineV4

    config   = Config.from_args(args)
    renderer = TerminalRenderer(color=not args.no_color, quiet=args.quiet)

    if not args.quiet:
        import shutil as _sh

        import sys as _sys; _sys.stderr.write(_gradient_banner() + "\n"); _sys.stderr.flush()

    if not args.domain and not args.file:
        renderer.error("argument -d/--domain or -f/--file is required (unless using --serve)")
        sys.exit(1)

    if args.domain:
        domains = [args.domain.lower().strip()]
    else:
        path = Path(args.file)
        if not path.exists():
            renderer.error(f"File not found: {args.file}")
            sys.exit(1)
        domains = [
            line.strip().lower()
            for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not domains:
            renderer.error("No domains found in file")
            sys.exit(1)
        renderer.info(f"Loaded {len(domains)} domain(s) from {args.file}")

    if args.daemon:
        from argus.intelligence.daemon import DaemonMode
        renderer.info(f"Starting daemon mode — interval: {args.interval}h")
        daemon = DaemonMode(config, webhook_url=args.webhook,
                            interval_hours=args.interval)
        await daemon.run(domains)
        return

    # Normal scan
    for domain in domains:
        import random as _rand
        _domain_colors = [
            "\033[38;2;140;0;30m",
            "\033[38;2;100;0;140m",
            "\033[38;2;60;0;160m",
            "\033[38;2;120;10;100m",
        ]
        _dc    = _rand.choice(_domain_colors)
        _reset = "\033[0m"
        try:
            with open("/dev/tty") as _tty2:
                _cols = __import__('os').get_terminal_size(_tty2.fileno()).columns
        except Exception:
            _cols = __import__('shutil').get_terminal_size((80, 20)).columns
        import sys as _sys2; _sys2.stderr.write(f"{_dc}{domain.center(_cols)}{_reset}\n\n"); _sys2.stderr.flush()
        print()
        engine = ArgusEngineV4(config, renderer)
        result = await engine.run(domain)

        _write_output(args, result, domain, renderer)


def _write_output(args, result, domain: str, renderer) -> None:
    safe = domain.replace(".", "_")
    fmt  = args.output

    if fmt in ("html", "terminal"):
        from argus.output.html_report import HTMLReport
        outfile = args.outfile or f"argus_{safe}.html"
        html    = HTMLReport().render(result.graph, domain, result.scan_start)
        Path(outfile).write_text(html, encoding="utf-8")
        renderer.success(f"HTML report → {outfile}")

    if fmt == "executive":
        from argus.output.executive_report import ExecutiveReport
        outfile = args.outfile or f"argus_{safe}_executive.html"
        html    = ExecutiveReport().render(
            result.graph, domain, result.scan_start,
            result.attack_paths, result.compliance,
            result.diff_data,
        )
        Path(outfile).write_text(html, encoding="utf-8")
        renderer.success(f"Executive report → {outfile}")

    if fmt == "json":
        import json
        from argus.output.exporters import JSONExporter
        outfile = args.outfile or f"argus_{safe}.json"
        JSONExporter().write(result.graph, outfile)
        renderer.success(f"JSON → {outfile}")

    if fmt == "csv":
        from argus.output.exporters import CSVExporter
        base = args.outfile or f"argus_{safe}"
        exp  = CSVExporter()
        exp.write_domains(result.graph,   f"{base}_domains.csv")
        exp.write_ips(result.graph,       f"{base}_ips.csv")
        exp.write_anomalies(result.graph, f"{base}_anomalies.csv")
        renderer.success(f"CSV → {base}_*.csv")

    renderer.render_summary(result.graph)


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    import logging
    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        if args.verbose:
            print("[*] uvloop active — faster event loop")
    except ImportError:
        pass  

    def _silent_exception_handler(loop, context):
        exc = context.get("exception")
        if isinstance(exc, (OSError, ConnectionResetError, ConnectionRefusedError)):
            return
        msg = context.get("message", "")
        if "gaierror" in str(exc) or "gaierror" in msg:
            return

        loop.default_exception_handler(context)

    async def run_scan_with_handler(args):
        loop = asyncio.get_event_loop()
        loop.set_exception_handler(_silent_exception_handler)
        await run_scan(args)
        
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        if tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=2.0
                )
            except asyncio.TimeoutError:
                pass  
                
    if getattr(args, 'serve', False):
        from argus.web.server import run_server
        port = getattr(args, 'ui_port', 8080)
        import sys as _sys; _sys.stderr.write(_gradient_banner() + "\n"); _sys.stderr.flush()
        print(f"  Starting web UI on http://0.0.0.0:{port}".center(__import__('shutil').get_terminal_size((80,20)).columns))
        print()
        run_server(host="0.0.0.0", port=port)
        return

    try:
        asyncio.run(run_scan_with_handler(args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        os._exit(0)
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        os._exit(1)
    os._exit(0)

if __name__ == "__main__":
    main()
