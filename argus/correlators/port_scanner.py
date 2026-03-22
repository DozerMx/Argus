"""
Async Port Scanner — Graph-Aware
Scans discovered IPs and adds PORT_SERVICE entities with banner info.
Async TCP port scanner with service banner extraction.
"""
from __future__ import annotations
import asyncio
import logging
import re
import ssl
from typing import Dict, List, Optional

from argus.ontology.entities import EntityType, RelationType
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.correlators.port_scanner")

DEFAULT_PORTS = [

    80, 443, 8080, 8443, 8000, 8001, 8008, 8009, 8010, 8088, 8090, 8888,
    8181, 8280, 8580, 9000, 9080, 9090, 9200, 9443, 9800, 4443, 4848,
    7443, 7080, 6443, 3000, 4000, 5000, 5001, 5601, 8161, 8983,

    22, 23, 2222, 2022, 22222, 3389, 5900, 5901, 5902, 6000, 6001,

    25, 26, 465, 587, 110, 143, 993, 995, 2525,

    53, 123, 853,

    20, 21, 69, 989, 990, 2049, 445, 139, 137, 138,

    3306, 3307, 5432, 6379, 6380, 27017, 27018, 27019,
    1433, 1434, 1521, 1522, 5984, 9200, 9300, 9042,
    5672, 5671, 15672, 4369, 6000, 7199, 7000, 7001,
    11211, 28017, 50000, 50001,

    1883, 8883, 61616, 61613, 5672,

    161, 162, 199, 502, 623, 9090, 9091, 9100, 4567, 4040,

    2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8447,

    79, 110, 111, 113, 119, 389, 636, 691, 860, 873, 902, 8834,
    1080, 1194, 1433, 1723, 2000, 2001, 5060, 5061, 5222, 5269,
    8194, 8649, 8888, 9001, 9002, 9003, 9009, 9030, 9418,
    10000, 10443, 11000, 12000, 32400,

    3001, 3002, 3003, 3306, 4200, 4567, 5000, 5173,
    6006, 7000, 7001, 7002, 8069, 8086, 8123,
    8333, 8500, 8554, 8888, 9200, 9300, 9999,
]
DEFAULT_PORTS = sorted(set(DEFAULT_PORTS))

SERVER_PATTERNS: Dict[str, str] = {
    "nginx":         "nginx",
    "apache":        "Apache httpd",
    "microsoft-iis": "Microsoft IIS",
    "cloudflare":    "Cloudflare",
    "openresty":     "OpenResty",
    "litespeed":     "LiteSpeed",
    "caddy":         "Caddy",
    "gunicorn":      "Gunicorn",
    "jetty":         "Eclipse Jetty",
    "tomcat":        "Apache Tomcat",
    "weblogic":      "Oracle WebLogic",
}

SERVICE_BANNER_RE = [
    (rb"^SSH-",                              "SSH"),
    (rb"^220 .*(?:ESMTP|FTP|SMTP)",         "SMTP/FTP"),
    (rb"^\+OK ",                             "POP3"),
    (rb"^\* OK ",                            "IMAP"),
    (rb"^RFB \d+\.\d+",                    "VNC"),
    (rb"redis_version",                      "Redis"),
    (rb"redis_mode",                         "Redis"),
    (rb"^\x16\x03[\x00-\x04]",            "TLS"),
    (rb"mongod",                             "MongoDB"),
    (rb"MongoDB",                            "MongoDB"),
    (rb"memcached",                          "Memcached"),
    (rb"Elasticsearch",                      "Elasticsearch"),
    (rb"elastic",                            "Elasticsearch"),
    (rb"CouchDB",                            "CouchDB"),
    (rb"MySQL",                              "MySQL"),
    (rb"MariaDB",                            "MariaDB"),
    (rb"PostgreSQL",                         "PostgreSQL"),
    (rb"MSSQL",                              "MSSQL"),
    (rb"Microsoft SQL Server",               "MSSQL"),
    (rb"Cassandra",                          "Cassandra"),
    (rb"RabbitMQ",                           "RabbitMQ"),
    (rb"Zookeeper",                          "Zookeeper"),
    (rb"ActiveMQ",                           "ActiveMQ"),
    (rb"Kafka",                              "Kafka"),
    (rb"Consul",                             "Consul"),
    (rb"etcd",                               "etcd"),
    (rb"docker",                             "Docker"),
    (rb"Kubernetes",                         "Kubernetes"),
    (rb"prometheus",                         "Prometheus"),
    (rb"Grafana",                            "Grafana"),
    (rb"Jenkins",                            "Jenkins"),
    (rb"GitLab",                             "GitLab"),
    (rb"Gitea",                              "Gitea"),
    (rb"LDAP",                               "LDAP"),
    (rb"NTLM",                               "SMB/NTLM"),
    (rb"SMB",                                "SMB"),
    (rb"FTP",                                "FTP"),
    (rb"220-",                               "FTP/SMTP"),
    (rb"MQTT",                               "MQTT"),
]

class PortScanner:
    def __init__(self, graph: KnowledgeGraph, timeout: float = 3.0, concurrency: int = 150):
        self.graph = graph
        self.timeout = timeout
        self.sem = asyncio.Semaphore(concurrency)

    async def scan_all_ips(self, ports: Optional[List[int]] = None) -> int:
        """
        Scan all IP entities in graph.
        Adds PORT_SERVICE entities + EXPOSES_SERVICE relationships.
        Returns total open ports found.
        """
        ports = ports or DEFAULT_PORTS
        ip_entities = self.graph.get_by_type(EntityType.IP)
        total_open = 0
        lock = asyncio.Lock()

        async def scan_one(ip_entity) -> None:
            nonlocal total_open
            open_ports = await self._scan_ip(ip_entity.name, ports)
            async with lock:
                total_open += len(open_ports)
            for port, info in open_ports.items():
                svc_name = f"{ip_entity.name}:{port}"
                svc_entity = self.graph.find_or_create(
                    EntityType.PORT_SERVICE,
                    name=svc_name,
                    properties={
                        "ip":          ip_entity.name,
                        "port":        port,
                        "service":     info.get("service", ""),
                        "banner":      info.get("banner", "")[:200],
                        "server":      info.get("server", ""),
                        "http_status": info.get("http_status"),
                        "is_tls":      info.get("is_tls", False),
                        "tech_stack":  info.get("tech_stack", []),
                    },
                    source="port_scan",
                )
                self.graph.link(
                    ip_entity.id, svc_entity.id,
                    RelationType.EXPOSES_SERVICE,
                    properties={"port": port},
                    source="port_scan",
                )

                server = info.get("server", "")
                if server:
                    tech_entity = self.graph.find_or_create(
                        EntityType.TECHNOLOGY, name=server, source="port_scan"
                    )

                    for domain_name in self.graph.get_domains_on_ip(ip_entity.name):
                        domain_entity = self.graph.get_by_name(domain_name)
                        if domain_entity:
                            self.graph.link(
                                domain_entity.id, tech_entity.id,
                                RelationType.USES_TECHNOLOGY, source="port_scan"
                            )

        await asyncio.gather(*[scan_one(ip_e) for ip_e in ip_entities], return_exceptions=True)
        return total_open

    async def _scan_ip(self, host: str, ports: List[int]) -> Dict[int, Dict]:
        tasks = {port: self._scan_port(host, port) for port in ports}
        results_list = await asyncio.gather(*tasks.values(), return_exceptions=True)
        open_ports: Dict[int, Dict] = {}
        for port, result in zip(tasks.keys(), results_list):
            if isinstance(result, dict) and result.get("open"):
                open_ports[port] = result
        return open_ports

    async def _scan_port(self, host: str, port: int) -> Dict:
        async with self.sem:
            result: Dict = {"open": False}
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=self.timeout
                )
                result["open"] = True
                banner_info = await self._grab_banner(r, w, host, port)
                result.update(banner_info)
                w.close()
                try:
                    await asyncio.wait_for(w.wait_closed(), timeout=1.0)
                except Exception:
                    pass
            except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
                pass
            except Exception as e:
                logger.debug(f"Scan error {host}:{port}: {e}")
            return result

    async def _grab_banner(self, reader, writer, host: str, port: int) -> Dict:
        if port in (443, 8443, 2083, 2087, 2096, 7443, 4443, 10443):
            return await self._https_banner(host, port)
        if port in (80, 8080, 8000, 8888, 9000, 9080):
            return await self._http_banner(reader, writer, host, tls=False)
        if port == 22:
            try:
                data = await asyncio.wait_for(reader.read(64), timeout=2.0)
                if data.startswith(b"SSH-"):
                    return {"service": "SSH", "banner": data.split(b"\n")[0].decode(errors="replace").strip()}
            except Exception:
                pass
        if port in (25, 587, 465):
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=2.0)
                return {"service": "SMTP", "banner": data.decode(errors="replace").strip()[:100]}
            except Exception:
                pass

        try:
            writer.write(b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=2.0)
            service = next((s for pat, s in SERVICE_BANNER_RE if re.search(pat, data[:64])), "Unknown")
            return {"service": service, "banner": data[:80].decode(errors="replace").strip()}
        except Exception:
            return {}

    async def _https_banner(self, host: str, port: int) -> Dict:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=self.timeout,
            )
            result = await self._http_banner(r, w, host, tls=True)
            w.close()
            try:
                await asyncio.wait_for(w.wait_closed(), timeout=1.0)
            except Exception:
                pass
            result["is_tls"] = True
            return result
        except Exception:
            return {"service": "HTTPS", "is_tls": True}

    async def _http_banner(self, reader, writer, host: str, tls: bool = False) -> Dict:
        try:
            req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
            return self._parse_http(data, tls)
        except Exception:
            return {"service": "HTTPS" if tls else "HTTP"}

    def _parse_http(self, data: bytes, tls: bool) -> Dict:
        result: Dict = {"service": "HTTPS" if tls else "HTTP", "is_tls": tls}
        try:
            text = data.decode("utf-8", errors="replace")
            lines = text.split("\r\n")
            if lines[0].startswith("HTTP/"):
                parts = lines[0].split(" ", 2)
                if len(parts) >= 2:
                    result["http_status"] = int(parts[1])
            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if not line:
                    break
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.lower().strip()] = v.strip()
            server_raw = headers.get("server", "").lower()
            for pattern, friendly in SERVER_PATTERNS.items():
                if pattern in server_raw:
                    result["server"] = friendly
                    break
            else:
                result["server"] = headers.get("server", "")[:60]
            tech: List[str] = []
            if headers.get("x-powered-by"):
                tech.append(headers["x-powered-by"])
            if headers.get("x-aspnet-version"):
                tech.append(f"ASP.NET {headers['x-aspnet-version']}")
            if tech:
                result["tech_stack"] = tech
        except Exception as e:
            logger.debug(f"HTTP parse error: {e}")
        return result
