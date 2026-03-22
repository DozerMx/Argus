# Argus

**Security Intelligence Framework**

Argus is a multi-phase security reconnaissance and analysis framework built for professional penetration testing and attack surface assessment. It runs fully autonomous — no API keys required, no external services, no accounts. A single command produces a complete picture of an organization's external exposure.

---

## Architecture

```
argus/
├── sources/          Certificate Transparency, passive DNS, brute force
├── correlators/      DNS resolution, CDN bypass, port scanning
├── intelligence/     43 analysis modules
│   ├── Core          TLS, HTTP, email, content discovery, JS secrets
│   ├── Graph         Attack paths, compliance, CVE, anomaly detection
│   ├── Advanced      SSRF chains, OAuth/GraphQL/WebSocket, BGP, stealth
│   └── Intelligence  Deep CVE, API enumeration, cloud storage, threat intel
├── ontology/         Knowledge graph (NetworkX), entity model, pivot engine
├── output/           HTML report, executive report, CSV, JSON, terminal
└── web/              FastAPI real-time dashboard with WebSocket
```

The engine builds a **Knowledge Graph** of all discovered entities — domains, IPs, certificates, organizations, technologies, open ports — and the relationships between them. Every finding is an anomaly attached to a graph node with a CVSS 3.1 score, attack path linkage, and compliance mapping.

---

## 43 Phases

| Range | Category | Coverage |
|-------|----------|----------|
| 1–9 | Reconnaissance | CT log collection, passive DNS, AXFR, subdomain brute force (2,500+ words + permutations), DNS resolution, IPv6, ASN intelligence, CDN origin bypass |
| 10–17 | Surface Analysis | TLS fingerprinting, HTTP header analysis, content discovery (100+ paths), JavaScript secret scanning, supply chain CVEs, cache poisoning, CORS, HTTP smuggling probes |
| 18–30 | Intelligence | Email security (SPF/DMARC/DKIM), Wayback Machine, reverse IP, JARM C2 fingerprinting, anomaly detection, CVSS 3.1 scoring, attack path synthesis, compliance mapping (OWASP/GDPR/ISO 27001/NIST/PCI-DSS), CVE correlation, graph analytics, scan diff |
| 31–35 | Active Testing | HTTP request smuggling (CL.TE/TE.CL/TE.TE), cross-org correlation, GNN subdomain prediction, authentication analysis (forms/JWT/Basic Auth), parameter fuzzing (SQLi/XSS/SSRF/IDOR/traversal) |
| 36–39 | Advanced | BGP/AS path + cloud provider correlation, SSRF chain pivoting (cloud metadata, internal services, Gopher), OAuth/GraphQL/WebSocket protocol fuzzing, honeypot detection |
| 40–43 | Intelligence+ | Deep CVE fingerprinting (22 technologies), API/OpenAPI/Swagger enumeration, cloud storage enumeration (S3/Azure/GCS/DO), threat intelligence (DNS blacklists, Tor exits, ASN reputation) |

---

## Installation

**Requirements:** Python 3.9+, Linux/macOS/Termux

```bash
git clone https://github.com/DozerMx/Argus
cd Argus
pip install -r requirements.txt
```

**Web UI (optional):**
```bash
pip install fastapi uvicorn websockets
```

---

## Usage

```
python argus.py -d TARGET [OPTIONS]
```

### Basic scans

```bash
# CT log collection + DNS resolution + anomaly detection
python argus.py -d target.com

# Full 43-phase scan
python argus.py -d target.com --full

# Full scan with executive report
python argus.py -d target.com --full --output executive

# Full scan with authentication and fuzzing
python argus.py -d target.com --full --fuzz --auth

# Scan with known credentials
python argus.py -d target.com --full --auth --user admin --password admin123
```

### Targeted modules

```bash
# Subdomain brute force + AXFR
python argus.py -d target.com --brute --axfr

# Deep infrastructure: ASN + CDN bypass + ports
python argus.py -d target.com --deep --cdn-bypass --ports

# Stealth scan (paranoid jitter profile)
python argus.py -d target.com --full --stealth-profile paranoid

# Through Tor
python argus.py -d target.com --full --proxy socks5://127.0.0.1:9050
```

### Bulk and continuous

```bash
# Bulk scan from file
python argus.py -f targets.txt --full --output json

# Continuous monitoring with Slack alerts
python argus.py -d target.com --daemon --webhook https://hooks.slack.com/...

# Web UI dashboard
python argus.py --serve --ui-port 8080
```

---

## Options

```
Target:
  -d DOMAIN             Single target domain
  -f FILE               File with one domain per line

Scan Modules:
  --full                Enable all modules
  --deep                ASN, cloud detection, Wayback, reverse IP
  --brute               Subdomain brute force + permutations
  --axfr                DNS zone transfer
  --cdn-bypass          CDN/WAF origin IP discovery
  --ports               TCP port scan + banner grab (178 ports)
  --jarm                JARM TLS fingerprinting
  --fuzz                Parameter fuzzing (SQLi, XSS, SSRF, IDOR, traversal)
  --auth                Authentication analysis
  --user USER           Username for authenticated scanning
  --password PASS       Password for authenticated scanning

Output:
  --output FORMAT       terminal | html | executive | json | csv
  --outfile PATH        Output file path
  -v                    Verbose logging
  -q                    Quiet mode

Performance:
  --threads N           Concurrent threads (default: 30)
  --timeout N           Request timeout in seconds (default: 10)
  --proxy URL           Proxy (socks5://host:port or http://host:port)
  --no-cache            Disable disk cache
  --stealth-profile     paranoid | careful | normal | aggressive

Web UI:
  --serve               Launch real-time web dashboard
  --ui-port N           Web UI port (default: 8080)

Daemon:
  --daemon              Continuous monitoring mode
  --webhook URL         Webhook URL for alerts (Slack/Telegram)
  --interval N          Scan interval in hours (default: 6)
```

---

## Output

### HTML Report
Interactive graph visualization of the full infrastructure with findings, risk scoring, and relationship mapping. Self-contained single file.

### Executive Report
Business-language summary with attack path narrative, compliance violations by framework, prioritized remediation roadmap, and risk matrix.

### JSON
Complete machine-readable output including the full knowledge graph, all anomalies with CVSS scores, attack paths, and scan metadata. Suitable for integration with SIEM, ticketing, or custom tooling.

---

## Scan Modules Detail

**Content Discovery**
Tests 100+ paths against each alive domain. Detects `.env` files, Git repositories, admin panels, backup archives, database dumps, Spring Actuator endpoints, GraphQL interfaces, and more. Includes SPA/CDN catch-all detection — hosts that respond 200 to any URL are handled correctly with pattern validation to eliminate false positives.

**Fuzzer**
Context-aware parameter fuzzing. Infers parameter type (numeric, string, path, URL) before selecting payloads. Tests SQLi (50 payloads, error-based and time-based), XSS (39 payloads), SSRF (45 payloads including AWS/GCP/Azure metadata), path traversal (33 payloads), open redirect, and IDOR. WAF detection with 3 levels of evasion.

**Authentication**
Discovers login forms, extracts CSRF tokens automatically, detects CAPTCHA and skips. Tests 132 credential combinations including vendor defaults, breach-derived passwords, and domain-specific variants. JWT analysis with HMAC brute force for weak secrets. OAuth/SSO endpoint detection.

**SSRF Chains**
Goes beyond single-endpoint detection. Uses confirmed SSRF to pivot: enumerates AWS IAM credentials, GCP service account tokens, Azure managed identity tokens, and probes internal services (Redis, Elasticsearch, Consul, Prometheus, Tomcat). Tests Gopher protocol for Redis write access.

**BGP Intelligence**
Per-IP AS path analysis via RIPEstat and BGPView. Maps ASN, prefixes, direct peers, IXP presence. Detects route anomalies (multiple origin ASNs) as BGP hijack indicators. Correlates cloud providers by ASN automatically.

**Protocol Fuzzer**
OAuth 2.0: implicit flow detection, missing PKCE, open redirect_uri, missing state parameter, unauthenticated token endpoints.
GraphQL: full introspection, depth limit testing, batch query abuse, field suggestion extraction, mutation enumeration.
WebSocket: origin bypass (CSWSH), unauthenticated upgrade.

**Cloud Storage**
35 permutations of the target name tested against S3, Azure Blob Storage, Google Cloud Storage, and DigitalOcean Spaces. Public buckets yield file listings. Private buckets are confirmed as existing.

**Deep CVE**
Fingerprints 22 technologies (Apache, Nginx, PHP, OpenSSL, Tomcat, Spring, WordPress, jQuery, OpenSSH, Redis, MySQL, etc.) from response headers, banners, and page content. Matches against a versioned CVE database including critical vulnerabilities from 2019–2024.

**Threat Intelligence**
DNS blacklist verification (Spamhaus, SpamCop, SORBS, Barracuda) via public DNS queries. Tor exit node detection. ASN reputation against known bulletproof hosting providers. All sources are public — no API keys required.

---

## Detected Anomaly Categories

| Severity | Examples |
|----------|---------|
| CRITICAL | Email spoofing (no SPF/DMARC), exposed Spring Actuator heapdump, SSRF to cloud metadata, SQL injection confirmed, public S3 bucket, Git config exposed |
| HIGH | Missing HSTS/CSP, admin panels, .env files, CORS misconfiguration, JWT with weak algorithm, HTTP request smuggling, BGP route anomaly |
| MEDIUM | TLS without forward secrecy, GraphQL introspection, missing security headers, wildcard certificates, API spec exposed |
| LOW | Server version disclosure, X-Powered-By header, WordPress detection |

---

## Compliance Mapping

Every finding is mapped to applicable framework controls:

- OWASP Top 10 2021
- GDPR (Articles 25, 32)
- ISO 27001:2022
- NIST CSF 2.0
- PCI-DSS v4.0
- CIS Controls v8

---

## Knowledge Graph

Argus builds a relational graph connecting:

```
Domain ── resolves_to ──> IP ── belongs_to ──> ASN
  |                              |
  +── has_cert ──> Certificate   +── hosts ──> Domain
  |
  +── runs ──> Technology ── has_cve ──> CVE
```

Graph analytics produce:
- Centrality scoring (which nodes are most critical)
- Bridge node detection (single points of failure)
- Cluster identification (related infrastructure groups)
- Attack path synthesis (entry point to target chains)

---

## Scan Diff

Every scan saves a snapshot. Subsequent scans compare against the previous state and report:
- New domains discovered
- New open ports
- New anomaly types
- Infrastructure changes

---

## Requirements

```
aiohttp>=3.9.0
dnspython>=2.4.0
networkx>=3.2.0
rich>=13.7.0
python-dateutil>=2.8.2
```

Optional for web UI:
```
fastapi>=0.110.0
uvicorn[standard]>=0.29.0
websockets>=12.0
```

---

## License

For authorized security testing only. Users are responsible for ensuring they have explicit written permission before scanning any target.

---

*github.com/DozerMx/Argus*
