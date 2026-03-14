# Home SOC Lab

A home Security Operations Centre (SOC) lab monorepo — detection rules, phishing triage pipeline, and SOAR automation with Tines, all wired to an Elastic/Kibana SIEM.

---

## Architecture

```
Elastic/Kibana (SIEM)
        │
        ├── Detection Rules (P1)
        │       └── Alerts → Tines (SOAR) via Webhook
        │
        ├── Phishing Pipeline (P3)
        │       EML files → Parse → Enrich (VT/urlscan/abuseipdb)
        │       → Verdict Engine → phishing-verdicts index
        │       └── Optional Tines Webhook
        │
        └── Tines SOAR (P2)
                ├── Allowlist Service (Flask)
                ├── Connector (Kibana→Tines)
                └── Stories (phishing_triage, alert_response)
```

---

## Packages

| Package | Description |
|---|---|
| `elastic_api` | Unified Elasticsearch + Kibana client (index, search, host isolation) |
| `p1_detection_rules` | KQL/EQL detection rules and rule loader |
| `p2_tines_soar` | Tines connector, allowlist Flask service, story exports |
| `p3_phishing_pipeline` | EML parser, threat-intel enrichment, verdict engine |

---

## Quickstart

### Prerequisites

- Docker & Docker Compose
- Python 3.9+

### 1. Clone & configure

```bash
git clone https://github.com/your-org/home-soc-lab.git
cd home-soc-lab
cp .env.example .env
# Edit .env with your credentials and API keys
```

### 2. Start Elastic stack

```bash
docker compose up -d
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
# or
make install
```

---

## Running Tests

```bash
PYTHONPATH=. pytest
# or
make test
```

Run tests for a specific package:

```bash
PYTHONPATH=. pytest elastic_api/ -v
PYTHONPATH=. pytest p3_phishing_pipeline/ -v
```

---

## Linting

```bash
make lint
```

---

## Environment Variables

See [`.env.example`](.env.example) for all supported variables.

| Variable | Description |
|---|---|
| `ELASTIC_HOST` | Elasticsearch URL (default: `https://localhost:9200`) |
| `ELASTIC_USER` | Elasticsearch username |
| `ELASTIC_PASSWORD` | Elasticsearch password |
| `KIBANA_HOST` | Kibana URL (default: `https://localhost:5601`) |
| `ELASTIC_VERIFY_TLS` | Verify TLS certificates (`true`/`false`) |
| `ELASTIC_CA_CERT` | Path to CA certificate file |
| `VT_API_KEY` | VirusTotal API key (phishing pipeline) |
| `URLSCAN_API_KEY` | urlscan.io API key (phishing pipeline) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key (phishing pipeline) |
| `TINES_WEBHOOK_URL` | Tines inbound webhook URL |
| `TINES_ALLOWLIST_URL` | Allowlist service URL |

---

## Project Structure

```
home-soc-lab/
├── elastic_api/            # Shared Elastic/Kibana client
│   ├── client.py
│   └── tests/
├── p1_detection_rules/     # Detection rules (KQL/EQL)
├── p2_tines_soar/          # Tines SOAR integration
│   └── allowlist_service/  # Flask allowlist microservice
├── p3_phishing_pipeline/   # Phishing triage pipeline
├── .env.example
├── requirements.txt
├── Makefile
└── docker-compose.yml
```

---

## License

MIT