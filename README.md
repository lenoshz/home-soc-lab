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
| `p1_elastic_soc` | Elastic SOC assets: 9 detection rules, 9 runbooks, infra scripts, simulation scripts |
| `p2_tines_soar` | Tines connector, allowlist Flask service, story exports, ES index mappings |
| `p3_phishing_pipeline` | EML parser, threat-intel enrichment (VT/urlscan/AbuseIPDB), verdict engine, pipeline |

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
# Automated setup (Docker required):
bash p1_elastic_soc/infra/setup_elastic.sh
bash p1_elastic_soc/infra/setup_kibana.sh

# Or use docker compose if you have a docker-compose.yml
# docker compose up -d
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
PYTHONPATH=. pytest p2_tines_soar/ -v
```

---

## Running the Phishing Pipeline

```bash
# Process a single EML file (no Elasticsearch needed):
PYTHONPATH=. python -m p3_phishing_pipeline.pipeline --file p3_phishing_pipeline/samples/phishing_sample.eml --no-elastic

# Watch a directory (requires Elasticsearch + env vars):
PYTHONPATH=. python -m p3_phishing_pipeline.pipeline --watch /path/to/eml-drop --interval 30
```

## TLS / Self-Signed Cert Notes

Local Elastic installs often use self-signed TLS certificates. To handle these:

- Set `ELASTIC_VERIFY_TLS=false` in `.env` to skip verification (insecure, for local dev only)
- Set `ELASTIC_CA_CERT=/path/to/ca.crt` to trust a specific CA certificate (preferred)
- The `ElasticClient` and all Kibana requests honour both settings

## P1 Simulations

```bash
# Dry-run (no Elasticsearch needed):
PYTHONPATH=. python p1_elastic_soc/simulations/simulate_brute_force.py --dry-run
PYTHONPATH=. python p1_elastic_soc/simulations/simulate_lateral_movement.py --dry-run
PYTHONPATH=. python p1_elastic_soc/simulations/simulate_exfiltration.py --dry-run
```

## P2 SOAR Setup

```bash
# Apply ES index mappings for SOAR indices:
PYTHONPATH=. python p2_tines_soar/mappings/apply_mappings.py

# Register Kibana connector + alerting rule (requires running Kibana + TINES_WEBHOOK_URL):
PYTHONPATH=. python p2_tines_soar/connector/register_connector.py

# Run allowlist service:
PYTHONPATH=. python p2_tines_soar/allowlist_service/app.py
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
├── elastic_api/                # Shared Elastic/Kibana client
│   ├── client.py               #   ElasticClient + ElasticAPIError
│   └── tests/
├── p1_elastic_soc/             # P1: Elastic SOC lab assets
│   ├── infra/                  #   setup_elastic.sh, setup_kibana.sh
│   ├── detection_rules/        #   9 TOML detection rules (MITRE-mapped)
│   ├── runbooks/               #   9 incident response runbooks
│   └── simulations/            #   brute_force, lateral_movement, exfiltration
├── p2_tines_soar/              # P2: Tines SOAR integration
│   ├── allowlist_service/      #   Flask IP/domain allowlist microservice
│   │   └── app.py
│   ├── connector/              #   Kibana connector + alerting rule registration
│   ├── mappings/               #   soar-cases + soar-audit ES mappings
│   ├── stories/                #   phishing_triage.json, alert_response.json
│   └── tests/
├── p3_phishing_pipeline/       # P3: Phishing analysis pipeline
│   ├── eml_parser.py
│   ├── header_analyser.py
│   ├── verdict_engine.py
│   ├── pipeline.py             #   CLI: --file / --watch modes
│   ├── enrichment/             #   virustotal, urlscan, abuseipdb, ip_extractor
│   ├── samples/                #   phishing_sample.eml, clean_sample.eml
│   └── tests/
├── .env.example
├── requirements.txt
└── Makefile
```

---

## License

MIT