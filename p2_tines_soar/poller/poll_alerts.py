import json
import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env")

ELASTIC_HOST = os.environ.get("ELASTIC_HOST", "http://localhost:9200").rstrip("/")
ELASTIC_USER = os.environ.get("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD = os.environ.get("ELASTIC_PASSWORD", "changeme")

ALERT_INDEX_PATTERN = os.environ.get(
    "ALERT_INDEX_PATTERN",
    ".internal.alerts-security.alerts-default-*",
)

# Local emulator endpoint (host-side)
TINES_EMULATOR_URL = os.environ.get("TINES_EMULATOR_URL", "http://127.0.0.1:5055/tines/alert")

POLL_LOOKBACK_MINUTES = int(os.environ.get("POLL_LOOKBACK_MINUTES", "15"))
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "30"))

STATE_FILE = Path(os.environ.get("SOAR_POLLER_STATE_FILE", ".soar_poller_state.json"))

def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"processed_ids": []}

def save_state(state: dict) -> None:
    # Keep file from growing forever
    processed = state.get("processed_ids", [])
    state["processed_ids"] = processed[-5000:]
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True))

def es_search_new_alerts() -> list[dict]:
    query = {
        "size": 50,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "range": {
                "@timestamp": {
                    "gte": f"now-{POLL_LOOKBACK_MINUTES}m",
                    "lte": "now",
                }
            }
        },
    }
    r = requests.get(
        f"{ELASTIC_HOST}/{ALERT_INDEX_PATTERN}/_search",
        auth=(ELASTIC_USER, ELASTIC_PASSWORD),
        headers={"Content-Type": "application/json"},
        data=json.dumps(query),
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["hits"]["hits"]

def to_emulator_payload(hit: dict) -> dict:
    src = hit.get("_source", {}) or {}
    return {
        "alert_id": hit.get("_id"),
        "rule_name": src.get("kibana.alert.rule.name"),
        "severity": src.get("kibana.alert.severity") or src.get("kibana.alert.rule.parameters", {}).get("severity"),
        "timestamp": src.get("@timestamp"),
        "source_ip": (src.get("source") or {}).get("ip"),
        "host_name": (src.get("host") or {}).get("name"),
        "kibana_alert_url": "",  # optional; you can add later if you build a URL format
        "message": src.get("message"),
        "raw": src,  # keep full context for debugging
    }

def main():
    print(f"[poller] elastic={ELASTIC_HOST} index={ALERT_INDEX_PATTERN}")
    print(f"[poller] emulator={TINES_EMULATOR_URL}")
    state = load_state()
    processed = set(state.get("processed_ids", []))

    while True:
        try:
            hits = es_search_new_alerts()
            new_hits = [h for h in hits if h.get("_id") not in processed]

            # process oldest -> newest so case chronology makes sense
            for hit in reversed(new_hits):
                payload = to_emulator_payload(hit)
                resp = requests.post(TINES_EMULATOR_URL, json=payload, timeout=30)
                resp.raise_for_status()

                processed.add(hit["_id"])
                state["processed_ids"] = list(processed)
                save_state(state)

                print(f"[poller] sent alert_id={hit['_id']} rule={payload.get('rule_name')}")

        except Exception as exc:
            print(f"[poller] ERROR: {exc}")

        time.sleep(POLL_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()
