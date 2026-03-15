import glob
import os

import requests
import toml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RULE_DIR = os.path.join(REPO_ROOT, "p1_elastic_soc", "detection_rules")

KIBANA_HOST = os.getenv("KIBANA_HOST", "http://localhost:5601").rstrip("/")
ELASTIC_USER = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "changeme")

def import_one(rule_path: str):
    rule_toml = toml.load(rule_path)["rule"]
    payload = {
        "rule_id": rule_toml["id"],
        "name": rule_toml["name"],
        "description": rule_toml.get("description", ""),
        "risk_score": int(rule_toml["risk_score"]),
        "severity": rule_toml["severity"],
        "type": rule_toml["type"],
        "language": rule_toml.get("language", "kuery"),
        "query": rule_toml["query"],
        "from": rule_toml.get("from", "now-5m"),
        "interval": rule_toml.get("interval", "1m"),
        "tags": rule_toml.get("tags", []),
        "enabled": bool(rule_toml.get("enabled", True)),
        # Lab-friendly: search everywhere. We’ll narrow later once we know simulation index.
        "index": ["*"],
    }

    r = requests.post(
        f"{KIBANA_HOST}/api/detection_engine/rules",
        auth=(ELASTIC_USER, ELASTIC_PASSWORD),
        headers={"kbn-xsrf": "true"},
        json=payload,
        timeout=60,
    )
    return r.status_code, r.text

def main():
    files = sorted(glob.glob(os.path.join(RULE_DIR, "*.toml")))
    print(f"Found {len(files)} TOML rules in {RULE_DIR}")
    for f in files:
        code, text = import_one(f)
        print(f"{os.path.basename(f)} -> {code} {text[:120]}")

if __name__ == "__main__":
    main()
