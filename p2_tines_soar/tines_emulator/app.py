import os
import uuid
import datetime as dt

import requests
from flask import Flask, jsonify, request
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env")

ELASTIC_HOST = os.environ.get("ELASTIC_HOST", "http://localhost:9200").rstrip("/")
ELASTIC_USER = os.environ.get("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD = os.environ.get("ELASTIC_PASSWORD", "changeme")

ALLOWLIST_BASE_URL = os.environ.get("ALLOWLIST_BASE_URL", "http://127.0.0.1:5000").rstrip("/")

SOAR_CASES_INDEX = os.environ.get("SOAR_CASES_INDEX", "soar-cases")
SOAR_AUDIT_INDEX = os.environ.get("SOAR_AUDIT_INDEX", "soar-audit")

app = Flask(__name__)

def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()

def es_post(index: str, doc: dict) -> dict:
    r = requests.post(
        f"{ELASTIC_HOST}/{index}/_doc",
        auth=(ELASTIC_USER, ELASTIC_PASSWORD),
        headers={"Content-Type": "application/json"},
        json=doc,
        timeout=30,
    )
    r.raise_for_status()
    return r.json()

def write_audit(case_id: str, action: str, details: str, result: str = "success") -> None:
    es_post(
        SOAR_AUDIT_INDEX,
        {
            "event_id": str(uuid.uuid4()),
            "case_id": case_id,
            "action": action,
            "actor": "tines_emulator",
            "timestamp": now_iso(),
            "details": details,
            "source_system": "tines_emulator",
            "result": result,
        },
    )

def check_allowlist_ip(ip: str | None) -> bool:
    if not ip:
        return False
    # We'll discover exact routes if needed; try common ones gracefully.
    for path in (f"/allowlist/check/{ip}", f"/check/{ip}"):
        try:
            r = requests.get(f"{ALLOWLIST_BASE_URL}{path}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                # accept {allowed: true} or {allowlisted: true}
                return bool(data.get("allowed") or data.get("allowlisted"))
        except Exception:
            continue
    return False

@app.get("/health")
def health():
    return jsonify({"status": "ok"})

@app.post("/tines/alert")
def tines_alert():
    body = request.get_json(force=True)

    alert_id = body.get("alert_id")
    rule_name = body.get("rule_name", "Unknown Rule")
    source_ip = body.get("source_ip")
    host_name = body.get("host_name")
    severity = body.get("severity", "unknown")
    timestamp = body.get("timestamp") or now_iso()
    kibana_alert_url = body.get("kibana_alert_url", "")

    # Simple case id + run id for traceability
    case_id = str(uuid.uuid4())
    tines_run_id = case_id

    allowlisted = check_allowlist_ip(source_ip)

    es_post(
        SOAR_CASES_INDEX,
        {
            "case_id": case_id,
            "alert_id": alert_id,
            "rule_name": rule_name,
            "source_ip": source_ip,
            "host_name": host_name,
            "severity": severity,
            "timestamp": timestamp,
            "kibana_alert_url": kibana_alert_url,
            "tines_story": "kibana_alert_ingest",
            "tines_run_id": tines_run_id,
            "case_status": "ignored_allowlisted" if allowlisted else "new",
            "allowlisted": allowlisted,
            "created_at": now_iso(),
            "updated_at": now_iso(),
        },
    )

    write_audit(case_id, "case_created", f"Created from rule={rule_name} alert_id={alert_id} source_ip={source_ip}")

    if allowlisted:
        write_audit(case_id, "guardrail_stop", f"Stopped: source_ip={source_ip} is allowlisted", result="skipped")

    return jsonify({"ok": True, "case_id": case_id, "allowlisted": allowlisted})

if __name__ == "__main__":
    port = int(os.environ.get("TINES_EMULATOR_PORT", "5055"))
    app.run(host="0.0.0.0", port=port, debug=False)
