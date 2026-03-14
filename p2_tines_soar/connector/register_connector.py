"""Register Kibana connector and alerting rule for Tines SOAR."""
import json
import os
import sys
import requests
from dotenv import load_dotenv

load_dotenv()

WEBHOOK_PAYLOAD_TEMPLATE = {
    "alert_id": "{{alert.id}}",
    "rule_name": "{{rule.name}}",
    "source_ip": "{{context.source_ip}}",
    "host_name": "{{context.host_name}}",
    "severity": "{{rule.severity}}",
    "timestamp": "{{context.timestamp}}",
    "kibana_alert_url": "{{context.kibana_alert_url}}",
}


def get_session() -> requests.Session:
    session = requests.Session()
    verify_tls = os.environ.get("ELASTIC_VERIFY_TLS", "false").lower() == "true"
    ca_cert = os.environ.get("ELASTIC_CA_CERT", "")
    session.verify = ca_cert if ca_cert else verify_tls
    session.auth = (
        os.environ.get("ELASTIC_USER", "elastic"),
        os.environ.get("ELASTIC_PASSWORD", "changeme"),
    )
    session.headers.update({"kbn-xsrf": "true", "Content-Type": "application/json"})
    if not verify_tls and not ca_cert:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return session


def create_kibana_connector(session: requests.Session, kibana_host: str, tines_webhook_url: str) -> str:
    """Create a Tines webhook connector in Kibana. Returns connector ID."""
    url = f"{kibana_host}/api/actions/connector"
    payload = {
        "name": "Tines SOAR Webhook",
        "connector_type_id": ".webhook",
        "config": {
            "url": tines_webhook_url,
            "method": "post",
            "headers": {"Content-Type": "application/json"},
        },
        "secrets": {},
    }
    resp = session.post(url, json=payload)
    resp.raise_for_status()
    connector_id = resp.json()["id"]
    print(f"Created connector: {connector_id}")
    return connector_id


def create_alerting_rule(
    session: requests.Session,
    kibana_host: str,
    connector_id: str,
    rule_name: str = "SOC Alert → Tines",
) -> str:
    """Create an Elasticsearch alerting rule that fires to the Tines connector."""
    url = f"{kibana_host}/api/alerting/rule"
    payload = {
        "name": rule_name,
        "rule_type_id": ".es-query",
        "consumer": "alerts",
        "schedule": {"interval": "1m"},
        "params": {
            "index": [".alerts-security.alerts-default"],
            "timeField": "@timestamp",
            "esQuery": json.dumps({"query": {"match_all": {}}}),
            "size": 10,
            "timeWindowSize": 5,
            "timeWindowUnit": "m",
            "thresholdComparator": ">",
            "threshold": [0],
        },
        "actions": [
            {
                "id": connector_id,
                "group": "threshold met",
                "params": {
                    "body": json.dumps(WEBHOOK_PAYLOAD_TEMPLATE),
                },
            }
        ],
    }
    resp = session.post(url, json=payload)
    resp.raise_for_status()
    rule_id = resp.json()["id"]
    print(f"Created alerting rule: {rule_id}")
    return rule_id


def main():
    kibana_host = os.environ.get("KIBANA_HOST", "https://localhost:5601").rstrip("/")
    tines_webhook_url = os.environ.get("TINES_WEBHOOK_URL", "")

    if not tines_webhook_url:
        print("ERROR: TINES_WEBHOOK_URL is not set", file=sys.stderr)
        sys.exit(1)

    session = get_session()
    connector_id = create_kibana_connector(session, kibana_host, tines_webhook_url)
    rule_id = create_alerting_rule(session, kibana_host, connector_id)
    print(f"Done. Connector: {connector_id}, Rule: {rule_id}")


if __name__ == "__main__":
    main()
