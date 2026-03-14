"""Simulate data exfiltration events in Elasticsearch."""
import argparse
import datetime
import json
import os
import sys
import uuid

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


def generate_exfiltration_events(source_host: str, destination_ip: str = "198.51.100.1") -> list:
    """Generate DNS tunneling and large transfer exfiltration events."""
    events = []
    base_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    # DNS tunneling events
    suspicious_domains = [
        "data.c2server.xyz",
        "exfil-1234567890.evil.net",
        "beacon.malware.cc",
    ]

    for i, domain in enumerate(suspicious_domains):
        events.append({
            "@timestamp": (base_time + datetime.timedelta(seconds=i * 60)).isoformat() + "Z",
            "event": {
                "category": "network",
                "type": "connection",
                "dataset": "zeek.dns",
            },
            "host": {"name": source_host},
            "source": {"ip": "10.0.0.50"},
            "destination": {"ip": destination_ip, "port": 53},
            "network": {"protocol": "dns", "transport": "udp"},
            "dns": {
                "question": {"name": domain, "type": "TXT"},
                "answers": [{"ttl": 60, "data": "dGVzdC1kYXRh"}],
            },
            "message": f"Suspicious DNS TXT query to {domain}",
            "simulation": True,
            "simulation_id": str(uuid.uuid4()),
        })

    # Large outbound transfer
    events.append({
        "@timestamp": (base_time + datetime.timedelta(minutes=5)).isoformat() + "Z",
        "event": {
            "category": "network",
            "type": "connection",
            "outcome": "success",
        },
        "host": {"name": source_host},
        "source": {"ip": "10.0.0.50", "port": 54321},
        "destination": {"ip": destination_ip, "port": 443},
        "network": {
            "bytes": 104857600,  # 100 MB
            "protocol": "tls",
            "transport": "tcp",
        },
        "message": f"Large outbound transfer to {destination_ip}: 100MB",
        "simulation": True,
        "simulation_id": str(uuid.uuid4()),
    })

    return events


def main():
    parser = argparse.ArgumentParser(description="Simulate data exfiltration events")
    parser.add_argument("--source-host", default="workstation-001")
    parser.add_argument("--destination-ip", default="198.51.100.1")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    events = generate_exfiltration_events(args.source_host, args.destination_ip)

    if args.dry_run:
        for event in events:
            print(json.dumps(event))
        return

    from elastic_api.client import ElasticClient
    client = ElasticClient(
        host=os.environ["ELASTIC_HOST"],
        username=os.environ.get("ELASTIC_USER", "elastic"),
        password=os.environ["ELASTIC_PASSWORD"],
        verify_tls=os.environ.get("ELASTIC_VERIFY_TLS", "false").lower() == "true",
    )

    for event in events:
        client.index_document("logs-simulation.exfiltration", event)

    print(f"[✓] Indexed {len(events)} exfiltration simulation events")


if __name__ == "__main__":
    main()
