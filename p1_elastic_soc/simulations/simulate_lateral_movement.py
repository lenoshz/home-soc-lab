"""Simulate lateral movement events in Elasticsearch."""
import argparse
import datetime
import json
import os
import sys
import uuid

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


def generate_lateral_movement_events(source_host: str, target_hosts: list, source_ip: str = "10.0.0.50") -> list:
    """Generate lateral movement network events."""
    events = []
    base_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    for i, target_host in enumerate(target_hosts):
        # SMB connection attempt
        events.append({
            "@timestamp": (base_time + datetime.timedelta(seconds=i * 30)).isoformat() + "Z",
            "event": {
                "category": "network",
                "action": "connection_attempted",
                "type": "connection",
                "outcome": "success",
            },
            "host": {"name": source_host},
            "source": {"ip": source_ip, "port": 49152 + i},
            "destination": {"ip": f"10.0.0.{100 + i}", "port": 445, "name": target_host},
            "network": {"protocol": "smb", "transport": "tcp"},
            "message": f"SMB connection from {source_host} to {target_host}:445",
            "simulation": True,
            "simulation_id": str(uuid.uuid4()),
        })

        # WMI execution
        events.append({
            "@timestamp": (base_time + datetime.timedelta(seconds=i * 30 + 10)).isoformat() + "Z",
            "event": {
                "category": "network",
                "action": "connection_attempted",
                "type": "connection",
                "outcome": "success",
            },
            "host": {"name": source_host},
            "source": {"ip": source_ip, "port": 49160 + i},
            "destination": {"ip": f"10.0.0.{100 + i}", "port": 135, "name": target_host},
            "network": {"protocol": "msrpc", "transport": "tcp"},
            "message": f"WMI/RPC connection from {source_host} to {target_host}:135",
            "simulation": True,
            "simulation_id": str(uuid.uuid4()),
        })

    return events


def main():
    parser = argparse.ArgumentParser(description="Simulate lateral movement events")
    parser.add_argument("--source-host", default="workstation-001", help="Source hostname")
    parser.add_argument("--target-hosts", nargs="+", default=["server-001", "server-002", "workstation-002"])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    events = generate_lateral_movement_events(args.source_host, args.target_hosts)

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
        client.index_document("logs-simulation.lateral_movement", event)

    print(f"[✓] Indexed {len(events)} lateral movement simulation events")


if __name__ == "__main__":
    main()
