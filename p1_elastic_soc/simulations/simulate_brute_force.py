"""Simulate brute force authentication events in Elasticsearch."""
import argparse
import datetime
import json
import os
import sys
import uuid

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


def generate_brute_force_events(target_host: str, source_ip: str, count: int = 20) -> list:
    """Generate brute force authentication failure events."""
    events = []
    # Use timezone-aware UTC datetime then strip tzinfo so isoformat() produces a
    # clean 'YYYY-MM-DDTHH:MM:SS' string; the 'Z' suffix is appended explicitly below.
    base_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    usernames = ["admin", "administrator", "root", "user", "test", "guest"]

    for i in range(count):
        timestamp = (base_time + datetime.timedelta(seconds=i * 3)).isoformat() + "Z"
        events.append({
            "@timestamp": timestamp,
            "event": {
                "category": "authentication",
                "outcome": "failure",
                "type": "start",
                "dataset": "system.auth",
            },
            "host": {"name": target_host},
            "source": {"ip": source_ip},
            "user": {"name": usernames[i % len(usernames)]},
            "winlog": {"event_id": 4625},
            "message": f"Authentication failure for {usernames[i % len(usernames)]} from {source_ip}",
            "simulation": True,
            "simulation_id": str(uuid.uuid4()),
        })

    # Add one success to simulate successful compromise
    events.append({
        "@timestamp": (base_time + datetime.timedelta(seconds=count * 3)).isoformat() + "Z",
        "event": {
            "category": "authentication",
            "outcome": "success",
            "type": "start",
            "dataset": "system.auth",
        },
        "host": {"name": target_host},
        "source": {"ip": source_ip},
        "user": {"name": "admin"},
        "winlog": {"event_id": 4624},
        "message": f"Authentication success for admin from {source_ip}",
        "simulation": True,
        "simulation_id": str(uuid.uuid4()),
    })

    return events


def main():
    parser = argparse.ArgumentParser(description="Simulate brute force events")
    parser.add_argument("--target-host", default="workstation-001", help="Target hostname")
    parser.add_argument("--source-ip", default="203.0.113.100", help="Attacker source IP")
    parser.add_argument("--count", type=int, default=20, help="Number of failure events")
    parser.add_argument("--dry-run", action="store_true", help="Print events without indexing")
    args = parser.parse_args()

    events = generate_brute_force_events(args.target_host, args.source_ip, args.count)

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
        client.index_document("soc-events-000001", event)

    print(f"[✓] Indexed {len(events)} brute force simulation events to logs-simulation.brute_force")


if __name__ == "__main__":
    main()
