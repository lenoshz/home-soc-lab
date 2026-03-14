"""Apply Elasticsearch index mappings for SOAR indices."""
import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

MAPPINGS_DIR = Path(__file__).parent
INDICES = {
    "soar-cases": MAPPINGS_DIR / "soar_cases.json",
    "soar-audit": MAPPINGS_DIR / "soar_audit.json",
}


def apply_mappings():
    from elastic_api.client import ElasticClient, ElasticAPIError

    client = ElasticClient(
        host=os.environ["ELASTIC_HOST"],
        username=os.environ["ELASTIC_USER"],
        password=os.environ["ELASTIC_PASSWORD"],
        kibana_host=os.environ.get("KIBANA_HOST"),
        verify_tls=os.environ.get("ELASTIC_VERIFY_TLS", "false").lower() == "true",
        ca_cert=os.environ.get("ELASTIC_CA_CERT") or None,
    )

    for index_name, mapping_file in INDICES.items():
        mapping = json.loads(mapping_file.read_text())
        try:
            result = client.create_index(index_name, mapping)
            if result.get("already_exists"):
                print(f"Index '{index_name}' already exists, skipping.")
            else:
                print(f"Created index '{index_name}'.")
        except Exception as exc:
            print(f"Failed to create '{index_name}': {exc}", file=sys.stderr)


if __name__ == "__main__":
    apply_mappings()
