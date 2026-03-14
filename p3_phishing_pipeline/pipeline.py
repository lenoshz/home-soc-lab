"""
Phishing analysis pipeline.

Usage:
  # Process single file:
  python -m p3_phishing_pipeline.pipeline --file suspicious.eml

  # Watch directory:
  python -m p3_phishing_pipeline.pipeline --watch /path/to/dir --interval 30
"""
import argparse
import json
import logging
import os
import sys
import time
import uuid
import datetime
from pathlib import Path
from typing import Optional, List

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("phishing_pipeline")

PHISHING_VERDICTS_INDEX = "phishing-verdicts"
FAILED_INGESTS_FILE = "failed_ingests.jsonl"

PHISHING_VERDICTS_MAPPING = {
    "mappings": {
        "properties": {
            "message_id": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "subject": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "sender": {"type": "keyword"},
            "sender_domain": {"type": "keyword"},
            "recipients": {"type": "keyword"},
            "sending_ips": {"type": "ip"},
            "urls": {
                "type": "nested",
                "properties": {
                    "original": {"type": "keyword"},
                    "defanged": {"type": "keyword"},
                },
            },
            "verdict": {"type": "keyword"},
            "score": {"type": "float"},
            "tines_processed": {"type": "boolean"},
            "resolved": {"type": "boolean"},
            "pipeline_run_id": {"type": "keyword"},
            "header_analysis": {
                "type": "object",
                "properties": {
                    "score": {"type": "float"},
                    "flags": {"type": "keyword"},
                    "reply_to_mismatch": {"type": "boolean"},
                    "free_sender_domain": {"type": "boolean"},
                    "suspicious_subject": {"type": "boolean"},
                },
            },
        }
    }
}


def get_elastic_client():
    """Build ElasticClient from environment variables."""
    from elastic_api.client import ElasticClient
    return ElasticClient(
        host=os.environ["ELASTIC_HOST"],
        username=os.environ["ELASTIC_USER"],
        password=os.environ["ELASTIC_PASSWORD"],
        kibana_host=os.environ.get("KIBANA_HOST"),
        verify_tls=os.environ.get("ELASTIC_VERIFY_TLS", "false").lower() == "true",
        ca_cert=os.environ.get("ELASTIC_CA_CERT") or None,
    )


def spool_failed_ingest(doc: dict, error: str):
    """Append a failed ingest to the failed_ingests.jsonl spool file."""
    record = {"error": error, "document": doc, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    with open(FAILED_INGESTS_FILE, "a") as fh:
        fh.write(json.dumps(record) + "\n")
    logger.warning("Failed ingest spooled: %s", error)


def post_tines_webhook(doc: dict, webhook_url: str):
    """Post verdict to Tines webhook."""
    import requests
    try:
        resp = requests.post(webhook_url, json=doc, timeout=10)
        resp.raise_for_status()
        logger.info("Tines webhook posted: %s", resp.status_code)
    except Exception as exc:
        logger.warning("Tines webhook post failed: %s", exc)


def run_enrichment(parsed_email: dict) -> dict:
    """Run enrichment against external APIs. Continues on partial failure."""
    vt_key = os.environ.get("VT_API_KEY", "")
    urlscan_key = os.environ.get("URLSCAN_API_KEY", "")
    abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "")

    enrichment = {"vt_ips": [], "vt_urls": [], "urlscan_urls": [], "abuseipdb_ips": []}

    sending_ips = parsed_email.get("sending_ips", [])
    urls = parsed_email.get("urls", [])

    if vt_key:
        from p3_phishing_pipeline.enrichment.virustotal import VirusTotalClient
        vt = VirusTotalClient(vt_key)
        for ip in sending_ips:
            try:
                enrichment["vt_ips"].append(vt.lookup_ip(ip))
            except Exception as exc:
                logger.warning("VT IP lookup failed for %s: %s", ip, exc)
        for url in urls[:10]:  # Limit to first 10 URLs
            try:
                enrichment["vt_urls"].append(vt.lookup_url(url))
            except Exception as exc:
                logger.warning("VT URL lookup failed for %s: %s", url, exc)

    if urlscan_key:
        from p3_phishing_pipeline.enrichment.urlscan import UrlscanClient
        us = UrlscanClient(urlscan_key)
        for url in urls[:5]:
            try:
                enrichment["urlscan_urls"].append(us.lookup_url(url))
            except Exception as exc:
                logger.warning("urlscan lookup failed for %s: %s", url, exc)

    if abuseipdb_key:
        from p3_phishing_pipeline.enrichment.abuseipdb import AbuseIPDBClient
        adb = AbuseIPDBClient(abuseipdb_key)
        for ip in sending_ips:
            try:
                enrichment["abuseipdb_ips"].append(adb.check_ip(ip))
            except Exception as exc:
                logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)

    return enrichment


def process_eml_file(file_path: str, es_client=None, tines_webhook_url: str = None) -> dict:
    """Process a single EML file through the full pipeline."""
    from p3_phishing_pipeline.eml_parser import parse_eml
    from p3_phishing_pipeline.header_analyser import analyse_headers
    from p3_phishing_pipeline.verdict_engine import build_verdict_document

    pipeline_run_id = str(uuid.uuid4())
    logger.info("Processing %s (run_id=%s)", file_path, pipeline_run_id)

    parsed = parse_eml(file_path)
    header_analysis = analyse_headers(parsed)
    enrichment = run_enrichment(parsed)
    doc = build_verdict_document(parsed, header_analysis, enrichment, pipeline_run_id)

    if es_client:
        try:
            es_client.create_index(PHISHING_VERDICTS_INDEX, PHISHING_VERDICTS_MAPPING)
            es_client.index_document(PHISHING_VERDICTS_INDEX, doc, doc_id=pipeline_run_id)
            logger.info("Indexed verdict for %s: %s (score=%.3f)", file_path, doc["verdict"], doc["score"])
        except Exception as exc:
            spool_failed_ingest(doc, str(exc))

    if tines_webhook_url:
        post_tines_webhook(doc, tines_webhook_url)

    return doc


def watch_directory(directory: str, interval: int = 30, es_client=None, tines_webhook_url: str = None):
    """Watch a directory for new EML files."""
    processed = set()
    logger.info("Watching %s every %ss", directory, interval)
    while True:
        try:
            for entry in Path(directory).iterdir():
                if entry.suffix.lower() == ".eml" and str(entry) not in processed:
                    try:
                        age = time.time() - entry.stat().st_mtime
                        if age >= 5:
                            process_eml_file(str(entry), es_client, tines_webhook_url)
                            processed.add(str(entry))
                    except FileNotFoundError:
                        pass
        except Exception as exc:
            logger.error("Watch loop error: %s", exc)
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="Phishing analysis pipeline")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Process a single EML file")
    group.add_argument("--watch", metavar="DIR", help="Watch directory for EML files")
    parser.add_argument("--interval", type=int, default=30, help="Watch interval seconds (default: 30)")
    parser.add_argument("--no-elastic", action="store_true", help="Skip Elasticsearch indexing")
    parser.add_argument("--tines-webhook", help="Tines webhook URL (overrides TINES_WEBHOOK_URL env)")
    args = parser.parse_args()

    es_client = None
    if not args.no_elastic:
        try:
            es_client = get_elastic_client()
        except KeyError as exc:
            logger.warning("Missing env var %s; running without Elasticsearch", exc)

    tines_url = args.tines_webhook or os.environ.get("TINES_WEBHOOK_URL", "")

    if args.file:
        doc = process_eml_file(args.file, es_client, tines_url or None)
        print(json.dumps(doc, indent=2, default=str))
    else:
        watch_directory(args.watch, args.interval, es_client, tines_url or None)


if __name__ == "__main__":
    main()
