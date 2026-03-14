"""Verdict engine: combines header analysis and enrichment results into a final verdict."""
from typing import Dict, Any, List, Optional


# Thresholds
VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN = "clean"

MALICIOUS_THRESHOLD = 0.7
SUSPICIOUS_THRESHOLD = 0.4


def score_enrichment(
    vt_ip_results: List[dict] = None,
    vt_url_results: List[dict] = None,
    urlscan_results: List[dict] = None,
    abuseipdb_results: List[dict] = None,
) -> float:
    """
    Score enrichment results. Returns a float 0.0-1.0.
    Each source can contribute up to a max weight.
    """
    score = 0.0
    
    # VT IP: each malicious IP adds score
    for result in (vt_ip_results or []):
        malicious = result.get("malicious", 0)
        if malicious > 0:
            score += min(malicious / 20, 0.3)

    # VT URL: each malicious URL adds score
    for result in (vt_url_results or []):
        malicious = result.get("malicious", 0)
        if malicious > 0:
            score += min(malicious / 15, 0.4)
        suspicious = result.get("suspicious", 0)
        if suspicious > 0:
            score += min(suspicious / 20, 0.1)

    # urlscan: malicious URLs
    for result in (urlscan_results or []):
        if result.get("malicious"):
            score += 0.3

    # AbuseIPDB: high confidence abuse reports
    for result in (abuseipdb_results or []):
        abuse = result.get("abuse_score", 0)
        if abuse >= 75:
            score += 0.3
        elif abuse >= 25:
            score += 0.15

    return min(score, 1.0)


def compute_verdict(
    header_score: float,
    enrichment_score: float,
    header_flags: List[str] = None,
    header_weight: float = 0.3,
    enrichment_weight: float = 0.7,
) -> Dict[str, Any]:
    """
    Compute final verdict combining header analysis and enrichment scores.

    Returns dict with:
        verdict: "malicious" | "suspicious" | "clean"
        score: float (0.0 to 1.0)
        header_score: float
        enrichment_score: float
        header_flags: list[str]
    """
    combined = (header_score * header_weight) + (enrichment_score * enrichment_weight)
    combined = min(combined, 1.0)

    if combined >= MALICIOUS_THRESHOLD:
        verdict = VERDICT_MALICIOUS
    elif combined >= SUSPICIOUS_THRESHOLD:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_CLEAN

    return {
        "verdict": verdict,
        "score": round(combined, 4),
        "header_score": round(header_score, 4),
        "enrichment_score": round(enrichment_score, 4),
        "header_flags": header_flags or [],
    }


def build_verdict_document(
    parsed_email: Dict[str, Any],
    header_analysis: Dict[str, Any],
    enrichment: Dict[str, Any],
    pipeline_run_id: str = None,
) -> Dict[str, Any]:
    """
    Build a complete phishing verdict document for indexing into `phishing-verdicts`.

    Args:
        parsed_email: output of eml_parser.parse_eml()
        header_analysis: output of header_analyser.analyse_headers()
        enrichment: dict with keys vt_ips, vt_urls, urlscan_urls, abuseipdb_ips
        pipeline_run_id: optional UUID for tracing

    Returns:
        dict ready for Elasticsearch indexing
    """
    import datetime
    
    enrich_score = score_enrichment(
        vt_ip_results=enrichment.get("vt_ips", []),
        vt_url_results=enrichment.get("vt_urls", []),
        urlscan_results=enrichment.get("urlscan_urls", []),
        abuseipdb_results=enrichment.get("abuseipdb_ips", []),
    )

    verdict_result = compute_verdict(
        header_score=header_analysis.get("score", 0.0),
        enrichment_score=enrich_score,
        header_flags=header_analysis.get("flags", []),
    )

    # Defang URLs for safe storage
    urls_defanged = []
    for url in parsed_email.get("urls", []):
        defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
        urls_defanged.append({"original": url, "defanged": defanged})

    return {
        "message_id": parsed_email.get("message_id", ""),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "subject": parsed_email.get("subject", ""),
        "sender": parsed_email.get("sender", ""),
        "sender_domain": parsed_email.get("sender_domain", ""),
        "recipients": parsed_email.get("recipients", []),
        "sending_ips": parsed_email.get("sending_ips", []),
        "urls": urls_defanged,
        "headers": {
            "reply_to": parsed_email.get("reply_to"),
            "sender_domain": parsed_email.get("sender_domain"),
        },
        "header_analysis": {
            "score": header_analysis.get("score", 0.0),
            "flags": header_analysis.get("flags", []),
            "reply_to_mismatch": header_analysis.get("reply_to_mismatch", False),
            "free_sender_domain": header_analysis.get("free_sender_domain", False),
            "suspicious_subject": header_analysis.get("suspicious_subject", False),
        },
        "enrichment": {
            "vt_ips": enrichment.get("vt_ips", []),
            "vt_urls": enrichment.get("vt_urls", []),
            "urlscan_urls": enrichment.get("urlscan_urls", []),
            "abuseipdb_ips": enrichment.get("abuseipdb_ips", []),
        },
        "verdict": verdict_result["verdict"],
        "score": verdict_result["score"],
        "tines_processed": False,
        "resolved": False,
        "pipeline_run_id": pipeline_run_id,
    }
