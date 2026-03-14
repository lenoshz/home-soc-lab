"""Tests for verdict engine."""
import pytest
from p3_phishing_pipeline.verdict_engine import (
    score_enrichment,
    compute_verdict,
    build_verdict_document,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_CLEAN,
)


class TestScoreEnrichment:
    def test_no_enrichment(self):
        score = score_enrichment()
        assert score == 0.0

    def test_vt_ip_malicious(self):
        score = score_enrichment(vt_ip_results=[{"malicious": 5}])
        assert score > 0

    def test_vt_url_malicious(self):
        score = score_enrichment(vt_url_results=[{"malicious": 10, "suspicious": 2}])
        assert score > 0.3

    def test_abuseipdb_high_score(self):
        score = score_enrichment(abuseipdb_results=[{"abuse_score": 90}])
        assert score == 0.3

    def test_abuseipdb_medium_score(self):
        score = score_enrichment(abuseipdb_results=[{"abuse_score": 50}])
        assert score == 0.15

    def test_combined_score_capped_at_1(self):
        score = score_enrichment(
            vt_ip_results=[{"malicious": 100}],
            vt_url_results=[{"malicious": 100}],
            abuseipdb_results=[{"abuse_score": 100}],
        )
        assert score <= 1.0

    def test_urlscan_malicious(self):
        score = score_enrichment(urlscan_results=[{"malicious": True}])
        assert score == 0.3


class TestComputeVerdict:
    def test_clean_verdict(self):
        result = compute_verdict(header_score=0.1, enrichment_score=0.0)
        assert result["verdict"] == VERDICT_CLEAN
        assert result["score"] < 0.4

    def test_suspicious_verdict(self):
        result = compute_verdict(header_score=0.5, enrichment_score=0.5)
        assert result["verdict"] in (VERDICT_SUSPICIOUS, VERDICT_MALICIOUS)

    def test_malicious_verdict(self):
        result = compute_verdict(header_score=1.0, enrichment_score=1.0)
        assert result["verdict"] == VERDICT_MALICIOUS
        assert result["score"] >= 0.7

    def test_returns_required_keys(self):
        result = compute_verdict(header_score=0.0, enrichment_score=0.0)
        assert "verdict" in result
        assert "score" in result
        assert "header_score" in result
        assert "enrichment_score" in result
        assert "header_flags" in result

    def test_score_is_rounded(self):
        result = compute_verdict(0.333333, 0.666666)
        assert isinstance(result["score"], float)


class TestBuildVerdictDocument:
    @pytest.fixture
    def sample_parsed_email(self):
        return {
            "message_id": "test123@evil.com",
            "subject": "Phishing test",
            "sender": "attacker@evil.com",
            "sender_domain": "evil.com",
            "recipients": ["victim@example.com"],
            "sending_ips": ["203.0.113.42"],
            "reply_to": "trap@malicious.org",
            "date": "Mon, 01 Jan 2024 10:00:00 +0000",
            "headers": {},
            "body_text": "Click: http://evil.com/phish",
            "body_html": "",
            "attachments": [],
            "urls": ["http://evil.com/phish"],
        }

    @pytest.fixture
    def sample_header_analysis(self):
        return {
            "score": 0.5,
            "flags": ["reply_to_domain_mismatch", "suspicious_subject_keyword"],
            "reply_to_mismatch": True,
            "free_sender_domain": False,
            "suspicious_subject": True,
        }

    @pytest.fixture
    def sample_enrichment(self):
        return {
            "vt_ips": [{"ip": "203.0.113.42", "malicious": 5}],
            "vt_urls": [{"url": "http://evil.com/phish", "malicious": 10}],
            "urlscan_urls": [],
            "abuseipdb_ips": [{"ip": "203.0.113.42", "abuse_score": 80}],
        }

    def test_build_returns_required_fields(self, sample_parsed_email, sample_header_analysis, sample_enrichment):
        doc = build_verdict_document(sample_parsed_email, sample_header_analysis, sample_enrichment)
        required = [
            "message_id", "timestamp", "subject", "sender", "sender_domain",
            "recipients", "sending_ips", "urls", "headers", "header_analysis",
            "enrichment", "verdict", "score", "tines_processed", "resolved",
        ]
        for key in required:
            assert key in doc, f"Missing key: {key}"

    def test_tines_processed_default_false(self, sample_parsed_email, sample_header_analysis, sample_enrichment):
        doc = build_verdict_document(sample_parsed_email, sample_header_analysis, sample_enrichment)
        assert doc["tines_processed"] is False
        assert doc["resolved"] is False

    def test_urls_are_defanged(self, sample_parsed_email, sample_header_analysis, sample_enrichment):
        doc = build_verdict_document(sample_parsed_email, sample_header_analysis, sample_enrichment)
        assert len(doc["urls"]) == 1
        url_obj = doc["urls"][0]
        assert "defanged" in url_obj
        assert "hxxp" in url_obj["defanged"]

    def test_pipeline_run_id_stored(self, sample_parsed_email, sample_header_analysis, sample_enrichment):
        doc = build_verdict_document(
            sample_parsed_email, sample_header_analysis, sample_enrichment,
            pipeline_run_id="test-run-id"
        )
        assert doc["pipeline_run_id"] == "test-run-id"

    def test_high_enrichment_score_leads_to_suspicious_or_malicious(
        self, sample_parsed_email, sample_header_analysis, sample_enrichment
    ):
        doc = build_verdict_document(sample_parsed_email, sample_header_analysis, sample_enrichment)
        assert doc["verdict"] in ("suspicious", "malicious")
