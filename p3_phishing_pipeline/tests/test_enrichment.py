"""Tests for enrichment modules."""
import pytest
import responses as resp_lib
from p3_phishing_pipeline.enrichment.virustotal import VirusTotalClient, enrich_ip, enrich_url
from p3_phishing_pipeline.enrichment.urlscan import UrlscanClient
from p3_phishing_pipeline.enrichment.abuseipdb import AbuseIPDBClient
from p3_phishing_pipeline.enrichment.ip_extractor import extract_ips, is_private


VT_BASE = "https://www.virustotal.com/api/v3"
URLSCAN_BASE = "https://urlscan.io/api/v1"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


class TestIpExtractor:
    def test_extract_public_ips(self):
        text = "Received from 203.0.113.42 and 8.8.8.8"
        ips = extract_ips(text)
        assert "203.0.113.42" in ips
        assert "8.8.8.8" in ips

    def test_excludes_private_ips(self):
        text = "192.168.1.1 10.0.0.1 172.16.0.1 127.0.0.1"
        ips = extract_ips(text)
        assert ips == []

    def test_is_private_loopback(self):
        assert is_private("127.0.0.1")

    def test_is_private_rfc1918(self):
        assert is_private("192.168.0.1")
        assert is_private("10.0.0.1")
        assert is_private("172.16.0.1")

    def test_is_not_private_public(self):
        assert not is_private("8.8.8.8")
        assert not is_private("203.0.113.1")


class TestVirusTotalClient:
    @resp_lib.activate
    def test_lookup_ip_malicious(self):
        resp_lib.add(
            resp_lib.GET,
            f"{VT_BASE}/ip_addresses/203.0.113.1",
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 5,
                            "suspicious": 1,
                            "harmless": 50,
                        },
                        "country": "US",
                        "as_owner": "Test ISP",
                    }
                }
            },
            status=200,
        )
        client = VirusTotalClient("test-key")
        result = client.lookup_ip("203.0.113.1")
        assert result["malicious"] == 5
        assert result["country"] == "US"

    @resp_lib.activate
    def test_lookup_ip_not_found(self):
        resp_lib.add(
            resp_lib.GET,
            f"{VT_BASE}/ip_addresses/1.2.3.4",
            json={},
            status=404,
        )
        client = VirusTotalClient("test-key")
        result = client.lookup_ip("1.2.3.4")
        assert result["not_found"] is True

    @resp_lib.activate
    def test_lookup_url(self):
        import base64
        url = "http://evil.com/phish"
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        resp_lib.add(
            resp_lib.GET,
            f"{VT_BASE}/urls/{url_id}",
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 10,
                            "suspicious": 0,
                            "harmless": 30,
                        }
                    }
                }
            },
            status=200,
        )
        client = VirusTotalClient("test-key")
        result = client.lookup_url(url)
        assert result["malicious"] == 10


class TestUrlscanClient:
    @resp_lib.activate
    def test_lookup_url_found(self):
        resp_lib.add(
            resp_lib.GET,
            f"{URLSCAN_BASE}/search/",
            json={
                "results": [
                    {
                        "_id": "abc123",
                        "verdicts": {
                            "overall": {"malicious": True, "score": 90}
                        }
                    }
                ],
                "total": 1,
            },
            status=200,
        )
        client = UrlscanClient("test-key")
        result = client.lookup_url("http://evil.com")
        assert result["malicious"] is True
        assert result["scan_count"] == 1

    @resp_lib.activate
    def test_lookup_url_not_found(self):
        resp_lib.add(
            resp_lib.GET,
            f"{URLSCAN_BASE}/search/",
            json={"results": [], "total": 0},
            status=200,
        )
        client = UrlscanClient("test-key")
        result = client.lookup_url("http://unknown.com")
        assert result["scan_count"] == 0
        assert result["malicious"] is False


class TestAbuseIPDBClient:
    @resp_lib.activate
    def test_check_ip_high_score(self):
        resp_lib.add(
            resp_lib.GET,
            f"{ABUSEIPDB_BASE}/check",
            json={
                "data": {
                    "abuseConfidenceScore": 95,
                    "totalReports": 42,
                    "countryCode": "CN",
                    "isp": "Bad ISP",
                    "isTor": False,
                    "isWhitelisted": False,
                }
            },
            status=200,
        )
        client = AbuseIPDBClient("test-key")
        result = client.check_ip("1.2.3.4")
        assert result["abuse_score"] == 95
        assert result["total_reports"] == 42

    @resp_lib.activate
    def test_check_ip_clean(self):
        resp_lib.add(
            resp_lib.GET,
            f"{ABUSEIPDB_BASE}/check",
            json={
                "data": {
                    "abuseConfidenceScore": 0,
                    "totalReports": 0,
                    "countryCode": "US",
                    "isp": "Good ISP",
                    "isTor": False,
                    "isWhitelisted": False,
                }
            },
            status=200,
        )
        client = AbuseIPDBClient("test-key")
        result = client.check_ip("8.8.8.8")
        assert result["abuse_score"] == 0
