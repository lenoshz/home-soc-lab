"""Tests for EML parser."""
import pytest
from p3_phishing_pipeline.eml_parser import parse_eml, _extract_urls, _sender_domain

PHISHING_EML = b"""From: attacker@evil.com
To: victim@example.com
Subject: Urgent: Click now!
Date: Mon, 01 Jan 2024 10:00:00 +0000
Message-ID: <test123@evil.com>
Reply-To: trap@malicious.org
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Received: from evil.com (203.0.113.99) by mx.example.com

Click here: http://evil.com/phish?id=123
Also: https://malicious.org/steal
"""

CLEAN_EML = b"""From: sender@example.com
To: recipient@example.com
Subject: Hello
Date: Mon, 01 Jan 2024 09:00:00 +0000
Message-ID: <hello@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Hello, this is a clean email.
"""

MULTIPART_EML = b"""From: sender@example.com
To: recipient@example.com
Subject: Multipart email
Date: Mon, 01 Jan 2024 09:00:00 +0000
Message-ID: <multi@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset=UTF-8

Plain text body.

--boundary123
Content-Type: text/html; charset=UTF-8

<html><body>HTML body with <a href="https://example.com">link</a></body></html>

--boundary123
Content-Type: application/pdf
Content-Disposition: attachment; filename="document.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQ=
--boundary123--
"""


class TestParseEml:
    def test_parse_bytes(self):
        result = parse_eml(PHISHING_EML)
        assert result["sender"] == "attacker@evil.com"
        assert result["sender_domain"] == "evil.com"
        assert "victim@example.com" in result["recipients"]
        assert result["subject"] == "Urgent: Click now!"
        assert result["message_id"] == "test123@evil.com"
        assert result["reply_to"] is not None

    def test_parse_urls(self):
        result = parse_eml(PHISHING_EML)
        assert any("evil.com/phish" in u for u in result["urls"])
        assert any("malicious.org/steal" in u for u in result["urls"])

    def test_parse_clean_email(self):
        result = parse_eml(CLEAN_EML)
        assert result["sender_domain"] == "example.com"
        assert result["urls"] == []

    def test_parse_multipart(self):
        result = parse_eml(MULTIPART_EML)
        assert result["body_text"].strip() == "Plain text body."
        assert "<html>" in result["body_html"]
        assert len(result["attachments"]) == 1
        assert result["attachments"][0]["filename"] == "document.pdf"
        assert any("example.com" in u for u in result["urls"])

    def test_returns_all_required_fields(self):
        result = parse_eml(CLEAN_EML)
        required_keys = [
            "message_id", "subject", "sender", "sender_domain", "recipients",
            "reply_to", "date", "headers", "body_text", "body_html",
            "attachments", "urls", "sending_ips",
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

    def test_generates_uuid_when_no_message_id(self):
        eml = b"""From: x@y.com
To: a@b.com
Subject: test
Date: Mon, 01 Jan 2024 00:00:00 +0000

body
"""
        result = parse_eml(eml)
        assert result["message_id"]  # Should have some ID

    def test_extract_ips_from_received(self):
        result = parse_eml(PHISHING_EML)
        assert "203.0.113.99" in result["sending_ips"]

    def test_sender_domain_extraction(self):
        assert _sender_domain("John Doe <john@example.com>") == "example.com"
        assert _sender_domain("plain@domain.org") == "domain.org"
        assert _sender_domain("") == ""


class TestExtractUrls:
    def test_extracts_http_urls(self):
        text = "Visit http://example.com/page and https://secure.com"
        urls = _extract_urls(text)
        assert "http://example.com/page" in urls
        assert "https://secure.com" in urls

    def test_no_duplicates(self):
        text = "http://example.com http://example.com"
        urls = _extract_urls(text)
        assert len(urls) == 1

    def test_empty_text(self):
        assert _extract_urls("") == []
        assert _extract_urls(None) == []
