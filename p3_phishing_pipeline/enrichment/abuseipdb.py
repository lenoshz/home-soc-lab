"""AbuseIPDB enrichment module."""
import requests
from typing import Optional


class AbuseIPDBClient:
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str, session: requests.Session = None):
        self.api_key = api_key
        self._session = session or requests.Session()
        self._session.headers.update({
            "Key": api_key,
            "Accept": "application/json",
        })

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        """Check an IP address."""
        resp = self._session.get(
            f"{self.BASE_URL}/check",
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
        )
        if resp.status_code == 404:
            return {"ip": ip, "abuse_score": 0, "total_reports": 0, "not_found": True}
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted", False),
        }


def enrich_ip(ip: str, api_key: str, session: requests.Session = None) -> dict:
    client = AbuseIPDBClient(api_key, session)
    return client.check_ip(ip)
