"""VirusTotal enrichment module."""
import time
import requests
from typing import Optional


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, session: requests.Session = None):
        self.api_key = api_key
        self._session = session or requests.Session()
        self._session.headers.update({"x-apikey": api_key})

    def _get(self, path: str, retries: int = 3) -> dict:
        url = f"{self.BASE_URL}{path}"
        for attempt in range(retries):
            resp = self._session.get(url)
            if resp.status_code == 429:
                time.sleep(2 ** attempt)
                continue
            if resp.status_code == 404:
                return {"not_found": True}
            resp.raise_for_status()
            return resp.json()
        return {"error": "rate_limited"}

    def lookup_ip(self, ip: str) -> dict:
        """Look up an IP address."""
        data = self._get(f"/ip_addresses/{ip}")
        if data.get("not_found"):
            return {"ip": ip, "malicious": 0, "suspicious": 0, "harmless": 0, "not_found": True}
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "country": attrs.get("country", ""),
            "as_owner": attrs.get("as_owner", ""),
        }

    def lookup_url(self, url: str) -> dict:
        """Look up a URL."""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        data = self._get(f"/urls/{url_id}")
        if data.get("not_found"):
            return {"url": url, "malicious": 0, "suspicious": 0, "harmless": 0, "not_found": True}
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }


def enrich_ip(ip: str, api_key: str, session: requests.Session = None) -> dict:
    client = VirusTotalClient(api_key, session)
    return client.lookup_ip(ip)


def enrich_url(url: str, api_key: str, session: requests.Session = None) -> dict:
    client = VirusTotalClient(api_key, session)
    return client.lookup_url(url)
