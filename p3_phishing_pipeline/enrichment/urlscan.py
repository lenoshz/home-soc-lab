"""urlscan.io enrichment module."""
import time
import requests
from typing import Optional


class UrlscanClient:
    BASE_URL = "https://urlscan.io/api/v1"

    def __init__(self, api_key: str, session: requests.Session = None):
        self.api_key = api_key
        self._session = session or requests.Session()
        self._session.headers.update({"API-Key": api_key})

    def search(self, query: str) -> dict:
        """Search urlscan for a query (e.g. domain, IP, URL)."""
        resp = self._session.get(f"{self.BASE_URL}/search/", params={"q": query, "size": 5})
        if resp.status_code == 404:
            return {"results": [], "total": 0}
        resp.raise_for_status()
        return resp.json()

    def submit(self, url: str, visibility: str = "private") -> dict:
        """Submit URL for scanning."""
        resp = self._session.post(
            f"{self.BASE_URL}/scan/",
            json={"url": url, "visibility": visibility},
        )
        resp.raise_for_status()
        return resp.json()

    def lookup_url(self, url: str) -> dict:
        """Search for existing scans of a URL."""
        data = self.search(f'page.url:"{url}"')
        results = data.get("results", [])
        if not results:
            return {"url": url, "scan_count": 0, "malicious": False}
        latest = results[0]
        verdicts = latest.get("verdicts", {}).get("overall", {})
        return {
            "url": url,
            "scan_count": len(results),
            "malicious": verdicts.get("malicious", False),
            "score": verdicts.get("score", 0),
            "uuid": latest.get("_id", ""),
        }


def enrich_url(url: str, api_key: str, session: requests.Session = None) -> dict:
    client = UrlscanClient(api_key, session)
    return client.lookup_url(url)
