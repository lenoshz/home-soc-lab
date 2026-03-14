"""Elastic API client for home-soc-lab."""
import urllib3
import requests
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import TransportError


class ElasticAPIError(Exception):
    """Raised when an Elastic/Kibana API call returns a non-2xx response."""

    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class ElasticClient:
    """Unified client for Elasticsearch and Kibana operations."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        kibana_host: str = None,
        verify_tls: bool = False,
        ca_cert: str = None,
    ):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = ca_cert if ca_cert else verify_tls

        # Derive Kibana host if not provided
        if kibana_host:
            self.kibana_host = kibana_host.rstrip("/")
        else:
            self.kibana_host = self._derive_kibana_host(self.host)

        if not verify_tls and not ca_cert:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Elasticsearch client
        es_kwargs = {
            "hosts": [self.host],
            "basic_auth": (username, password),
            "verify_certs": bool(self.verify_tls),
        }
        if ca_cert:
            es_kwargs["ca_certs"] = ca_cert
        self._es = Elasticsearch(**es_kwargs)

        # Requests session for Kibana
        self._session = requests.Session()
        self._session.auth = (username, password)
        self._session.verify = self.verify_tls
        self._session.headers.update(self._kibana_headers)

    @staticmethod
    def _derive_kibana_host(es_host: str) -> str:
        """Derive Kibana host from Elasticsearch host by replacing port."""
        import re
        # Replace port 9200 with 5601, handle URLs without explicit ports
        result = re.sub(r":9200(/.*)?$", ":5601", es_host)
        if result == es_host:
            # No port substitution; try to replace scheme and append kibana port
            # e.g. https://myhost → https://myhost:5601
            result = re.sub(r"(https?://[^:/]+)$", r"\1:5601", es_host)
        return result

    @property
    def _kibana_headers(self) -> dict:
        return {"kbn-xsrf": "true", "Content-Type": "application/json"}

    def index_document(self, index: str, document: dict, doc_id: str = None) -> dict:
        """Index a document into Elasticsearch."""
        kwargs = {"index": index, "document": document}
        if doc_id:
            kwargs["id"] = doc_id
        response = self._es.index(**kwargs)
        return dict(response)

    def search(self, index: str, query: dict) -> list:
        """Search Elasticsearch and return list of hits."""
        response = self._es.search(index=index, body=query)
        return response["hits"]["hits"]

    def create_index(self, index: str, mapping: dict = None) -> dict:
        """Create an index if it doesn't already exist."""
        body = mapping or {}
        try:
            response = self._es.indices.create(index=index, body=body)
            return dict(response)
        except Exception as exc:
            # Ignore index already exists (400 resource_already_exists_exception)
            if "resource_already_exists_exception" in str(exc).lower():
                return {"acknowledged": True, "index": index, "already_exists": True}
            raise

    def _kibana_post(self, path: str, payload: dict) -> dict:
        """POST to a Kibana API endpoint; raises ElasticAPIError on non-2xx."""
        url = f"{self.kibana_host}{path}"
        resp = self._session.post(url, json=payload)
        if not resp.ok:
            raise ElasticAPIError(
                f"Kibana API error {resp.status_code}: {resp.text}",
                status_code=resp.status_code,
            )
        return resp.json() if resp.text else {}

    def isolate_host(self, hostname: str) -> dict:
        """Isolate a host via Kibana Endpoint API."""
        return self._kibana_post(
            "/api/endpoint/action/isolate",
            {"endpoint_ids": [hostname]},
        )

    def unisolate_host(self, hostname: str) -> dict:
        """Un-isolate a host via Kibana Endpoint API."""
        return self._kibana_post(
            "/api/endpoint/action/unisolate",
            {"endpoint_ids": [hostname]},
        )
