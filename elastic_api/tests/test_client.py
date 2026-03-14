"""Tests for elastic_api.client."""
import pytest
import responses as resp_lib
from unittest.mock import MagicMock, patch
from elastic_api.client import ElasticClient, ElasticAPIError


ES_HOST = "https://localhost:9200"
KIBANA_HOST = "https://localhost:5601"
USERNAME = "elastic"
PASSWORD = "changeme"


@pytest.fixture
def mock_es():
    """Patch elasticsearch.Elasticsearch so no real connection is made."""
    with patch("elastic_api.client.Elasticsearch") as mock_cls:
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def client(mock_es):
    return ElasticClient(
        host=ES_HOST,
        username=USERNAME,
        password=PASSWORD,
        kibana_host=KIBANA_HOST,
    )


class TestElasticAPIError:
    def test_has_status_code(self):
        err = ElasticAPIError("test error", status_code=404)
        assert err.status_code == 404
        assert "test error" in str(err)

    def test_default_status_code(self):
        err = ElasticAPIError("test error")
        assert err.status_code == 0

    def test_is_exception(self):
        with pytest.raises(ElasticAPIError):
            raise ElasticAPIError("boom", status_code=500)


class TestElasticClientInit:
    def test_derives_kibana_host_from_es_port(self, mock_es):
        client = ElasticClient(ES_HOST, USERNAME, PASSWORD)
        assert client.kibana_host == "https://localhost:5601"

    def test_uses_explicit_kibana_host(self, mock_es):
        client = ElasticClient(ES_HOST, USERNAME, PASSWORD, kibana_host="https://kibana:5601")
        assert client.kibana_host == "https://kibana:5601"

    def test_strips_trailing_slash(self, mock_es):
        client = ElasticClient("https://localhost:9200/", USERNAME, PASSWORD, kibana_host="https://localhost:5601/")
        assert not client.host.endswith("/")
        assert not client.kibana_host.endswith("/")


class TestDeriveKibanaHost:
    def test_standard_port(self):
        assert ElasticClient._derive_kibana_host("https://localhost:9200") == "https://localhost:5601"

    def test_no_port(self):
        result = ElasticClient._derive_kibana_host("https://myelastic.example.com")
        assert "5601" in result

    def test_already_5601(self):
        result = ElasticClient._derive_kibana_host("https://localhost:5601")
        assert "5601" in result


class TestIsolateHost:
    @resp_lib.activate
    def test_isolate_success(self, client):
        resp_lib.add(
            resp_lib.POST,
            f"{KIBANA_HOST}/api/endpoint/action/isolate",
            json={"action": "isolate", "status": "ok"},
            status=200,
        )
        result = client.isolate_host("host-1")
        assert result["status"] == "ok"
        assert len(resp_lib.calls) == 1
        import json
        body = json.loads(resp_lib.calls[0].request.body)
        assert body["endpoint_ids"] == ["host-1"]

    @resp_lib.activate
    def test_isolate_raises_on_error(self, client):
        resp_lib.add(
            resp_lib.POST,
            f"{KIBANA_HOST}/api/endpoint/action/isolate",
            json={"error": "not found"},
            status=404,
        )
        with pytest.raises(ElasticAPIError) as exc_info:
            client.isolate_host("host-1")
        assert exc_info.value.status_code == 404


class TestUnisolateHost:
    @resp_lib.activate
    def test_unisolate_success(self, client):
        resp_lib.add(
            resp_lib.POST,
            f"{KIBANA_HOST}/api/endpoint/action/unisolate",
            json={"action": "unisolate", "status": "ok"},
            status=200,
        )
        result = client.unisolate_host("host-1")
        assert result["status"] == "ok"

    @resp_lib.activate
    def test_unisolate_raises_on_error(self, client):
        resp_lib.add(
            resp_lib.POST,
            f"{KIBANA_HOST}/api/endpoint/action/unisolate",
            status=500,
            body="Internal Server Error",
        )
        with pytest.raises(ElasticAPIError) as exc_info:
            client.unisolate_host("host-1")
        assert exc_info.value.status_code == 500


class TestIndexDocument:
    def test_index_with_id(self, client, mock_es):
        mock_es.index.return_value = {"result": "created", "_id": "doc-1"}
        result = client.index_document("my-index", {"field": "value"}, doc_id="doc-1")
        mock_es.index.assert_called_once_with(index="my-index", document={"field": "value"}, id="doc-1")
        assert result["result"] == "created"

    def test_index_without_id(self, client, mock_es):
        mock_es.index.return_value = {"result": "created", "_id": "auto"}
        result = client.index_document("my-index", {"field": "value"})
        mock_es.index.assert_called_once_with(index="my-index", document={"field": "value"})

    def test_index_returns_dict(self, client, mock_es):
        mock_es.index.return_value = MagicMock()
        mock_es.index.return_value.__iter__ = MagicMock(return_value=iter([("result", "created")]))
        # Patch dict() to return something predictable
        mock_es.index.return_value = {"result": "created"}
        result = client.index_document("test", {})
        assert isinstance(result, dict)


class TestCreateIndex:
    def test_create_new_index(self, client, mock_es):
        mock_es.indices.create.return_value = {"acknowledged": True, "index": "new-index"}
        result = client.create_index("new-index", {"mappings": {}})
        assert result["acknowledged"] is True

    def test_create_index_already_exists(self, client, mock_es):
        mock_es.indices.create.side_effect = Exception("resource_already_exists_exception")
        result = client.create_index("existing-index")
        assert result["already_exists"] is True

    def test_create_index_raises_other_errors(self, client, mock_es):
        mock_es.indices.create.side_effect = Exception("connection refused")
        with pytest.raises(Exception, match="connection refused"):
            client.create_index("my-index")
