"""Tests for connector payload and Tines story structure."""
import json
import pytest
from pathlib import Path

STORIES_DIR = Path(__file__).parent.parent / "stories"
CONNECTOR_MODULE_PATH = Path(__file__).parent.parent / "connector" / "register_connector.py"


class TestWebhookPayloadTemplate:
    """Verify the exact webhook payload template from shared contract Section 2.4."""

    def _get_template(self):
        """Import WEBHOOK_PAYLOAD_TEMPLATE from register_connector."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "register_connector", str(CONNECTOR_MODULE_PATH)
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.WEBHOOK_PAYLOAD_TEMPLATE

    def test_template_has_required_fields(self):
        template = self._get_template()
        required_fields = [
            "alert_id", "rule_name", "source_ip", "host_name",
            "severity", "timestamp", "kibana_alert_url",
        ]
        for field in required_fields:
            assert field in template, f"Missing field in webhook payload: {field}"

    def test_template_alert_id_uses_alert_id(self):
        template = self._get_template()
        assert "alert.id" in template["alert_id"]

    def test_template_source_ip_field(self):
        template = self._get_template()
        assert "source_ip" in template["source_ip"]

    def test_template_host_name_field(self):
        template = self._get_template()
        assert "host_name" in template["host_name"]


class TestPhishingTriageStory:
    """Verify structure of phishing_triage.json Tines story."""

    @pytest.fixture
    def story(self):
        path = STORIES_DIR / "phishing_triage.json"
        return json.loads(path.read_text())

    def test_schema_version_4(self, story):
        assert story["schema_version"] == 4

    def test_has_name(self, story):
        assert story["name"]

    def test_has_agents(self, story):
        assert len(story["agents"]) > 0

    def test_has_connections(self, story):
        assert len(story["connections"]) > 0

    def test_has_entry_agent_guid(self, story):
        assert "entry_agent_guid" in story

    def test_entry_agent_exists_in_agents(self, story):
        entry_guid = story["entry_agent_guid"]
        agent_guids = [a["guid"] for a in story["agents"]]
        assert entry_guid in agent_guids

    def test_all_agents_have_required_fields(self, story):
        for agent in story["agents"]:
            assert "guid" in agent, f"Agent missing guid: {agent}"
            assert "name" in agent, f"Agent missing name: {agent}"
            assert "type" in agent, f"Agent missing type: {agent}"

    def test_vt_enrichment_uses_source_ip_not_host_name(self, story):
        """VT IP enrichment should reference source_ip (sending_ips), not host_name."""
        vt_agents = [a for a in story["agents"] if "virustotal" in a.get("name", "").lower() or "vt" in a.get("guid", "").lower()]
        assert len(vt_agents) > 0, "No VT enrichment agent found"
        vt_agent = vt_agents[0]
        url = vt_agent.get("options", {}).get("url", "")
        # Should NOT use host_name for IP lookup - should use sending_ips
        assert "host_name" not in url, f"VT IP enrichment incorrectly uses host_name: {url}"
        assert "sending_ips" in url, f"VT IP enrichment should use sending_ips field: {url}"

    def test_check_allowlist_action_present(self, story):
        guids = [a["guid"] for a in story["agents"]]
        assert any("allowlist" in g.lower() for g in guids)

    def test_create_case_action_present(self, story):
        agent_names = [a["name"].lower() for a in story["agents"]]
        assert any("case" in name for name in agent_names)


class TestAlertResponseStory:
    """Verify structure of alert_response.json Tines story."""

    @pytest.fixture
    def story(self):
        path = STORIES_DIR / "alert_response.json"
        return json.loads(path.read_text())

    def test_schema_version_4(self, story):
        assert story["schema_version"] == 4

    def test_has_name(self, story):
        assert story["name"]

    def test_has_agents(self, story):
        assert len(story["agents"]) > 0

    def test_has_connections(self, story):
        assert len(story["connections"]) > 0

    def test_entry_agent_exists_in_agents(self, story):
        entry_guid = story["entry_agent_guid"]
        agent_guids = [a["guid"] for a in story["agents"]]
        assert entry_guid in agent_guids

    def test_all_agents_have_required_fields(self, story):
        for agent in story["agents"]:
            assert "guid" in agent
            assert "name" in agent
            assert "type" in agent

    def test_isolate_host_action_present(self, story):
        names = [a["name"].lower() for a in story["agents"]]
        assert any("isolate" in name for name in names)

    def test_audit_log_action_present(self, story):
        names = [a["name"].lower() for a in story["agents"]]
        assert any("audit" in name for name in names)

    def test_allowlist_check_present(self, story):
        guids = [a["guid"] for a in story["agents"]]
        assert any("allowlist" in g.lower() for g in guids)
