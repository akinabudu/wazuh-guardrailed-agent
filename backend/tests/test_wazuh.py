import os
import unittest
from unittest.mock import MagicMock, patch

os.environ.update({
    "WAZUH_INDEXER_URL": "https://indexer.invalid",
    "WAZUH_URL": "https://manager.invalid",
    "INDEXER_USER": "indexer-user",
    "INDEXER_PASSWORD": "test-indexer-password",
    "WAZUH_API_USER": "api-user",
    "WAZUH_API_PASSWORD": "test-api-password",
})

from wazuh import ActiveResponseFailed, WazuhClient


class WazuhClientTests(unittest.TestCase):
    @patch("wazuh.httpx.Client")
    def test_query_events_tolerates_an_empty_index(self, client_class):
        response = MagicMock()
        response.json.return_value = {"hits": {"hits": []}}
        client_class.return_value.post.return_value = response

        events = WazuhClient().query_events({"query": {"match_all": {}}})

        self.assertEqual(events, [])
        _, kwargs = client_class.return_value.post.call_args
        self.assertEqual(kwargs["params"]["allow_no_indices"], "true")
        self.assertEqual(kwargs["params"]["ignore_unavailable"], "true")

    @patch("wazuh.httpx.Client")
    def test_query_events_preserves_document_ids(self, client_class):
        response = MagicMock()
        response.json.return_value = {
            "hits": {
                "hits": [
                    {"_id": "event-1", "_source": {"agent": "000", "id": "old"}}
                ]
            }
        }
        client_class.return_value.post.return_value = response

        events = WazuhClient().query_events({"query": {"match_all": {}}})

        self.assertEqual(events, [{"agent": "000", "evidence_id": "event-1"}])

    @patch("wazuh.httpx.Client")
    def test_active_response_uses_the_analyst_token(self, client_class):
        action_response = MagicMock()
        sent = {"data": {"affected_items": ["001"], "total_affected_items": 1,
                         "total_failed_items": 0, "failed_items": []}}
        action_response.json.return_value = sent
        client_class.return_value.put.return_value = action_response

        result = WazuhClient().active_response(
            "block_ip", "192.0.2.10", "001", "analyst-jwt"
        )

        self.assertEqual(result, sent)
        _, action_kwargs = client_class.return_value.put.call_args
        self.assertEqual(
            action_kwargs["headers"], {"Authorization": "Bearer analyst-jwt"}
        )
        client_class.return_value.post.assert_not_called()
        self.assertEqual(action_kwargs["json"]["command"], "!firewall-drop")

    @patch("wazuh.httpx.Client")
    def test_active_response_raises_when_the_agent_did_not_run_it(self, client_class):
        action_response = MagicMock()
        action_response.json.return_value = {"data": {
            "affected_items": [], "total_affected_items": 0, "total_failed_items": 1,
            "failed_items": [{"id": ["001"], "error": {"code": 1652}}]}}
        client_class.return_value.put.return_value = action_response

        with self.assertRaises(ActiveResponseFailed):
            WazuhClient().active_response("block_ip", "192.0.2.10", "001", "analyst-jwt")

    @patch("wazuh.httpx.Client")
    def test_connection_check_authenticates_both_services(self, client_class):
        auth_response = MagicMock(text="test-jwt")
        client_class.return_value.post.return_value = auth_response

        WazuhClient().check_connections()

        client_class.return_value.get.assert_any_call(
            "https://indexer.invalid",
            auth=("indexer-user", "test-indexer-password"),
        )
        client_class.return_value.get.assert_any_call(
            "https://manager.invalid",
            headers={"Authorization": "Bearer test-jwt"},
        )


if __name__ == "__main__":
    unittest.main()
