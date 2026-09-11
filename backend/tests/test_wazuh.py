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

from wazuh import WazuhClient


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
    def test_active_response_uses_a_manager_token(self, client_class):
        auth_response = MagicMock(text="test-jwt")
        action_response = MagicMock()
        action_response.json.return_value = {"data": "ok"}
        client_class.return_value.post.return_value = auth_response
        client_class.return_value.put.return_value = action_response

        result = WazuhClient().active_response("block_ip", "192.0.2.10", "001")

        self.assertEqual(result, {"data": "ok"})
        _, auth_kwargs = client_class.return_value.post.call_args
        self.assertEqual(auth_kwargs["params"], {"raw": "true"})
        _, action_kwargs = client_class.return_value.put.call_args
        self.assertEqual(
            action_kwargs["headers"], {"Authorization": "Bearer test-jwt"}
        )

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
