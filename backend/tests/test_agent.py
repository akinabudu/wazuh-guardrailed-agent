import os
import unittest
from unittest.mock import patch

os.environ.update({
    "DATABASE_URL": "postgresql://test:test@database.invalid/test",
    "WAZUH_INDEXER_URL": "https://indexer.invalid",
    "WAZUH_URL": "https://manager.invalid",
    "INDEXER_USER": "indexer-user",
    "INDEXER_PASSWORD": "test-indexer-password",
    "WAZUH_API_USER": "api-user",
    "WAZUH_API_PASSWORD": "test-api-password",
})

import agent


class ExecutionAuthorizationTests(unittest.TestCase):
    def setUp(self):
        agent.revoke_execution("thread-test")

    def tearDown(self):
        agent.revoke_execution("thread-test")

    @staticmethod
    def state():
        return {
            "thread_id": "thread-test",
            "alert": {"agent_id": "001"},
            "decision": "approved",
            "proposal_id": 7,
            "proposal": {"action": "block_ip", "target": "192.0.2.10"},
        }

    def test_execution_uses_scoped_token_and_target_agent(self):
        agent.authorize_execution("thread-test", "analyst-jwt")
        with patch.object(
            agent.wazuh, "active_response", return_value={"status": "ok"}
        ) as active_response, patch.object(agent.db, "audit"), patch.object(
            agent.db, "set_status"
        ):
            result = agent.execute(self.state())

        self.assertEqual(result["outcome"], {"status": "ok"})
        active_response.assert_called_once_with(
            "block_ip", "192.0.2.10", "001", "analyst-jwt"
        )

    def test_execution_fails_without_a_scoped_token(self):
        with patch.object(agent.wazuh, "active_response") as active_response:
            with self.assertRaises(PermissionError):
                agent.execute(self.state())

        active_response.assert_not_called()


if __name__ == "__main__":
    unittest.main()
