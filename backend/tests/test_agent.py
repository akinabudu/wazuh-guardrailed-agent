import os
import unittest
from unittest.mock import MagicMock, patch

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


class HuntQueryTests(unittest.TestCase):
    def test_query_returns_newest_events_for_the_agent(self):
        query = agent.hunt_query({"agent_id": "001"})

        self.assertEqual(
            query["query"]["bool"]["filter"], [{"match": {"agent.id": "001"}}]
        )
        self.assertEqual(query["sort"], [{"timestamp": {"order": "desc"}}])
        self.assertEqual(query["size"], 20)

    def test_query_is_bounded_by_since(self):
        query = agent.hunt_query({"agent_id": "001", "since": "2026-10-22T10:00:00Z"})

        self.assertIn(
            {"range": {"timestamp": {"gte": "2026-10-22T10:00:00Z"}}},
            query["query"]["bool"]["filter"],
        )


class ContextBudgetTests(unittest.TestCase):
    def test_context_keeps_whole_events_within_budget(self):
        events = [{"evidence_id": f"id-{i}", "full_log": "x" * 100} for i in range(10)]

        kept = agent.context_within(events, 450)

        self.assertEqual([e["evidence_id"] for e in kept], ["id-0", "id-1", "id-2"])
        self.assertLessEqual(len(agent.json.dumps(kept)), 450)

    def test_context_keeps_one_event_even_if_oversized(self):
        events = [{"evidence_id": "big", "full_log": "x" * 1000}]

        self.assertEqual(agent.context_within(events, 400), events)


class OllamaChatTests(unittest.TestCase):
    def test_chat_sends_fixed_sampling_and_returns_timings(self):
        response = MagicMock()
        response.json.return_value = {
            "message": {"content": "{}"},
            "prompt_eval_count": 900,
            "eval_count": 80,
            "eval_duration": 4_000_000_000,
        }
        with patch.dict(os.environ, {"OLLAMA_TEMPERATURE": "0", "OLLAMA_SEED": "7"}), \
                patch.object(agent.httpx, "post", return_value=response) as post:
            content, inference = agent._ollama_chat("system", "user")

        self.assertEqual(content, "{}")
        self.assertEqual(
            post.call_args.kwargs["json"]["options"], {"temperature": 0.0, "seed": 7}
        )
        self.assertEqual(inference["prompt_eval_count"], 900)
        self.assertEqual(inference["eval_count"], 80)
        self.assertIn("wall_s", inference)


if __name__ == "__main__":
    unittest.main()
