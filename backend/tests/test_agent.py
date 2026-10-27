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

    def test_think_is_sent_only_when_configured(self):
        response = MagicMock()
        response.json.return_value = {"message": {"content": "{}"}}
        with patch.dict(os.environ, {"OLLAMA_THINK": ""}), \
                patch.object(agent.httpx, "post", return_value=response) as post:
            agent._ollama_chat("system", "user")
        self.assertNotIn("think", post.call_args.kwargs["json"])

        with patch.dict(os.environ, {"OLLAMA_THINK": "false"}), \
                patch.object(agent.httpx, "post", return_value=response) as post:
            agent._ollama_chat("system", "user")
        self.assertIs(post.call_args.kwargs["json"]["think"], False)


def _bedrock_response(stop_reason="end_turn", text="{}", served="anthropic.claude-opus-5-5",
                      iterations=(), category=None):
    block = MagicMock(type="text", text=text)
    response = MagicMock(stop_reason=stop_reason, model=served,
                         content=[] if stop_reason == "refusal" else [block])
    response.usage.input_tokens = 2400
    response.usage.output_tokens = 300
    response.usage.iterations = [MagicMock(type=t) for t in iterations]
    response.stop_details = MagicMock(category=category) if stop_reason == "refusal" else None
    return response


class BedrockChatTests(unittest.TestCase):
    def call(self, response, env=None):
        client = MagicMock()
        client.beta.messages.create.return_value = response
        with patch.dict(os.environ, env or {}), \
                patch.object(agent, "_bedrock", return_value=client):
            content, inference = agent._bedrock_chat("system", "user", {"type": "object"})
        return client.beta.messages.create.call_args.kwargs, content, inference

    def test_requests_a_closed_json_schema_and_records_tokens(self):
        kwargs, content, inference = self.call(_bedrock_response())

        fmt = kwargs["output_config"]["format"]
        self.assertEqual(fmt["type"], "json_schema")
        self.assertIs(fmt["schema"]["additionalProperties"], False)
        self.assertNotIn("effort", kwargs["output_config"])
        self.assertEqual(content, "{}")
        self.assertEqual(inference["prompt_eval_count"], 2400)
        self.assertEqual(inference["eval_count"], 300)
        self.assertFalse(inference["fallback_ran"])

    def test_effort_is_sent_only_when_configured(self):
        kwargs, _, inference = self.call(_bedrock_response(), {"BEDROCK_EFFORT": "low"})

        self.assertEqual(kwargs["output_config"]["effort"], "low")
        self.assertEqual(inference["effort"], "low")

    def test_records_a_fallback_and_the_model_that_served(self):
        _, content, inference = self.call(_bedrock_response(
            served="anthropic.claude-opus-4-8", iterations=("message", "fallback_message")))

        self.assertEqual(content, "{}")
        self.assertTrue(inference["fallback_ran"])
        self.assertEqual(inference["served_by"], "anthropic.claude-opus-4-8")

    def test_messages_api_models_send_no_version_override(self):
        kwargs, _, _ = self.call(_bedrock_response(), {"BEDROCK_MODEL": "anthropic.claude-opus-5-5"})

        self.assertIsNone(kwargs["extra_body"])

    def test_invoke_model_profiles_pin_the_bedrock_api_version(self):
        kwargs, _, _ = self.call(
            _bedrock_response(),
            {"BEDROCK_MODEL": "us.anthropic.claude-sonnet-4-5-20250929-v1:0"})

        self.assertEqual(kwargs["extra_body"], {"anthropic_version": "bedrock-2023-05-31"})

    def test_defaults_to_the_evaluated_bedrock_model(self):
        with patch.dict(os.environ):
            os.environ.pop("LLM_PROVIDER", None)
            os.environ.pop("BEDROCK_MODEL", None)
            self.assertEqual(agent._llm_provider(), "bedrock")
            kwargs, _, _ = self.call(_bedrock_response())
        self.assertEqual(kwargs["model"], "us.anthropic.claude-opus-4-6-v1")

    def test_legacy_detection(self):
        self.assertTrue(agent._bedrock_legacy("us.anthropic.claude-sonnet-4-5-20250929-v1:0"))
        self.assertTrue(agent._bedrock_legacy("global.anthropic.claude-sonnet-4-5-20250929-v1:0"))
        self.assertFalse(agent._bedrock_legacy("anthropic.claude-opus-5-5"))

    def test_refusal_returns_no_content_and_its_category(self):
        _, content, inference = self.call(
            _bedrock_response(stop_reason="refusal", category="cyber"))

        self.assertEqual(content, "")
        self.assertEqual(inference["stop_reason"], "refusal")
        self.assertEqual(inference["refusal_category"], "cyber")


if __name__ == "__main__":
    unittest.main()
