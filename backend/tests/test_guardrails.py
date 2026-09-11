import unittest

from guardrails import ALLOWED_ACTIONS, GuardrailEngine, Tier, ollama_action_schema


class OllamaSchemaTests(unittest.TestCase):
    def test_schema_uses_phi4_compatible_grammar(self):
        schema = ollama_action_schema()

        self.assertEqual(
            schema["properties"]["action"]["enum"], list(ALLOWED_ACTIONS)
        )
        self.assertEqual(
            set(schema["required"]), set(schema["properties"])
        )
        self.assertNotIn("anyOf", str(schema))


class TargetValidationTests(unittest.TestCase):
    class FakeWazuh:
        def verify_events(self, event_ids):
            return bool(event_ids)

    def setUp(self):
        self.engine = GuardrailEngine(self.FakeWazuh())

    def test_block_ip_rejects_a_hostname(self):
        result = self.engine.run({
            "action": "block_ip",
            "target": "example.invalid",
            "reason": "test",
            "evidence": ["event-1"],
        })

        self.assertFalse(result.passed)
        self.assertEqual(result.tier, Tier.BLOCKED)
        self.assertEqual(result.reason, "block_ip target is not an IP address")

    def test_kill_process_requires_a_positive_process_id(self):
        result = self.engine.run({
            "action": "kill_process",
            "target": "not-a-pid",
            "reason": "test",
            "evidence": ["event-1"],
        })

        self.assertFalse(result.passed)
        self.assertEqual(result.tier, Tier.BLOCKED)

    def test_valid_ip_reaches_the_auto_lane(self):
        result = self.engine.run({
            "action": "block_ip",
            "target": "192.0.2.10",
            "reason": "test",
            "evidence": ["event-1"],
        })

        self.assertTrue(result.passed)
        self.assertEqual(result.tier, Tier.AUTO)


if __name__ == "__main__":
    unittest.main()
