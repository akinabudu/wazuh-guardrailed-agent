import os
import unittest
from unittest.mock import patch

from guardrails import (ALLOWED_ACTIONS, UNRESOLVED, GuardrailEngine, Tier,
                        ollama_action_schema)


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

    def test_valid_ip_requires_a_human(self):
        result = self.engine.run({
            "action": "block_ip",
            "target": "192.0.2.10",
            "reason": "test",
            "evidence": ["event-1"],
        })

        self.assertTrue(result.passed)
        self.assertEqual(result.tier, Tier.HUMAN)

    def test_enrich_rejects_a_url_target(self):
        result = self.engine.run({
            "action": "enrich",
            "target": "https://exfil.example.net/upload?d=172.31.42.14",
            "reason": "test",
        })

        self.assertFalse(result.passed)
        self.assertEqual(result.reason,
                         "enrich target is not an address, host name or file hash")

    def test_enrich_accepts_hosts_addresses_and_hashes(self):
        for target in ("lab-linux-01", "192.0.2.10", "d41d8cd98f00b204e9800998ecf8427e"):
            with self.subTest(target=target):
                result = self.engine.run(
                    {"action": "enrich", "target": target, "reason": "test"})
                self.assertTrue(result.passed)
                self.assertEqual(result.tier, Tier.AUTO)


class ProtectedAddressTests(unittest.TestCase):
    FakeWazuh = TargetValidationTests.FakeWazuh

    def setUp(self):
        with patch.dict(os.environ, {"PROTECTED_NETWORKS": "172.31.47.63/32,10.9.0.0/16"}):
            self.engine = GuardrailEngine(self.FakeWazuh())

    def proposal(self, action, target):
        return {"action": action, "target": target, "reason": "test",
                "evidence": ["event-1"]}

    def test_configured_and_built_in_networks_cannot_be_blocked(self):
        for target in ("172.31.47.63", "10.9.4.4", "169.254.169.254", "127.0.0.1"):
            with self.subTest(target=target):
                result = self.engine.run(self.proposal("block_ip", target))
                self.assertFalse(result.passed)
                self.assertEqual(result.reason,
                                 f"targets a protected network address: {target}")

    def test_a_protected_address_cannot_be_isolated(self):
        result = self.engine.run(self.proposal("isolate_host", "172.31.47.63"))
        self.assertFalse(result.passed)

    def test_block_ip_refuses_the_monitored_host(self):
        result = self.engine.run(self.proposal("block_ip", "172.31.36.228"),
                                 monitored_ip="172.31.36.228")
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "block_ip targets the monitored host's own address")

    def test_block_ip_fails_closed_when_the_host_address_is_unknown(self):
        result = self.engine.run(self.proposal("block_ip", "192.0.2.10"),
                                 monitored_ip=UNRESOLVED)
        self.assertFalse(result.passed)

    def test_the_attacker_can_still_be_blocked(self):
        result = self.engine.run(self.proposal("block_ip", "172.31.42.14"),
                                 monitored_ip="172.31.36.228")
        self.assertTrue(result.passed)
        self.assertEqual(result.tier, Tier.HUMAN)

    def test_the_monitored_host_can_still_be_isolated(self):
        result = self.engine.run(self.proposal("isolate_host", "172.31.36.228"),
                                 monitored_ip="172.31.36.228")
        self.assertTrue(result.passed)


if __name__ == "__main__":
    unittest.main()
