import unittest

from guardrails import ALLOWED_ACTIONS, ollama_action_schema


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


if __name__ == "__main__":
    unittest.main()
