import asyncio
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

import main


class MainTests(unittest.TestCase):
    def test_lifespan_keeps_checkpointer_open(self):
        checkpointer = MagicMock()
        context = MagicMock()
        context.__enter__.return_value = checkpointer

        async def exercise():
            with patch.object(
                main.PostgresSaver, "from_conn_string", return_value=context
            ), patch.object(main.db, "ensure_schema") as ensure_schema, patch.object(
                main.agent_mod, "build_graph", return_value="graph"
            ):
                async with main.lifespan(None):
                    self.assertEqual(main._graph, "graph")
                    self.assertIs(main._checkpointer, checkpointer)
                    context.__exit__.assert_not_called()
                ensure_schema.assert_called_once_with()

        asyncio.run(exercise())
        context.__exit__.assert_called_once()
        self.assertIsNone(main._graph)
        self.assertIsNone(main._checkpointer)

    def test_thread_lookup_returns_persisted_thread(self):
        with patch.object(main.db, "get_thread_id", return_value="alert-000-test"):
            self.assertEqual(main._thread_for(4), "alert-000-test")

    def test_health_checks_dependencies(self):
        with patch.object(main.db, "ping") as db_ping, patch.object(
            main.agent_mod, "check_dependencies"
        ) as dependency_check:
            self.assertEqual(main.health(), {"status": "ok"})
        db_ping.assert_called_once_with()
        dependency_check.assert_called_once_with()

    def test_thread_lookup_rejects_legacy_proposal(self):
        with patch.object(main.db, "get_thread_id", return_value=None):
            with self.assertRaises(main.HTTPException) as raised:
                main._thread_for(4)
        self.assertEqual(raised.exception.status_code, 409)


if __name__ == "__main__":
    unittest.main()
