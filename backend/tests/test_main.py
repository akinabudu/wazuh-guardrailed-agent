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
    "APP_SECRET": "test-service-secret",
})

import main


class MainTests(unittest.TestCase):
    def test_investigation_runs_in_background(self):
        tasks = MagicMock()
        graph = MagicMock()

        with patch.object(main, "_graph", graph), patch.object(
            main.os, "urandom", return_value=b"test"
        ):
            result = main.investigate(
                main.Alert(agent_id="000"),
                tasks,
                "analyst1",
            )

        self.assertEqual(result["status"], "started")
        self.assertEqual(result["thread"], "alert-000-74657374")
        tasks.add_task.assert_called_once()
        args, kwargs = tasks.add_task.call_args
        self.assertIs(args[0], graph.invoke)
        self.assertEqual(args[1]["thread_id"], result["thread"])
        self.assertEqual(args[1]["requested_by"], "analyst1")
        self.assertEqual(
            kwargs["config"]["configurable"]["thread_id"], result["thread"]
        )

    def test_request_without_window_gets_the_evidence_window(self):
        # The dashboard sends no `since`. Retrieval must then be bounded by the
        # same window the evidence check enforces, or the model is shown (and
        # cites) older same-rule alerts that the check rejects.
        tasks = MagicMock()
        with patch.object(main, "_graph", MagicMock()):
            main.investigate(main.Alert(agent_id="001", rule_id="5710"), tasks, "admin")
        alert = tasks.add_task.call_args[0][1]["alert"]
        since = main.agent_mod.parse_time(alert["since"])
        scope = main.agent_mod.evidence_scope(alert)
        self.assertEqual(scope.not_before, since)
        query = main.agent_mod.hunt_query(alert)
        self.assertIn({"range": {"timestamp": {"gte": alert["since"]}}},
                      query["query"]["bool"]["filter"])

    def test_request_window_is_kept(self):
        tasks = MagicMock()
        with patch.object(main, "_graph", MagicMock()):
            main.investigate(main.Alert(agent_id="001", since="2026-11-03T11:55:00Z"),
                             tasks, "harness")
        self.assertEqual(tasks.add_task.call_args[0][1]["alert"]["since"],
                         "2026-11-03T11:55:00Z")

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

    def test_resume_uses_the_persisted_thread(self):
        graph = MagicMock()
        with patch.object(main, "_graph", graph), patch.object(
            main, "_thread_for", return_value="alert-000-test"
        ), patch.object(main.agent_mod, "authorize_execution") as authorize, \
                patch.object(main.agent_mod, "revoke_execution") as revoke:
            main._resume(4, "approved", "scoped-token")

        args, kwargs = graph.invoke.call_args
        self.assertEqual(args[0].resume, "approved")
        self.assertEqual(
            kwargs["config"],
            {"configurable": {"thread_id": "alert-000-test"}},
        )
        authorize.assert_called_once_with("alert-000-test", "scoped-token")
        revoke.assert_called_once_with("alert-000-test")

    def test_approve_records_an_active_response_the_agent_did_not_run(self):
        pending = {"status": "pending", "tier": "human"}
        with patch.dict(os.environ, {"APP_SECRET": "secret"}), patch.object(
            main.db, "get_proposal", return_value=pending
        ), patch.object(main.db, "claim_decision", return_value=True), patch.object(
            main, "_resume", side_effect=main.ActiveResponseFailed([{"id": ["001"]}])
        ), patch.object(main.db, "set_status") as set_status, patch.object(
            main.db, "audit"
        ) as audit:
            with self.assertRaises(main.HTTPException) as raised:
                main.approve(4, main.Decision(justification="ok"), "analyst1",
                             "scoped-token")

        self.assertEqual(raised.exception.status_code, 502)
        set_status.assert_called_once_with(4, "execution_failed")
        audit.assert_called_with("execution_failed", 4,
                                 payload={"failed_items": [{"id": ["001"]}]})

    def test_backend_rejects_unsigned_dashboard_calls(self):
        with self.assertRaises(main.HTTPException) as raised:
            main.verify_signature("GET", "/queue", b"", "analyst1",
                                  str(main.time.time()), "nonce-0001", "wrong-signature")

        self.assertEqual(raised.exception.status_code, 401)

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
