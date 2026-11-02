"""Governance pathways of the approval route, one test per case.

Each test names the case it covers in the governance test table (thesis
Appendix): valid approval, rejection, missing approval, elevated fail-closed,
wrong tier, duplicate decision, replayed request, tampered request, stale
proposal, Wazuh command failure and Wazuh timeout.
"""

import hashlib
import hmac
import os
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

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

import httpx

import agent
import main

SECRET = "test-service-secret"


def sign(method, path, body=b"", analyst="analyst1", ts=None, nonce=None):
    ts = str(ts if ts is not None else time.time())
    nonce = nonce or os.urandom(8).hex()
    sig = hmac.new(SECRET.encode(), main._signed_message(ts, nonce, method, path,
                                                         analyst, body),
                   hashlib.sha256).hexdigest()
    return (method, path, body, analyst, ts, nonce, sig)


def pending(tier="human", age_s=0):
    created = datetime.now(timezone.utc) - timedelta(seconds=age_s)
    return {"id": 4, "status": "pending", "tier": tier, "agent_id": "001",
            "created_at": created.isoformat()}


class ApprovalPathTests(unittest.TestCase):
    def approve(self, proposal, claim=True, resume=None, token="scoped-token"):
        with patch.object(main.db, "get_proposal", return_value=proposal), \
                patch.object(main.db, "claim_decision", return_value=claim) as claim_mock, \
                patch.object(main, "_resume", side_effect=resume) as resume_mock, \
                patch.object(main.db, "set_status") as status_mock, \
                patch.object(main.db, "audit") as audit_mock:
            try:
                result = main.approve(4, main.Decision(justification="ok"), "analyst1", token)
                error = None
            except main.HTTPException as exc:
                result, error = None, exc
        return result, error, claim_mock, resume_mock, status_mock, audit_mock

    def test_valid_approval_executes_once_with_the_analyst_token(self):
        result, error, claim, resume, _, _ = self.approve(pending())
        self.assertIsNone(error)
        self.assertEqual(result, {"status": "approved"})
        claim.assert_called_once_with(4, "approved", "analyst1", "ok")
        resume.assert_called_once_with(4, "approved", "scoped-token")

    def test_missing_wazuh_token_is_refused_before_any_decision(self):
        _, error, claim, resume, _, _ = self.approve(pending(), token=None)
        self.assertEqual(error.status_code, 401)
        claim.assert_not_called()
        resume.assert_not_called()

    def test_elevated_tier_fails_closed_and_is_audited(self):
        _, error, claim, resume, _, audit = self.approve(pending("elevated"))
        self.assertEqual(error.status_code, 501)
        claim.assert_not_called()
        resume.assert_not_called()
        self.assertEqual(audit.call_args.args[0], "approval_refused")

    def test_wrong_tier_cannot_be_approved(self):
        for tier in ("auto", "blocked"):
            with self.subTest(tier=tier):
                _, error, claim, _, _, _ = self.approve(pending(tier))
                self.assertEqual(error.status_code, 409)
                claim.assert_not_called()

    def test_already_decided_proposal_is_refused(self):
        decided = {**pending(), "status": "approved"}
        _, error, claim, resume, _, _ = self.approve(decided)
        self.assertEqual(error.status_code, 409)
        claim.assert_not_called()
        resume.assert_not_called()

    def test_concurrent_duplicate_approval_loses_the_race(self):
        # Both requests saw 'pending'; the compare-and-set lets only one win.
        _, error, _, resume, _, _ = self.approve(pending(), claim=False)
        self.assertEqual(error.status_code, 409)
        resume.assert_not_called()

    def test_stale_proposal_is_refused(self):
        _, error, claim, _, _, _ = self.approve(pending(age_s=main.PROPOSAL_TTL_S + 60))
        self.assertEqual(error.status_code, 409)
        self.assertIn("stale", error.detail)
        claim.assert_not_called()

    def test_unknown_proposal_is_not_found(self):
        _, error, _, _, _, _ = self.approve(None)
        self.assertEqual(error.status_code, 404)

    def test_wazuh_refusal_is_recorded_as_a_failure(self):
        response = httpx.Response(403, request=httpx.Request("PUT", "https://m"))
        _, error, _, _, status, audit = self.approve(
            pending(), resume=httpx.HTTPStatusError("no", request=response.request,
                                                    response=response))
        self.assertEqual(error.status_code, 403)
        status.assert_called_once_with(4, "execution_failed")
        self.assertEqual(audit.call_args.args[0], "execution_denied")

    def test_agent_not_running_the_command_is_recorded_as_a_failure(self):
        _, error, _, _, status, audit = self.approve(
            pending(), resume=main.ActiveResponseFailed([{"id": "001"}]))
        self.assertEqual(error.status_code, 502)
        status.assert_called_once_with(4, "execution_failed")
        self.assertEqual(audit.call_args.args[0], "execution_failed")

    def test_wazuh_timeout_is_recorded_as_a_failure(self):
        _, error, _, _, status, audit = self.approve(
            pending(), resume=httpx.ReadTimeout("slow"))
        self.assertEqual(error.status_code, 504)
        status.assert_called_once_with(4, "execution_failed")
        self.assertEqual(audit.call_args.args[0], "execution_failed")


class RejectionPathTests(unittest.TestCase):
    def reject(self, proposal, claim=True):
        with patch.object(main.db, "get_proposal", return_value=proposal), \
                patch.object(main.db, "claim_decision", return_value=claim) as claim_mock, \
                patch.object(main, "_resume") as resume_mock, \
                patch.object(main.db, "audit"):
            try:
                return main.reject(4, main.Decision(justification="no"), "analyst1"), \
                    None, claim_mock, resume_mock
            except main.HTTPException as exc:
                return None, exc, claim_mock, resume_mock

    def test_rejection_resumes_without_a_token(self):
        result, error, claim, resume = self.reject(pending())
        self.assertEqual(result, {"status": "rejected"})
        claim.assert_called_once_with(4, "rejected", "analyst1", "no")
        resume.assert_called_once_with(4, "rejected")

    def test_an_approved_proposal_cannot_then_be_rejected(self):
        _, error, claim, resume = self.reject({**pending(), "status": "executed"})
        self.assertEqual(error.status_code, 409)
        claim.assert_not_called()
        resume.assert_not_called()

    def test_duplicate_rejection_loses_the_race(self):
        _, error, _, resume = self.reject(pending(), claim=False)
        self.assertEqual(error.status_code, 409)
        resume.assert_not_called()


class MissingApprovalTests(unittest.TestCase):
    def test_execute_runs_nothing_without_an_approval(self):
        with patch.object(agent.db, "audit"), patch.object(agent.wazuh, "active_response") as ar:
            out = agent.execute({"decision": "rejected", "proposal_id": 4,
                                 "proposal": {"action": "block_ip", "target": "198.51.100.7"}})
        self.assertEqual(out["outcome"]["status"], "rejected")
        ar.assert_not_called()

    def test_execute_needs_the_scoped_token_even_when_approved(self):
        with patch.object(agent.db, "audit"), patch.object(agent.db, "set_status"):
            with self.assertRaises(PermissionError):
                agent.execute({"decision": "approved", "proposal_id": 4, "thread_id": "t-none",
                               "alert": {"agent_id": "001"},
                               "proposal": {"action": "block_ip", "target": "198.51.100.7"}})

    def test_read_only_actions_change_nothing(self):
        for action in ("enrich", "escalate"):
            with self.subTest(action=action), patch.object(agent.db, "audit"), \
                    patch.object(agent.db, "set_status"), \
                    patch.object(agent.wazuh, "active_response") as ar:
                out = agent.execute({"decision": "approved", "proposal_id": 4,
                                     "thread_id": "t", "alert": {"agent_id": "001"},
                                     "proposal": {"action": action, "target": "lab-linux-01"}})
            self.assertEqual(out["outcome"]["status"], "no_change")
            ar.assert_not_called()


class SignatureTests(unittest.TestCase):
    def setUp(self):
        main._seen_nonces.clear()

    def test_a_signed_request_identifies_the_analyst(self):
        self.assertEqual(main.verify_signature(*sign("POST", "/proposals/4/approve", b"{}")),
                         "analyst1")

    def test_a_replayed_request_is_refused(self):
        signed = sign("POST", "/proposals/4/approve", b"{}")
        main.verify_signature(*signed)
        with self.assertRaises(main.HTTPException) as raised:
            main.verify_signature(*signed)
        self.assertEqual(raised.exception.detail, "replayed request")

    def test_an_old_request_is_refused(self):
        with self.assertRaises(main.HTTPException):
            main.verify_signature(*sign("GET", "/queue", ts=time.time() - 300))

    def test_tampering_with_any_signed_part_is_refused(self):
        m, path, body, analyst, ts, nonce, sig = sign("POST", "/proposals/4/approve", b"{}")
        for changed in ((m, "/proposals/5/approve", body, analyst, ts, nonce, sig),
                        (m, path, b'{"justification":"x"}', analyst, ts, nonce, sig),
                        (m, path, body, "someone-else", ts, nonce, sig),
                        ("GET", path, body, analyst, ts, nonce, sig)):
            with self.subTest(changed=changed[:4]), self.assertRaises(main.HTTPException):
                main.verify_signature(*changed)

    def test_missing_parts_are_refused(self):
        m, path, body, analyst, ts, nonce, sig = sign("GET", "/queue")
        for changed in ((m, path, body, None, ts, nonce, sig),
                        (m, path, body, analyst, None, nonce, sig),
                        (m, path, body, analyst, ts, None, sig),
                        (m, path, body, analyst, ts, nonce, None)):
            with self.subTest(), self.assertRaises(main.HTTPException) as raised:
                main.verify_signature(*changed)
            self.assertEqual(raised.exception.status_code, 401)


class ApprovalCardTests(unittest.TestCase):
    """Log text reaches the approval card; it must render as text, not markup."""

    def test_plugin_ui_never_injects_raw_html(self):
        public = Path(__file__).resolve().parents[2] / "dashboard-plugin" / "public"
        for source in public.glob("*.ts*"):
            text = source.read_text(encoding="utf-8")
            for sink in ("dangerouslySetInnerHTML", "innerHTML", "outerHTML",
                         "insertAdjacentHTML", "document.write"):
                with self.subTest(file=source.name, sink=sink):
                    self.assertNotIn(sink, text)


if __name__ == "__main__":
    unittest.main()
