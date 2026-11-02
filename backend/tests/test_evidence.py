"""Check 5 (evidence) beyond existence: relevance, support and attribution.

These are the cases a real but unrelated Wazuh event used to pass: an event
from another agent, from outside the investigation window, that never mentions
the target, or that carries a different ATT&CK technique.
"""

import unittest
from datetime import datetime, timedelta, timezone

from guardrails import (EvidenceScope, GuardrailEngine, RateLimiter, Tier,
                        mentions, parse_time)

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


def event(agent="001", minutes_ago=1, srcip="198.51.100.7", mitre=("T1110.001",),
          user="admin"):
    return {
        "timestamp": (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "agent": {"id": agent, "name": "lab-linux-01"},
        "rule": {"id": "5712", "mitre": {"id": list(mitre)}},
        "data": {"srcip": srcip, "srcuser": user},
        "full_log": f"sshd: Failed password for {user} from {srcip} port 4242",
    }


class FakeWazuh:
    def __init__(self, events=None, fail=False):
        self.events = events or {}
        self.fail = fail
        self.asked = []

    def fetch_events(self, ids):
        self.asked.append(list(ids))
        if self.fail:
            return None
        return {i: self.events[i] for i in ids if i in self.events}


SCOPE = EvidenceScope(agent_id="001", not_before=NOW - timedelta(minutes=10), not_after=NOW)


def block(target="198.51.100.7", evidence=("e1",), technique="T1110.001"):
    return {"action": "block_ip", "target": target, "reason": "brute force",
            "evidence": list(evidence), "hosts_affected": [], "mitre_technique": technique}


class EvidenceRelevanceTests(unittest.TestCase):
    def run_check(self, events, proposal, scope=SCOPE, fail=False):
        return GuardrailEngine(FakeWazuh(events, fail)).run(proposal, scope=scope)

    def test_relevant_evidence_passes_to_a_human(self):
        r = self.run_check({"e1": event()}, block())
        self.assertTrue(r.passed)
        self.assertEqual((r.tier, r.check), (Tier.HUMAN, "passed"))

    def test_event_from_another_agent_is_refused(self):
        r = self.run_check({"e1": event(agent="002")}, block())
        self.assertEqual(r.check, "evidence_relevance")

    def test_event_before_the_window_is_refused(self):
        r = self.run_check({"e1": event(minutes_ago=60)}, block())
        self.assertEqual(r.check, "evidence_relevance")
        self.assertIn("predates", r.reason)

    def test_event_after_the_window_is_refused(self):
        r = self.run_check({"e1": event(minutes_ago=-30)}, block())
        self.assertEqual(r.check, "evidence_relevance")

    def test_event_without_a_timestamp_is_refused(self):
        ev = event()
        del ev["timestamp"]
        r = self.run_check({"e1": ev}, block())
        self.assertEqual(r.check, "evidence_relevance")

    def test_real_event_that_never_mentions_the_target_is_refused(self):
        # A genuine event about something else cannot stand behind the action.
        r = self.run_check({"e1": event(srcip="203.0.113.9")}, block())
        self.assertEqual(r.check, "evidence_support")

    def test_target_must_match_a_whole_token(self):
        r = self.run_check({"e1": event(srcip="198.51.100.70")}, block())
        self.assertEqual(r.check, "evidence_support")

    def test_technique_unlike_the_wazuh_labels_is_noted_not_blocked(self):
        r = self.run_check({"e1": event()}, block(technique="T1118"))
        self.assertTrue(r.passed)
        self.assertEqual(len(r.notes), 1)
        self.assertIn("T1118 differs", r.reason)

    def test_matching_technique_has_no_note(self):
        r = self.run_check({"e1": event()}, block())
        self.assertEqual(r.notes, ())

    def test_address_inside_host_port_is_found(self):
        ev = event(srcip="")
        ev["data"]["audit"] = {"execve": {"a1": "http://198.51.100.7:8080/s.sh"}}
        r = self.run_check({"e1": ev}, block(technique=""))
        self.assertTrue(r.passed)

    def test_sub_technique_of_the_labelled_parent_passes(self):
        r = self.run_check({"e1": event(mitre=("T1110",))}, block(technique="T1110.001"))
        self.assertTrue(r.passed)

    def test_malformed_technique_is_refused(self):
        r = self.run_check({"e1": event()}, block(technique="brute force"))
        self.assertEqual(r.check, "attribution")

    def test_empty_technique_is_allowed(self):
        r = self.run_check({"e1": event()}, block(technique=""))
        self.assertTrue(r.passed)

    def test_unlabelled_events_do_not_block_a_technique(self):
        r = self.run_check({"e1": event(mitre=())}, block(technique="T1110.001"))
        self.assertTrue(r.passed)


class EvidenceFailClosedTests(unittest.TestCase):
    def test_indexer_unavailable_fails_closed(self):
        r = GuardrailEngine(FakeWazuh(fail=True)).run(block(), scope=SCOPE)
        self.assertFalse(r.passed)
        self.assertEqual(r.check, "evidence_exists")
        self.assertIn("could not be verified", r.reason)

    def test_missing_event_fails_closed(self):
        r = GuardrailEngine(FakeWazuh({"e1": event()})).run(
            block(evidence=("e1", "e2")), scope=SCOPE)
        self.assertEqual(r.check, "evidence_exists")

    def test_empty_evidence_fails_closed(self):
        r = GuardrailEngine(FakeWazuh()).run(block(evidence=()), scope=SCOPE)
        self.assertEqual(r.check, "evidence_exists")

    def test_too_many_cited_events_fail_closed(self):
        ids = [f"e{i}" for i in range(25)]
        wazuh = FakeWazuh({i: event() for i in ids})
        r = GuardrailEngine(wazuh).run(block(evidence=ids), scope=SCOPE)
        self.assertEqual(r.check, "evidence_exists")
        self.assertEqual(wazuh.asked, [])

    def test_repeated_ids_are_checked_once(self):
        wazuh = FakeWazuh({"e1": event()})
        r = GuardrailEngine(wazuh).run(block(evidence=("e1", "e1")), scope=SCOPE)
        self.assertTrue(r.passed)
        self.assertEqual(wazuh.asked, [["e1"]])

    def test_malformed_proposal_fails_closed(self):
        for raw in ({}, {"action": "block_ip"}, {"action": 7, "target": [], "reason": None}):
            with self.subTest(raw=raw):
                r = GuardrailEngine(FakeWazuh()).run(raw, scope=SCOPE)
                self.assertEqual((r.passed, r.check), (False, "schema"))


class EscalateTests(unittest.TestCase):
    def test_escalate_needs_relevant_evidence_and_goes_to_a_human(self):
        ev = event()
        r = GuardrailEngine(FakeWazuh({"e1": ev})).run(
            {"action": "escalate", "target": "lab-linux-01", "reason": "persistence",
             "evidence": ["e1"], "mitre_technique": ""}, scope=SCOPE)
        self.assertTrue(r.passed)
        self.assertEqual(r.tier, Tier.HUMAN)

    def test_escalate_without_evidence_is_refused(self):
        r = GuardrailEngine(FakeWazuh()).run(
            {"action": "escalate", "target": "lab-linux-01", "reason": "x"}, scope=SCOPE)
        self.assertEqual(r.check, "evidence_exists")

    def test_disable_account_is_elevated(self):
        r = GuardrailEngine(FakeWazuh({"e1": event(user="evil_user")})).run(
            {"action": "disable_account", "target": "evil_user", "reason": "x",
             "evidence": ["e1"], "mitre_technique": "T1110"}, scope=SCOPE)
        self.assertTrue(r.passed)
        self.assertEqual(r.tier, Tier.ELEVATED)


class CircuitBreakerTests(unittest.TestCase):
    def test_breaker_counts_allowed_auto_proposals_in_a_sliding_hour(self):
        clock = [1000.0]
        limiter = RateLimiter(2, clock=lambda: clock[0])
        self.assertEqual([limiter.allow() for _ in range(3)], [True, True, False])
        clock[0] += 3601
        self.assertTrue(limiter.allow())

    def test_breaker_stops_enrich_once_full(self):
        engine = GuardrailEngine(FakeWazuh(), auto_rate_limit=1)
        first = engine.run({"action": "enrich", "target": "lab-linux-01", "reason": "x"})
        second = engine.run({"action": "enrich", "target": "lab-linux-01", "reason": "x"})
        self.assertEqual((first.tier, second.check), (Tier.AUTO, "circuit_breaker"))

    def test_breaker_never_counts_human_tier_proposals(self):
        engine = GuardrailEngine(FakeWazuh({"e1": event()}), auto_rate_limit=1)
        for _ in range(3):
            self.assertTrue(engine.run(block(), scope=SCOPE).passed)

    def test_breaker_is_atomic_under_concurrency(self):
        import threading
        limiter = RateLimiter(50)
        results = []
        threads = [threading.Thread(target=lambda: results.append(limiter.allow()))
                   for _ in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(True), 50)


class HelperTests(unittest.TestCase):
    def test_parse_time_reads_wazuh_offsets(self):
        self.assertEqual(parse_time("2026-11-03T12:00:00.000+0000"), NOW)
        self.assertEqual(parse_time("2026-11-03T12:00:00Z"), NOW)
        self.assertIsNone(parse_time("yesterday"))

    def test_mentions_searches_nested_values(self):
        self.assertTrue(mentions({"a": {"b": ["x", "user=evil_user;"]}}, "evil_user"))
        self.assertFalse(mentions({"a": "evil_user2"}, "evil_user"))


if __name__ == "__main__":
    unittest.main()
