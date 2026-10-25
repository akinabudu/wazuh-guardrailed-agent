"""Replay a run's recorded proposals through the current guardrail engine.

    python replay.py results/2026-10-22 [--protected 172.31.47.63/32,172.31.0.2/32]

The model's proposals are taken as they were, so any change in outcome comes
from the guardrails alone. Evidence grounding is replayed from the recorded
verdict, since the cited events are a fact about the original run.
Writes replay.json next to trials.jsonl.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "backend"))

EVIDENCE_MISSING = "cited evidence does not exist in Wazuh"


class RecordedEvidence:
    def __init__(self, verdict: bool):
        self.verdict = verdict

    def verify_events(self, ids):
        return self.verdict


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run")
    ap.add_argument("--protected", default="172.31.47.63/32,172.31.0.2/32")
    args = ap.parse_args()
    os.environ["PROTECTED_NETWORKS"] = args.protected
    os.environ.setdefault("CROWN_JEWEL_ASSETS", "dc01,payroll,backup-primary")
    os.environ["AUTO_ACTION_RATE_LIMIT"] = "100000"   # replay is not a rate test
    from guardrails import GuardrailEngine

    run = Path(args.run)
    lab = json.loads((run / "lab.json").read_text())
    monitored = lab["endpoint"]["ip"]
    rows = []
    for line in (run / "trials.jsonl").read_text().splitlines():
        t = json.loads(line)
        p = (t.get("investigation") or {}).get("proposal")
        if not p:
            continue
        engine = GuardrailEngine(RecordedEvidence(p["guardrail_reason"] != EVIDENCE_MISSING))
        new = engine.run(p["action"], monitored_ip=monitored)
        rows.append({
            "trial_id": t["trial_id"], "phase": t["phase"], "category": t.get("category"),
            "action": p["action"].get("action"), "target": p["action"].get("target"),
            "susceptible": (t.get("score") or {}).get("susceptible"),
            "before": {"passed": p["guardrail_ok"], "tier": p["risk_tier"],
                       "reason": p["guardrail_reason"]},
            "after": {"passed": new.passed, "tier": new.tier.value, "reason": new.reason},
        })

    def tally(phase=None, steered=None):
        sel = [r for r in rows if (phase is None or r["phase"] == phase)
               and (steered is None or bool(r["susceptible"]) == steered)]
        return {"n": len(sel),
                "blocked_before": sum(not r["before"]["passed"] for r in sel),
                "blocked_after": sum(not r["after"]["passed"] for r in sel),
                "auto_before": sum(r["before"]["tier"] == "auto" for r in sel),
                "auto_after": sum(r["after"]["tier"] == "auto" for r in sel)}

    summary = {
        "monitored_ip": monitored, "protected": args.protected,
        "all": tally(), "by_phase": {ph: tally(ph) for ph in sorted({r["phase"] for r in rows})},
        "injection_steered": tally("injection", True),
        "newly_blocked_reasons": Counter(r["after"]["reason"] for r in rows
                                         if r["before"]["passed"] and not r["after"]["passed"]),
        "newly_passed": [r for r in rows if not r["before"]["passed"] and r["after"]["passed"]],
        "steered_by_category": {
            c: {"steered": sum(1 for r in rows if r["category"] == c and r["susceptible"]),
                "blocked_after": sum(1 for r in rows if r["category"] == c and r["susceptible"]
                                     and not r["after"]["passed"]),
                "auto_after": sum(1 for r in rows if r["category"] == c and r["susceptible"]
                                  and r["after"]["tier"] == "auto")}
            for c in sorted({r["category"] for r in rows if r["phase"] == "injection"})},
    }
    (run / "replay.json").write_text(json.dumps({"summary": summary, "rows": rows}, indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
