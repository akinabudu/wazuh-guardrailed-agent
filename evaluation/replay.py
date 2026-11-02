"""Circuit-breaker sensitivity: replay a run's auto-tier proposals at other limits.

    python replay.py results/<run> [--limits 5,10,20]

The breaker sees every auto-tier proposal that passed checks 1-5, in the order
and at the times they were made. This replays that recorded sequence through
the backend's own RateLimiter at each limit, and reports how many would have
been stopped. Nothing about the run itself changes. Writes breaker.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "backend"))

from lab import parse_ts  # noqa: E402


def auto_sequence(trials: list[dict]) -> list[dict]:
    seq = []
    for t in trials:
        p = (t.get("investigation") or {}).get("proposal")
        if not p or p["risk_tier"] not in ("auto", "blocked"):
            continue
        check = p.get("guardrail_check")
        if p["risk_tier"] == "auto" or check == "circuit_breaker":
            seq.append({"trial_id": t["trial_id"], "phase": t["phase"],
                        "malicious": t.get("malicious"),
                        "from_attacker": t.get("field") not in (None, "fim_filename"),
                        "at": parse_ts(p["created_at"]).timestamp(),
                        "stopped_in_run": check == "circuit_breaker"})
    return sorted(seq, key=lambda r: r["at"])


def replay(seq: list[dict], limit: int) -> dict:
    from guardrails import RateLimiter

    clock = [0.0]
    limiter = RateLimiter(limit, clock=lambda: clock[0])
    stopped = []
    for r in seq:
        clock[0] = r["at"]
        if not limiter.allow():
            stopped.append(r)
    return {"limit_per_hour": limit, "auto_proposals": len(seq), "stopped": len(stopped),
            "stopped_by_phase": dict(Counter(r["phase"] for r in stopped)),
            "stopped_on_attack_runs": sum(1 for r in stopped if r["malicious"]),
            "stopped_trials": [r["trial_id"] for r in stopped]}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run")
    ap.add_argument("--limits", default="5,10,20")
    args = ap.parse_args()
    run = Path(args.run)
    trials = [json.loads(l) for l in (run / "trials.jsonl").read_text().splitlines() if l]
    seq = auto_sequence(trials)
    result = {"recorded_stops": sum(r["stopped_in_run"] for r in seq),
              "replays": [replay(seq, int(x)) for x in args.limits.split(",")]}
    (run / "breaker.json").write_text(json.dumps(result, indent=1))
    print(json.dumps({**result, "replays": [{k: v for k, v in r.items()
                                              if k != "stopped_trials"}
                                             for r in result["replays"]]}, indent=1))


if __name__ == "__main__":
    main()
