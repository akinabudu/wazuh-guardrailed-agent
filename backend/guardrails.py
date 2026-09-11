"""
guardrails.py - The guardrail engine (the "gauntlet").

This is the safety core of the whole framework and the heart of the thesis
contribution. It is DETERMINISTIC application code. The language model NEVER
runs in here. The model only ever *proposes* a structured action; this module,
and a human, decide whether it may execute.

Every proposed action runs four checks in sequence:
    1. schema       - is it a well-formed, known action object?
    2. allowlist    - is the action type permitted at all?
    3. blast-radius - is it within safe limits (no crown-jewels, capped scope)?
    4. evidence     - does it cite real Wazuh events (not hallucinated)?

Failing ANY check -> blocked and logged; it never reaches a human.
Passing all four -> the tier router decides who signs off:
    - auto      : low-risk, reversible, rate-limited -> policy auto-approves
    - human     : medium-risk -> one analyst must approve
    - elevated  : high-risk / irreversible -> analyst + second approver

Because these are ordinary if-statements, no wording inside a log - however
cleverly crafted by an attacker - can argue its way past them.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator


# ---------------------------------------------------------------------------
# 1. The action schema. A proposal that does not fit this is rejected outright.
# ---------------------------------------------------------------------------

# The allowlist. The agent can NEVER invent a capability outside this set.
# Each action is tagged with its default risk tier and whether it is reversible.
ALLOWED_ACTIONS: dict[str, dict[str, Any]] = {
    "enrich":         {"tier": "auto",     "reversible": True},   # read-only, changes nothing
    "block_ip":       {"tier": "auto",     "reversible": True},   # low-risk, reversible
    "kill_process":   {"tier": "human",    "reversible": True},
    "isolate_host":   {"tier": "human",    "reversible": False},
    "disable_account":{"tier": "elevated", "reversible": False},
}


class ProposedAction(BaseModel):
    """The strict shape every proposed action must take."""
    action: str = Field(..., description="one of ALLOWED_ACTIONS")
    target: str = Field(..., min_length=1, description="ip, host, user, or pid")
    reason: str = Field(..., min_length=1, max_length=2000)
    evidence: list[str] = Field(default_factory=list, description="Wazuh event ids")
    hosts_affected: list[str] = Field(default_factory=list)
    mitre_technique: str | None = None

    @field_validator("action")
    @classmethod
    def _known_action(cls, v: str) -> str:
        if v not in ALLOWED_ACTIONS:
            raise ValueError(f"unknown action '{v}'")
        return v


def ollama_action_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": list(ALLOWED_ACTIONS)},
            "target": {"type": "string"},
            "reason": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "string"}},
            "hosts_affected": {
                "type": "array", "items": {"type": "string"}
            },
            "mitre_technique": {"type": "string"},
        },
        "required": [
            "action", "target", "reason", "evidence",
            "hosts_affected", "mitre_technique",
        ],
    }


class Tier(str, Enum):
    AUTO = "auto"
    HUMAN = "human"
    ELEVATED = "elevated"
    BLOCKED = "blocked"


@dataclass
class GuardrailResult:
    passed: bool
    tier: Tier
    reason: str
    action: ProposedAction | None = None


# ---------------------------------------------------------------------------
# A tiny rate limiter for the autonomous lane (the circuit breaker).
# In production, back this with the DB so it survives restarts; in-memory here
# keeps the example self-contained.
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, max_per_hour: int):
        self.max = max_per_hour
        self._timestamps: list[float] = []

    def allow(self) -> bool:
        now = time.time()
        cutoff = now - 3600
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        if len(self._timestamps) >= self.max:
            return False
        self._timestamps.append(now)
        return True


# ---------------------------------------------------------------------------
# The engine.
# ---------------------------------------------------------------------------
class GuardrailEngine:
    def __init__(self, wazuh_client, crown_jewels: set[str] | None = None,
                 auto_rate_limit: int | None = None, max_hosts: int = 5):
        self.wazuh = wazuh_client
        self.crown_jewels = crown_jewels or self._load_crown_jewels()
        self.max_hosts = max_hosts
        self.auto_limiter = RateLimiter(
            auto_rate_limit or int(os.getenv("AUTO_ACTION_RATE_LIMIT", "10"))
        )

    @staticmethod
    def _load_crown_jewels() -> set[str]:
        raw = os.getenv("CROWN_JEWEL_ASSETS", "")
        return {a.strip().lower() for a in raw.split(",") if a.strip()}

    # -- the full gauntlet ---------------------------------------------------
    def run(self, raw_proposal: dict[str, Any]) -> GuardrailResult:
        # CHECK 1 - schema
        try:
            action = ProposedAction(**raw_proposal)
        except ValidationError as e:
            return GuardrailResult(False, Tier.BLOCKED, f"schema check failed: {e}")

        # CHECK 2 - allowlist (redundant with the validator, kept explicit
        # because this is the security-critical gate and should be obvious)
        if action.action not in ALLOWED_ACTIONS:
            return GuardrailResult(False, Tier.BLOCKED,
                                   f"action '{action.action}' not on allowlist", action)

        # CHECK 3 - blast radius
        radius_ok, radius_reason = self._check_blast_radius(action)
        if not radius_ok:
            return GuardrailResult(False, Tier.BLOCKED, radius_reason, action)

        # CHECK 4 - evidence grounding
        if action.action != "enrich":  # enrich changes nothing, needs no evidence
            if not action.evidence:
                return GuardrailResult(False, Tier.BLOCKED,
                                       "no evidence cited", action)
            if not self.wazuh.verify_events(action.evidence):
                return GuardrailResult(False, Tier.BLOCKED,
                                       "cited evidence does not exist in Wazuh", action)

        # All checks passed -> decide the autonomy tier.
        tier = self._classify_tier(action)

        # The autonomous lane is the one sharp edge: rate-limit it hard.
        if tier == Tier.AUTO and not self.auto_limiter.allow():
            return GuardrailResult(False, Tier.BLOCKED,
                                   "auto-action rate limit hit (circuit breaker)", action)

        return GuardrailResult(True, tier, "passed all checks", action)

    # -- individual checks ---------------------------------------------------
    def _check_blast_radius(self, action: ProposedAction) -> tuple[bool, str]:
        targets = {action.target.lower(), *(h.lower() for h in action.hosts_affected)}

        # never touch a crown-jewel asset automatically
        hit = targets & self.crown_jewels
        if hit:
            return False, f"targets a protected asset: {', '.join(sorted(hit))}"

        # cap the number of hosts a single action may affect
        if len(action.hosts_affected) > self.max_hosts:
            return False, (f"affects {len(action.hosts_affected)} hosts "
                           f"(limit {self.max_hosts})")

        return True, "within limits"

    def _classify_tier(self, action: ProposedAction) -> Tier:
        meta = ALLOWED_ACTIONS[action.action]
        base = Tier(meta["tier"])
        # An irreversible action never rides the auto lane, whatever its default.
        if not meta["reversible"] and base == Tier.AUTO:
            return Tier.HUMAN
        return base


# ---------------------------------------------------------------------------
# Quick self-test:  python guardrails.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    class _FakeWazuh:
        def verify_events(self, ids): return all(i.isdigit() for i in ids)

    eng = GuardrailEngine(_FakeWazuh(), crown_jewels={"dc01", "payroll"})

    samples = [
        {"action": "block_ip", "target": "203.0.113.47", "reason": "brute force",
         "evidence": ["1699823"]},                                   # -> auto
        {"action": "disable_account", "target": "jsmith", "reason": "compromise",
         "evidence": ["1699999"]},                                   # -> elevated
        {"action": "block_ip", "target": "dc01", "reason": "spoofed",
         "evidence": ["1700000"]},                                   # -> BLOCKED (crown jewel)
        {"action": "whitelist_ip", "target": "10.0.0.5", "reason": "injected"},  # -> BLOCKED (not allowed)
        {"action": "kill_process", "target": "4123", "reason": "no evidence"},   # -> BLOCKED (no evidence)
    ]
    for s in samples:
        r = eng.run(s)
        print(f"{s['action']:<16} -> passed={r.passed!s:<5} tier={r.tier.value:<9} {r.reason}")
