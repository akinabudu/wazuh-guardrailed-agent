"""
guardrails.py - The guardrail engine (the "gauntlet").

This is the safety core of the whole framework and the heart of the thesis
contribution. It is DETERMINISTIC application code. The language model NEVER
runs in here. The model only ever *proposes* a structured action; this module,
and a human, decide whether it may execute.

Every proposed action runs five checks in sequence:
    1. schema       - is it a well-formed, known action object?
    2. allowlist    - is the action type permitted at all?
    3. target       - does the target fit the requested action?
    4. blast-radius - is it within safe limits (no crown-jewels, no protected
                      infrastructure address, not the monitored host itself,
                      capped scope)?
    5. evidence     - does it cite real Wazuh events (not hallucinated)?

Failing ANY check -> blocked and logged; it never reaches a human.
Passing all five -> the tier router decides who signs off:
    - auto      : low-risk, reversible, rate-limited -> policy auto-approves
    - human     : medium-risk -> one analyst must approve
    - elevated  : high-risk / irreversible -> analyst + second approver

Because these are ordinary if-statements, no wording inside a log - however
cleverly crafted by an attacker - can argue its way past them.
"""

from __future__ import annotations

import os
import re
import time
from ipaddress import ip_address, ip_network
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
    "block_ip":       {"tier": "human",    "reversible": True},
    "kill_process":   {"tier": "human",    "reversible": True},
    "isolate_host":   {"tier": "human",    "reversible": False},
    "disable_account":{"tier": "elevated", "reversible": False},
}


# What an enrich target may look like: an address, a host name or a file hash.
# Anything else - a URL above all - is something the agent would be sending
# data to, not looking up.
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*$")
_FILE_HASH = re.compile(r"^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")

# Infrastructure addresses no action may block or isolate, whatever the
# deployment adds through PROTECTED_NETWORKS.
_ALWAYS_PROTECTED = [ip_network(n) for n in (
    "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32", "224.0.0.0/4",
    "::1/128", "fe80::/10",
)]

# Returned by the caller when it could not resolve the monitored host's address.
UNRESOLVED = "unresolved"


def _as_ip(value: str):
    try:
        return ip_address(value)
    except ValueError:
        return None


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
        self.protected_networks = _ALWAYS_PROTECTED + self._load_protected_networks()
        self.max_hosts = max_hosts
        self.auto_limiter = RateLimiter(
            auto_rate_limit or int(os.getenv("AUTO_ACTION_RATE_LIMIT", "10"))
        )

    @staticmethod
    def _load_crown_jewels() -> set[str]:
        raw = os.getenv("CROWN_JEWEL_ASSETS", "")
        return {a.strip().lower() for a in raw.split(",") if a.strip()}

    @staticmethod
    def _load_protected_networks() -> list:
        raw = os.getenv("PROTECTED_NETWORKS", "")
        return [ip_network(n.strip(), strict=False) for n in raw.split(",") if n.strip()]

    # -- the full gauntlet ---------------------------------------------------
    def run(self, raw_proposal: dict[str, Any],
            monitored_ip: str | None = None) -> GuardrailResult:
        """`monitored_ip` is the investigated agent's address, resolved from the
        Wazuh manager, never from the proposal. UNRESOLVED fails block_ip closed."""
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

        # CHECK 3 - target shape
        target_ok, target_reason = self._check_target(action)
        if not target_ok:
            return GuardrailResult(False, Tier.BLOCKED, target_reason, action)

        # CHECK 4 - blast radius
        radius_ok, radius_reason = self._check_blast_radius(action, monitored_ip)
        if not radius_ok:
            return GuardrailResult(False, Tier.BLOCKED, radius_reason, action)

        # CHECK 5 - evidence grounding
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
    @staticmethod
    def _check_target(action: ProposedAction) -> tuple[bool, str]:
        if action.action == "block_ip":
            try:
                ip_address(action.target)
            except ValueError:
                return False, "block_ip target is not an IP address"
        if action.action == "kill_process":
            if not action.target.isdigit() or int(action.target) < 1:
                return False, "kill_process target is not a positive process id"
        if action.action == "enrich":
            t = action.target
            if not (_as_ip(t) or _HOSTNAME.match(t) or _FILE_HASH.match(t)):
                return False, "enrich target is not an address, host name or file hash"
        return True, "target shape is valid"

    def _check_blast_radius(self, action: ProposedAction,
                            monitored_ip: str | None = None) -> tuple[bool, str]:
        targets = {action.target.lower(), *(h.lower() for h in action.hosts_affected)}

        # never touch a crown-jewel asset automatically
        hit = targets & self.crown_jewels
        if hit:
            return False, f"targets a protected asset: {', '.join(sorted(hit))}"

        # Crown jewels are names; the same protection has to hold for the
        # addresses of the infrastructure itself.
        ip = _as_ip(action.target)
        if ip and action.action in ("block_ip", "isolate_host"):
            if any(ip in net for net in self.protected_networks if net.version == ip.version):
                return False, f"targets a protected network address: {ip}"

        # Blocking the monitored host's own address cuts it off from the
        # manager and contains nothing.
        if action.action == "block_ip" and monitored_ip is not None:
            if monitored_ip == UNRESOLVED:
                return False, "monitored host address could not be resolved"
            if ip == _as_ip(monitored_ip):
                return False, "block_ip targets the monitored host's own address"

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
