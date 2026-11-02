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
    5. evidence     - are the cited Wazuh events real, from the investigated
                      agent and the investigation window, and do they mention
                      the target? Is the ATT&CK id well formed? (A technique
                      that differs from Wazuh's rule labels is noted, not blocked.)

Failing ANY check -> blocked and logged; it never reaches a human.
Passing all five -> the tier router decides who signs off:
    - auto      : read-only enrichment, rate-limited (circuit breaker)
    - human     : one analyst must approve
    - elevated  : analyst + second approver. The second-approver route is not
                  implemented, so elevated proposals fail closed at approval.

What these checks establish, and what they do not:
    format      checks 1 and 3 (shape of the object and of its target)
    policy      checks 2 and 4 and the tier router (what may run, and who signs)
    grounding   check 5 (the cited events exist, belong to this incident and
                mention the target). It does not establish that the proposed
                response is the right one; that judgement stays with the analyst.

Because these are ordinary if-statements, no wording inside a log - however
cleverly crafted by an attacker - can argue its way past them.
"""

from __future__ import annotations

import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator


# ---------------------------------------------------------------------------
# 1. The action schema. A proposal that does not fit this is rejected outright.
# ---------------------------------------------------------------------------

# The allowlist. The agent can NEVER invent a capability outside this set.
# Each action is tagged with its default risk tier and whether it is technically
# reversible. Reversibility is not the same as low impact: isolating a host can
# be undone, but stops whatever the host was serving until it is.
ALLOWED_ACTIONS: dict[str, dict[str, Any]] = {
    "enrich":         {"tier": "auto",     "reversible": True,  "changes": False},
    "escalate":       {"tier": "human",    "reversible": True,  "changes": False},
    "block_ip":       {"tier": "human",    "reversible": True,  "changes": True},
    # A killed process can be restarted, but its memory and open work are lost.
    "kill_process":   {"tier": "human",    "reversible": False, "changes": True},
    "isolate_host":   {"tier": "human",    "reversible": True,  "changes": True},
    "disable_account":{"tier": "elevated", "reversible": True,  "changes": True},
}

# Actions that change nothing on the endpoint. `escalate` puts the incident and
# its evidence in front of an analyst without proposing any remediation.
READ_ONLY_ACTIONS = {a for a, m in ALLOWED_ACTIONS.items() if not m["changes"]}

MAX_EVIDENCE = 20
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


# What an enrich target may look like: an address, a host name or a file hash.
# Anything else - a URL above all - is something the agent would be sending
# data to, not looking up.
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*$")
_FILE_HASH = re.compile(r"^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_USERNAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,31}\$?$")

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
    # Which stage decided: schema, allowlist, target, blast_radius,
    # evidence_exists, evidence_relevance, evidence_support, attribution,
    # circuit_breaker, or passed. Reported separately in the evaluation.
    check: str = "passed"
    # Observations that do not block, shown to the analyst (e.g. a technique
    # that differs from Wazuh's labels on the cited events).
    notes: tuple[str, ...] = ()


@dataclass
class EvidenceScope:
    """The incident the cited evidence must belong to. Built by the caller from
    the investigation request and the Wazuh manager, never from the proposal."""
    agent_id: str
    not_before: datetime | None = None
    not_after: datetime | None = None
    margin: timedelta = timedelta(minutes=5)


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    # Wazuh writes +0000 without a colon.
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    try:
        ts = datetime.fromisoformat(text)
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _leaves(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [s for v in value.values() for s in _leaves(v)]
    if isinstance(value, list):
        return [s for v in value for s in _leaves(v)]
    return [str(value)] if value is not None else []


_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9._:@\-]+")
_TOKEN_SPLIT_NO_COLON = re.compile(r"[^A-Za-z0-9._@\-]+")


def mentions(event: dict, target: str) -> bool:
    """True when `target` appears in the event as a whole value or token, so
    '10.0.0.1' does not match inside '10.0.0.15'. A target without a colon is
    also matched inside 'host:port' tokens; IPv6 targets keep their colons."""
    want = target.strip().lower()
    if not want:
        return False
    split = _TOKEN_SPLIT if ":" in want else _TOKEN_SPLIT_NO_COLON
    for leaf in _leaves(event):
        text = leaf.lower()
        if text == want or want in split.split(text):
            return True
    return False


def event_techniques(event: dict) -> set[str]:
    ids = ((event.get("rule") or {}).get("mitre") or {}).get("id") or []
    return {str(i) for i in (ids if isinstance(ids, list) else [ids])}


# ---------------------------------------------------------------------------
# A rate limiter for the autonomous lane (the circuit breaker).
#
# What it counts: auto-tier proposals that passed checks 1-5. Each one allowed
# through takes a slot; a proposal that arrives with no slot free is stopped.
# Clock: wall-clock time.time(), a sliding one-hour window.
# Persistence: in memory, so a backend restart empties the window.
# Concurrency: a lock makes check-and-take atomic across request threads.
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, max_per_hour: int, clock=time.time):
        self.max = max_per_hour
        self._clock = clock
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = self._clock()
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
            monitored_ip: str | None = None,
            scope: EvidenceScope | None = None) -> GuardrailResult:
        """`monitored_ip` is the investigated agent's address, resolved from the
        Wazuh manager, never from the proposal. UNRESOLVED fails block_ip closed.
        `scope` is the incident the evidence must come from; without it only
        existence is checked."""
        def blocked(check: str, reason: str, action=None) -> GuardrailResult:
            return GuardrailResult(False, Tier.BLOCKED, reason, action, check)

        # CHECK 1 - schema
        try:
            action = ProposedAction(**raw_proposal)
        except (ValidationError, TypeError) as e:
            return blocked("schema", f"schema check failed: {e}")

        # CHECK 2 - allowlist (redundant with the validator, kept explicit
        # because this is the security-critical gate and should be obvious)
        if action.action not in ALLOWED_ACTIONS:
            return blocked("allowlist", f"action '{action.action}' not on allowlist", action)

        # CHECK 3 - target shape
        target_ok, target_reason = self._check_target(action)
        if not target_ok:
            return blocked("target", target_reason, action)

        # CHECK 4 - blast radius
        radius_ok, radius_reason = self._check_blast_radius(action, monitored_ip)
        if not radius_ok:
            return blocked("blast_radius", radius_reason, action)

        # CHECK 5 - evidence grounding (enrich changes nothing, needs no evidence)
        notes: tuple[str, ...] = ()
        if action.action != "enrich":
            check, reason, notes = self._check_evidence(action, scope)
            if check != "passed":
                return blocked(check, reason, action)

        # All checks passed -> decide the autonomy tier.
        tier = self._classify_tier(action)

        # The autonomous lane is the one sharp edge: rate-limit it hard.
        if tier == Tier.AUTO and not self.auto_limiter.allow():
            return blocked("circuit_breaker",
                           "auto-action rate limit hit (circuit breaker)", action)

        reason = "passed all checks" + (f" (note: {'; '.join(notes)})" if notes else "")
        return GuardrailResult(True, tier, reason, action, "passed", notes)

    # -- individual checks ---------------------------------------------------
    def _check_evidence(self, action: ProposedAction,
                        scope: EvidenceScope | None) -> tuple[str, str, tuple[str, ...]]:
        ids = list(dict.fromkeys(action.evidence))
        if not ids:
            return "evidence_exists", "no evidence cited", ()
        if len(ids) > MAX_EVIDENCE:
            return "evidence_exists", f"cites {len(ids)} events (limit {MAX_EVIDENCE})", ()
        events = self.wazuh.fetch_events(ids)
        if events is None:
            # On any doubt, fail closed: unverifiable evidence is not verified.
            return ("evidence_exists",
                    "cited evidence could not be verified (indexer unavailable)", ())
        missing = [i for i in ids if i not in events]
        if missing:
            return "evidence_exists", "cited evidence does not exist in Wazuh", ()

        if scope is not None:
            for eid in ids:
                ev = events[eid]
                if str((ev.get("agent") or {}).get("id", "")) != scope.agent_id:
                    return ("evidence_relevance",
                            f"cited event {eid} is from another agent", ())
                ts = parse_time(ev.get("timestamp"))
                if ts is None:
                    return ("evidence_relevance",
                            f"cited event {eid} has no readable timestamp", ())
                if scope.not_before and ts < scope.not_before - scope.margin:
                    return ("evidence_relevance",
                            f"cited event {eid} predates the investigation window", ())
                if scope.not_after and ts > scope.not_after + scope.margin:
                    return ("evidence_relevance",
                            f"cited event {eid} postdates the investigation window", ())

        # The target must appear in what was cited, so a real but unrelated
        # event cannot stand behind an action on something it never mentions.
        if not any(mentions(events[i], action.target) for i in ids):
            return "evidence_support", "no cited event mentions the target", ()

        # Attribution: a malformed technique id is refused. A well-formed one
        # that differs from Wazuh's rule labels is only noted: the labels are
        # generic (a FIM rule says nothing of cron persistence), so a mismatch
        # is a question for the analyst, not a reason to drop the response.
        notes: tuple[str, ...] = ()
        technique = (action.mitre_technique or "").strip()
        if technique:
            if not _TECHNIQUE.match(technique):
                return "attribution", f"'{technique}' is not an ATT&CK technique id", ()
            labelled = set().union(*(event_techniques(events[i]) for i in ids))
            parent = technique.split(".")[0]
            if labelled and parent not in {t.split(".")[0] for t in labelled}:
                notes = (f"{technique} differs from the cited events' Wazuh labels "
                         f"({', '.join(sorted(labelled))})",)
        return "passed", "evidence verified", notes

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
        t = action.target
        if action.action in ("enrich", "escalate"):
            if not (_as_ip(t) or _HOSTNAME.match(t) or _FILE_HASH.match(t)):
                return False, (f"{action.action} target is not an address, "
                               "host name or file hash")
        if action.action == "isolate_host":
            if not (_as_ip(t) or _HOSTNAME.match(t)):
                return False, "isolate_host target is not an address or host name"
        if action.action == "disable_account":
            if not _USERNAME.match(t):
                return False, "disable_account target is not an account name"
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
