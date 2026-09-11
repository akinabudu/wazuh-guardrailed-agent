"""
db.py - PostgreSQL access layer.

Wraps the tables from db/init/01_schema.sql:
  - insert_proposal / set_status
  - record_decision
  - audit            (append-only)
  - list_pending     (for the dashboard queue)

A synchronous psycopg connection pool keeps this simple; the API is low-traffic
(one analyst reviewing proposals), so this is more than fast enough.
"""

from __future__ import annotations

import json
import os
from typing import Any

from psycopg_pool import ConnectionPool

_pool: ConnectionPool | None = None


def pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(os.environ["DATABASE_URL"], min_size=1, max_size=5)
    return _pool


# ---------------------------------------------------------------------------
def ensure_schema() -> None:
    with pool().connection() as conn:
        conn.execute(
            "ALTER TABLE proposals ADD COLUMN IF NOT EXISTS thread_id TEXT"
        )


# ---------------------------------------------------------------------------
def ping() -> None:
    with pool().connection() as conn:
        conn.execute("SELECT 1").fetchone()


# ---------------------------------------------------------------------------
def insert_proposal(action: dict, reasoning: str, evidence: list[str],
                    tier: str, guardrail_ok: bool, guardrail_reason: str,
                    thread_id: str) -> int:
    status = "pending" if (guardrail_ok and tier != "auto") else \
             ("auto_approved" if (guardrail_ok and tier == "auto") else "blocked")
    with pool().connection() as conn:
        row = conn.execute(
            """INSERT INTO proposals
                 (action, reasoning, evidence, risk_tier, guardrail_ok,
                  guardrail_reason, status, thread_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (json.dumps(action), reasoning, json.dumps(evidence), tier,
             guardrail_ok, guardrail_reason, status, thread_id),
        ).fetchone()
    pid = row[0]
    audit("proposal", pid, payload={"action": action, "tier": tier,
                                    "guardrail_ok": guardrail_ok})
    return pid


def set_status(proposal_id: int, status: str) -> None:
    with pool().connection() as conn:
        conn.execute("UPDATE proposals SET status=%s WHERE id=%s",
                     (status, proposal_id))


def record_decision(proposal_id: int, decision: str, decided_by: str,
                    justification: str | None = None,
                    second_approver: str | None = None) -> None:
    with pool().connection() as conn:
        conn.execute(
            """INSERT INTO decisions
                 (proposal_id, decision, decided_by, justification, second_approver)
               VALUES (%s,%s,%s,%s,%s)""",
            (proposal_id, decision, decided_by, justification, second_approver),
        )
        new_status = {"approved": "approved", "rejected": "rejected",
                      "auto_approved": "auto_approved"}[decision]
        conn.execute("UPDATE proposals SET status=%s WHERE id=%s",
                     (new_status, proposal_id))


def audit(event_type: str, proposal_id: int | None = None,
          autonomous: bool = False, payload: dict[str, Any] | None = None) -> None:
    with pool().connection() as conn:
        conn.execute(
            """INSERT INTO audit_log (event_type, proposal_id, autonomous, payload)
               VALUES (%s,%s,%s,%s)""",
            (event_type, proposal_id, autonomous, json.dumps(payload or {})),
        )


def list_pending() -> list[dict]:
    with pool().connection() as conn:
        rows = conn.execute(
            """SELECT id, created_at, action, reasoning, evidence, risk_tier
                 FROM proposals WHERE status='pending' ORDER BY created_at""").fetchall()
    return [
        {"id": r[0], "created_at": r[1].isoformat(), "action": r[2],
         "reasoning": r[3], "evidence": r[4], "tier": r[5]}
        for r in rows
    ]


def get_proposal(proposal_id: int) -> dict | None:
    with pool().connection() as conn:
        r = conn.execute(
            """SELECT id, status, action, reasoning, evidence, risk_tier
                 FROM proposals WHERE id=%s""", (proposal_id,)).fetchone()
    if not r:
        return None
    return {"id": r[0], "status": r[1], "action": r[2],
            "reasoning": r[3], "evidence": r[4], "tier": r[5]}


def get_thread_id(proposal_id: int) -> str | None:
    with pool().connection() as conn:
        row = conn.execute(
            "SELECT thread_id FROM proposals WHERE id=%s", (proposal_id,)
        ).fetchone()
    return row[0] if row else None
