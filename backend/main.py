"""
main.py - the FastAPI backend.

Bridges the Wazuh Dashboard plugin to the agent. Endpoints:
  GET  /health                     liveness
  POST /investigate                start a hunt from an alert (kicks off the graph)
  GET  /queue                      proposals awaiting human approval
  GET  /proposals/{id}             one proposal with its evidence
  POST /proposals/{id}/approve     analyst approves -> resume graph -> execute
  POST /proposals/{id}/reject      analyst rejects  -> resume graph -> no action

The approve/reject endpoints resume the paused LangGraph run (which stopped at
interrupt()) using the persisted checkpoint. This is the human gate.

The Wazuh Dashboard plugin authenticates analysts and signs every backend call
(HMAC over timestamp, nonce, method, path, analyst and body; see caller()).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from hmac import compare_digest

import httpx
from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from compat import configure_langgraph_warnings

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

configure_langgraph_warnings()

from langgraph.checkpoint.postgres import PostgresSaver  # noqa: E402
from langgraph.types import Command                       # noqa: E402
import agent as agent_mod                                 # noqa: E402
import db                                                 # noqa: E402
from wazuh import ActiveResponseFailed                    # noqa: E402
from guardrails import parse_time                         # noqa: E402

_checkpointer: PostgresSaver | None = None
_graph = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _checkpointer, _graph
    with PostgresSaver.from_conn_string(os.environ["DATABASE_URL"]) as checkpointer:
        checkpointer.setup()
        db.ensure_schema()
        _checkpointer = checkpointer
        _graph = agent_mod.build_graph(checkpointer=checkpointer)
        try:
            yield
        finally:
            _graph = None
            _checkpointer = None


app = FastAPI(title="Guardrailed Agentic AI - backend", lifespan=lifespan)


_SKEW_S = 60
_seen_nonces: dict[str, float] = {}
_nonce_lock = threading.Lock()


def _signed_message(timestamp: str, nonce: str, method: str, path: str,
                    analyst: str, body: bytes) -> bytes:
    """What the dashboard plugin signs (dashboard-plugin/server/plugin.ts)."""
    return "\n".join([timestamp, nonce, method.upper(), path, analyst,
                      hashlib.sha256(body).hexdigest()]).encode()


def _check_nonce(nonce: str, now: float) -> bool:
    """A nonce may be used once inside the skew window; a replay is refused."""
    with _nonce_lock:
        for n, seen in list(_seen_nonces.items()):
            if seen < now - 2 * _SKEW_S:
                del _seen_nonces[n]
        if nonce in _seen_nonces:
            return False
        _seen_nonces[nonce] = now
        return True


def verify_signature(method: str, path: str, body: bytes, analyst: str | None,
                     timestamp: str | None, nonce: str | None,
                     signature: str | None) -> str:
    """Authenticate the dashboard plugin's server side and return the analyst.

    Each call carries an HMAC-SHA256 over its timestamp, a one-time nonce, the
    method, the path, the analyst name and the body hash, keyed with the
    shared secret. A captured request cannot be replayed (nonce), reused later
    (timestamp), redirected to another endpoint or proposal (path), or altered
    (body hash). What this does not protect against: anyone holding the secret
    itself, i.e. a compromised dashboard container, can sign for any analyst.
    """
    secret = os.environ.get("APP_SECRET", "")
    if not secret or not (timestamp and nonce and signature):
        raise HTTPException(401, "invalid dashboard service credential")
    if not analyst or len(analyst) > 255:
        raise HTTPException(401, "missing analyst identity")
    try:
        ts = float(timestamp)
    except ValueError:
        raise HTTPException(401, "invalid dashboard service credential") from None
    now = time.time()
    if abs(now - ts) > _SKEW_S or not (8 <= len(nonce) <= 128):
        raise HTTPException(401, "invalid dashboard service credential")
    expected = hmac.new(secret.encode(), _signed_message(
        timestamp, nonce, method, path, analyst, body), hashlib.sha256).hexdigest()
    if not compare_digest(expected, signature):
        raise HTTPException(401, "invalid dashboard service credential")
    if not _check_nonce(nonce, now):
        raise HTTPException(401, "replayed request")
    return analyst


async def caller(
    request: Request,
    x_analyst: str | None = Header(None),
    x_guardrail_timestamp: str | None = Header(None),
    x_guardrail_nonce: str | None = Header(None),
    x_guardrail_signature: str | None = Header(None),
) -> str:
    return verify_signature(request.method, request.url.path, await request.body(),
                            x_analyst, x_guardrail_timestamp, x_guardrail_nonce,
                            x_guardrail_signature)


class Alert(BaseModel):
    agent_id: str = Field(default="000", pattern=r"^[0-9]{3,8}$")
    # The indexer id of the alert that triggered the investigation, if known.
    alert_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_\-]{1,128}$")
    rule_id: str | None = Field(default=None, pattern=r"^[0-9]{1,8}$")
    description: str | None = Field(default=None, max_length=2000)
    # ISO 8601 lower bound for the events the hunt retrieves.
    since: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}T[0-9:.+\-Z]+$")


class Decision(BaseModel):
    justification: str | None = Field(default=None, max_length=2000)


PROPOSAL_TTL_S = int(os.environ.get("PROPOSAL_TTL_S", "86400"))


@app.get("/health")
def health():
    db.ping()
    agent_mod.check_dependencies()
    return {"status": "ok"}


@app.post("/investigate")
def investigate(
    alert: Alert,
    background_tasks: BackgroundTasks,
    who: str = Depends(caller),
):
    """Start a hunt. Runs until the graph ends or pauses at the human gate."""
    thread_id = f"alert-{alert.agent_id}-{os.urandom(4).hex()}"
    thread = {"configurable": {"thread_id": thread_id}}
    state = {
        "alert": alert.model_dump(),
        "thread_id": thread_id,
        "requested_by": who,
    }
    background_tasks.add_task(_graph.invoke, state, config=thread)
    return {"status": "started", "thread": thread_id}


@app.get("/queue")
def queue(who: str = Depends(caller)):
    return {"pending": db.list_pending()}


@app.get("/proposals/{proposal_id}")
def proposal(proposal_id: int, who: str = Depends(caller)):
    p = db.get_proposal(proposal_id)
    if not p:
        raise HTTPException(404, "not found")
    return p


def _pending_or_409(proposal_id: int) -> dict:
    p = db.get_proposal(proposal_id)
    if not p:
        raise HTTPException(404, "not found")
    if p["status"] != "pending":
        raise HTTPException(409, f"proposal is '{p['status']}', not pending")
    created = parse_time(p.get("created_at"))
    if created and (datetime.now(timezone.utc) - created).total_seconds() > PROPOSAL_TTL_S:
        raise HTTPException(409, "proposal is stale; start a new investigation")
    return p


@app.post("/proposals/{proposal_id}/approve")
def approve(
    proposal_id: int,
    body: Decision,
    who: str = Depends(caller),
    x_wazuh_token: str | None = Header(None),
):
    p = _pending_or_409(proposal_id)
    if p["tier"] == "elevated":
        # The second-approver route does not exist, so this fails closed.
        db.audit("approval_refused", proposal_id,
                 payload={"by": who, "reason": "elevated tier needs a second approver"})
        raise HTTPException(501, "two-person approval is not implemented")
    if p["tier"] != "human":
        raise HTTPException(409, f"tier '{p['tier']}' is not decided by an analyst")
    if not x_wazuh_token:
        raise HTTPException(401, "missing scoped Wazuh credential")
    if not db.claim_decision(proposal_id, "approved", who, body.justification):
        raise HTTPException(409, "proposal was already decided")
    db.audit("decision", proposal_id, payload={"decision": "approved", "by": who})

    try:
        _resume(proposal_id, "approved", x_wazuh_token)
    except httpx.HTTPStatusError as exc:
        db.set_status(proposal_id, "execution_failed")
        status = exc.response.status_code
        db.audit("execution_denied", proposal_id, payload={"status": status})
        raise HTTPException(
            403 if status in (401, 403) else 502,
            "Wazuh rejected the active response",
        ) from exc
    except httpx.HTTPError as exc:
        db.set_status(proposal_id, "execution_failed")
        db.audit("execution_failed", proposal_id, payload={"error": type(exc).__name__})
        raise HTTPException(504, "Wazuh did not answer") from exc
    except ActiveResponseFailed as exc:
        db.set_status(proposal_id, "execution_failed")
        db.audit("execution_failed", proposal_id, payload={"failed_items": exc.args[0]})
        raise HTTPException(502, "Wazuh did not run the active response") from exc
    return {"status": "approved"}


@app.post("/proposals/{proposal_id}/reject")
def reject(
    proposal_id: int,
    body: Decision,
    who: str = Depends(caller),
):
    _pending_or_409(proposal_id)
    if not db.claim_decision(proposal_id, "rejected", who, body.justification):
        raise HTTPException(409, "proposal was already decided")
    db.audit("decision", proposal_id, payload={"decision": "rejected", "by": who})
    _resume(proposal_id, "rejected")
    return {"status": "rejected"}


def _resume(proposal_id: int, decision: str, wazuh_token: str | None = None) -> None:
    """Resume the paused graph run for this proposal with the analyst decision."""
    # Map the proposal back to its thread. In this skeleton we store the thread
    # id alongside the proposal in production; shown here as the lookup point.
    thread_id = _thread_for(proposal_id)
    if wazuh_token:
        agent_mod.authorize_execution(thread_id, wazuh_token)
    try:
        _graph.invoke(Command(resume=decision),
                      config={"configurable": {"thread_id": thread_id}})
    finally:
        agent_mod.revoke_execution(thread_id)


def _thread_for(proposal_id: int) -> str:
    thread_id = db.get_thread_id(proposal_id)
    if not thread_id:
        raise HTTPException(409, "proposal has no resumable graph thread")
    return thread_id
