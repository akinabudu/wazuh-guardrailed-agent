"""
main.py - the FastAPI backend.

Bridges the Next.js dashboard to the agent. Endpoints:
  GET  /health                     liveness
  POST /investigate                start a hunt from an alert (kicks off the graph)
  GET  /queue                      proposals awaiting human approval
  GET  /proposals/{id}             one proposal with its evidence
  POST /proposals/{id}/approve     analyst approves -> resume graph -> execute
  POST /proposals/{id}/reject      analyst rejects  -> resume graph -> no action

The approve/reject endpoints resume the paused LangGraph run (which stopped at
interrupt()) using the persisted checkpoint. This is the human gate.

The Wazuh Dashboard plugin authenticates analysts and signs every backend call.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from hmac import compare_digest

import httpx
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from compat import configure_langgraph_warnings

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

configure_langgraph_warnings()

from langgraph.checkpoint.postgres import PostgresSaver  # noqa: E402
from langgraph.types import Command                       # noqa: E402
import agent as agent_mod                                 # noqa: E402
import db                                                 # noqa: E402

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


def _analyst(x_analyst: str | None, x_guardrail_token: str | None) -> str:
    expected = os.environ.get("APP_SECRET", "")
    if not expected or not x_guardrail_token or not compare_digest(
        expected, x_guardrail_token
    ):
        raise HTTPException(401, "invalid dashboard service credential")
    if not x_analyst or len(x_analyst) > 255:
        raise HTTPException(401, "missing analyst identity")
    return x_analyst


class Alert(BaseModel):
    agent_id: str = Field(default="000", pattern=r"^[0-9]{3,8}$")
    rule_id: str | None = None
    description: str | None = None


class Decision(BaseModel):
    justification: str | None = None
    second_approver: str | None = None


@app.get("/health")
def health():
    db.ping()
    agent_mod.check_dependencies()
    return {"status": "ok"}


@app.post("/investigate")
def investigate(
    alert: Alert,
    background_tasks: BackgroundTasks,
    x_analyst: str | None = Header(None),
    x_guardrail_token: str | None = Header(None),
):
    """Start a hunt. Runs until the graph ends or pauses at the human gate."""
    who = _analyst(x_analyst, x_guardrail_token)
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
def queue(
    x_analyst: str | None = Header(None),
    x_guardrail_token: str | None = Header(None),
):
    _analyst(x_analyst, x_guardrail_token)
    return {"pending": db.list_pending()}


@app.get("/proposals/{proposal_id}")
def proposal(
    proposal_id: int,
    x_analyst: str | None = Header(None),
    x_guardrail_token: str | None = Header(None),
):
    _analyst(x_analyst, x_guardrail_token)
    p = db.get_proposal(proposal_id)
    if not p:
        raise HTTPException(404, "not found")
    return p


@app.post("/proposals/{proposal_id}/approve")
def approve(
    proposal_id: int,
    body: Decision,
    x_analyst: str | None = Header(None),
    x_guardrail_token: str | None = Header(None),
    x_wazuh_token: str | None = Header(None),
):
    who = _analyst(x_analyst, x_guardrail_token)
    p = db.get_proposal(proposal_id)
    if not p:
        raise HTTPException(404, "not found")
    if p["status"] != "pending":
        raise HTTPException(409, f"proposal is '{p['status']}', not pending")
    if p["tier"] == "elevated":
        raise HTTPException(501, "two-person approval is not implemented")
    if not x_wazuh_token:
        raise HTTPException(401, "missing scoped Wazuh credential")

    db.record_decision(proposal_id, "approved", who,
                       body.justification, body.second_approver)
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
    return {"status": "approved"}


@app.post("/proposals/{proposal_id}/reject")
def reject(
    proposal_id: int,
    body: Decision,
    x_analyst: str | None = Header(None),
    x_guardrail_token: str | None = Header(None),
):
    who = _analyst(x_analyst, x_guardrail_token)
    p = db.get_proposal(proposal_id)
    if not p:
        raise HTTPException(404, "not found")
    db.record_decision(proposal_id, "rejected", who, body.justification)
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
