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

NOTE: authentication is stubbed with a header for clarity. Wire real auth
(session / OAuth) before any non-lab use - the approval action is privileged.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

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
app.add_middleware(
    CORSMiddleware, allow_origins=["http://127.0.0.1:3000", "http://localhost:3000"],
    allow_methods=["*"], allow_headers=["*"],
)


def _analyst(x_analyst: str | None) -> str:
    # Placeholder auth. Replace with real session/OAuth verification.
    if not x_analyst:
        raise HTTPException(401, "missing analyst identity")
    return x_analyst


class Alert(BaseModel):
    agent_id: str = "000"
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
def investigate(alert: Alert, background_tasks: BackgroundTasks):
    """Start a hunt. Runs until the graph ends or pauses at the human gate."""
    thread_id = f"alert-{alert.agent_id}-{os.urandom(4).hex()}"
    thread = {"configurable": {"thread_id": thread_id}}
    state = {"alert": alert.model_dump(), "thread_id": thread_id}
    background_tasks.add_task(_graph.invoke, state, config=thread)
    return {"status": "started", "thread": thread_id}


@app.get("/queue")
def queue():
    return {"pending": db.list_pending()}


@app.get("/proposals/{proposal_id}")
def proposal(proposal_id: int):
    p = db.get_proposal(proposal_id)
    if not p:
        raise HTTPException(404, "not found")
    return p


@app.post("/proposals/{proposal_id}/approve")
def approve(proposal_id: int, body: Decision, x_analyst: str | None = Header(None)):
    who = _analyst(x_analyst)
    p = db.get_proposal(proposal_id)
    if not p:
        raise HTTPException(404, "not found")
    if p["status"] != "pending":
        raise HTTPException(409, f"proposal is '{p['status']}', not pending")
    if p["tier"] == "elevated" and not body.second_approver:
        raise HTTPException(422, "elevated actions require a second approver")

    db.record_decision(proposal_id, "approved", who,
                       body.justification, body.second_approver)
    _resume(proposal_id, "approved")
    return {"status": "approved"}


@app.post("/proposals/{proposal_id}/reject")
def reject(proposal_id: int, body: Decision, x_analyst: str | None = Header(None)):
    who = _analyst(x_analyst)
    p = db.get_proposal(proposal_id)
    if not p:
        raise HTTPException(404, "not found")
    db.record_decision(proposal_id, "rejected", who, body.justification)
    _resume(proposal_id, "rejected")
    return {"status": "rejected"}


def _resume(proposal_id: int, decision: str) -> None:
    """Resume the paused graph run for this proposal with the analyst decision."""
    # Map the proposal back to its thread. In this skeleton we store the thread
    # id alongside the proposal in production; shown here as the lookup point.
    thread_id = _thread_for(proposal_id)
    _graph.invoke(Command(resume=decision),
                  config={"configurable": {"thread_id": thread_id}})


def _thread_for(proposal_id: int) -> str:
    thread_id = db.get_thread_id(proposal_id)
    if not thread_id:
        raise HTTPException(409, "proposal has no resumable graph thread")
    return thread_id
