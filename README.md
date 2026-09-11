# Guardrailed Agentic AI Framework for Wazuh SIEM

An on-premise, human-supervised agentic AI for **context-aware threat hunting**
and **guardrailed incident remediation** in Wazuh. A locally hosted language
model *proposes* actions; a deterministic guardrail engine and a human analyst
*decide*. Nothing but optional notifications leaves your network.

> **Design principle:** the model is a *brain*, never a *body*. It proposes;
> deterministic code and a human authorise. A model fooled by prompt injection
> can still only produce a *proposal* - the guardrails and the human gate stand
> between any proposal and execution.

Tuned to run on a modest **16 GB RAM, CPU-only** host.

---

## What's in here

```
setup.sh                     one-shot on-prem setup (start here)
docker-compose.yml           app tier: postgres + backend + frontend (one command)
.env.example                 config template (setup.sh fills in secrets)
db/init/01_schema.sql        audit log (append-only), proposals, decisions
backend/
  guardrails.py              THE guardrail engine (deterministic, written in full)
  agent.py                   LangGraph loop: hunt -> guardrail -> tier router -> human/auto -> execute
  wazuh.py                   Wazuh indexer/manager client (query, verify, active response)
  notify.py                  Telegram alerts (NOTIFY-ONLY)
  db.py                      PostgreSQL access layer
  main.py                    FastAPI: queue, approve/reject, resume the graph
  Dockerfile                 backend image
frontend/starter/            approval page, API client, Dockerfile (copied into the app)
```

## Requirements

- Ubuntu 22.04 / 24.04, **16 GB RAM minimum**, CPU-only is fine (no GPU).
- ~25 GB free disk.
- A small 3.8B model runs on CPU at a few tokens/sec - fine, because the agent is
  human-supervised, not real-time.

## Quick start

```bash
./setup.sh
```

That provisions everything and brings the app tier up with `docker compose`.
When it finishes:

- Dashboard:  http://127.0.0.1:3000
- Backend:    http://127.0.0.1:8000/health
- Wazuh API:  https://127.0.0.1:55000

Everyday commands:

```bash
docker compose up -d --build      # start / rebuild the app tier
docker compose down               # stop the app tier
docker compose logs -f backend    # watch backend logs
cd wazuh-docker/single-node && docker compose down   # stop Wazuh when idle
```

## Running on 16 GB (read this)

16 GB is tight - Wazuh, a model, Postgres, and the app all want memory. The
setup script therefore:

- defaults to a small **3.8B** function-calling model (`phi4-mini`);
- caps the **Wazuh indexer heap** at 1 GB;
- **stops the Wazuh dashboard** container (the agent uses the API/indexer
  directly and does not need it - restart it when you want the UI);
- creates an **8 GB swap file** as a safety net.

Survival tips:

- **Stop Wazuh when idle** - it is the biggest memory user.
- Swap cushions spikes but is slow; avoid running a heavy hunt *and* full Wazuh
  load at the same time.
- Best comfort: put **Wazuh on a second cheap box** and point `WAZUH_URL` /
  `WAZUH_INDEXER_URL` in `.env` at it. This also mirrors a real deployment.
- Want a stronger model and have headroom? Set `OLLAMA_MODEL=phi4:14b` (or any
  8B+ tool-calling model) in `.env` and re-pull - but watch memory.

## The autonomy tiers

| Action           | Reversible | Tier      | Who approves                         |
|------------------|-----------|-----------|--------------------------------------|
| enrich           | yes (r/o) | auto      | policy (no change to environment)    |
| block_ip         | yes       | auto      | policy, rate-limited                 |
| kill_process     | yes       | human     | one analyst                          |
| isolate_host     | partial   | human     | one analyst + justification          |
| disable_account  | no        | elevated  | analyst + second approver            |

The **auto** lane is the one sharp edge - the only path where a successful
prompt injection could reach execution without a human. Keep it narrow
(reversible, rate-limited, low blast radius) and hammer it in your injection
tests.

## How the containers talk

- `postgres`, `backend`, `frontend` run via `docker-compose.yml`.
- The backend reaches host **Ollama** through `host.docker.internal` and joins
  Wazuh's private Docker network for manager and indexer access.
- **Wazuh** runs in its own official single-node compose (started by setup.sh),
  kept separate because it is a large stack.
- All service ports bind to `127.0.0.1` only. Use an SSH tunnel for access.

## Security notes

- Setup generates and synchronizes private Wazuh indexer and API credentials.
- Keep `.env` secret (git-ignored).
- Approvals happen **only** in the dashboard, inside the boundary - never over
  Telegram. Telegram is notify-only and its messages carry no telemetry.
- The auth in `main.py` is a **stub**. Wire real session/OAuth auth before any
  non-lab use - approving an action is privileged.

## Honest scope

A working **skeleton**, not a finished product. Real and complete: the guardrail
engine, the DB schema + append-only audit log, the graph wiring, the tier
routing, the notify path, checkpoint resume, and the container setup.
Intentionally minimal / `TODO`: the LLM prompting and hunting depth in
`agent.py`, real authentication, and the fuller dashboard panels. Those are
what you build out and evaluate for the thesis.
