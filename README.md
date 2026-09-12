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
docker-compose.yml           app tier: postgres + backend
.env.example                 config template (setup.sh fills in secrets)
db/init/01_schema.sql        audit log (append-only), proposals, decisions
dashboard-plugin/            native Wazuh 4.9.2 dashboard application
backend/
  guardrails.py              THE guardrail engine (deterministic, written in full)
  agent.py                   LangGraph loop: hunt -> guardrail -> tier router -> human/auto -> execute
  wazuh.py                   Wazuh indexer/manager client (query, verify, active response)
  notify.py                  Telegram alerts (NOTIFY-ONLY)
  db.py                      PostgreSQL access layer
  main.py                    FastAPI: queue, approve/reject, resume the graph
  Dockerfile                 backend image
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

- Dashboard:  https://127.0.0.1, then open **Guardrailed AI**
- Backend:    http://127.0.0.1:8000/health
- Wazuh API:  https://127.0.0.1:55000

For a remote host, forward the dashboard over SSH:

```bash
ssh -N -L 8443:127.0.0.1:443 wazuh-lab
```

Then open `https://127.0.0.1:8443/app/wazuhGuardrail` and accept the lab's
self-signed certificate. The **Guardrailed AI** entry appears in the Security
section of the dashboard sidebar with a security-signal icon.

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
- installs the agent as a native Wazuh Dashboard plugin;
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
| block_ip         | yes       | human     | one analyst                          |
| kill_process     | yes       | human     | one analyst                          |
| isolate_host     | partial   | human     | one analyst + justification          |
| disable_account  | no        | elevated  | analyst + second approver            |

The **auto** lane is the one sharp edge - the only path where a successful
prompt injection could reach execution without a human. Keep it narrow
(reversible, rate-limited, low blast radius) and hammer it in your injection
tests.

## How the containers talk

- `postgres` and `backend` run via `docker-compose.yml`.
- The Wazuh Dashboard plugin supplies the analyst interface and authenticated
  server-side proxy.
- The backend reaches host **Ollama** on Docker's private bridge and joins
  Wazuh's private Docker network for manager and indexer access.
- **Wazuh** runs in its own official single-node compose (started by setup.sh),
  kept separate because it is a large stack.
- All service ports bind to `127.0.0.1` only. Use an SSH tunnel for access.

## Installing or updating only the dashboard plugin

After you install the full stack once, update the dashboard plugin with one
command:

```bash
./dashboard-plugin/install.sh
```

The installer builds the persistent dashboard image, recreates only the Wazuh
Dashboard container, waits for it to become ready, and verifies that
the plugin list contains `wazuhGuardrail`. It leaves the manager, indexer,
PostgreSQL, and backend running. To compile changed plugin source with the
pinned Wazuh SDK before installation, run:

```bash
./dashboard-plugin/install.sh --rebuild
```

Use `./setup.sh` instead for a first installation because it also provisions
Wazuh, Ollama, PostgreSQL, credentials, and the backend.

## Building the dashboard plugin

The committed plugin archive targets Wazuh 4.9.2 and OpenSearch Dashboards
2.13.0. Rebuild it after changing `dashboard-plugin/public` or
`dashboard-plugin/server`:

```bash
./dashboard-plugin/build.sh
```

The `--rebuild` installer option copies the resulting archive into place for
you. A Wazuh upgrade requires rebuilding and testing the plugin against that
release's matching dashboard SDK.

## Security notes

- Setup generates and synchronizes private Wazuh indexer and API credentials.
- Keep `.env` secret (git-ignored).
- Approvals happen **only** in the dashboard, inside the boundary - never over
  Telegram. Telegram is notify-only and its messages carry no telemetry.
- The plugin obtains the current Wazuh identity and checks agent access before
  investigation or review. The backend accepts only plugin-signed calls.
- Approved active responses use the analyst's short-lived Wazuh token, so
  Wazuh enforces `active-response:command` on the target agent or group.
- Every mutating action requires a human. Elevated actions fail closed until a
  separate two-person approval flow is implemented.

## Honest scope

A working **skeleton**, not a finished product. Real and complete: the guardrail
engine, the DB schema + append-only audit log, the graph wiring, the tier
routing, the notify path, checkpoint resume, and the container setup.
Intentionally minimal / `TODO`: the LLM prompting and hunting depth in
`agent.py`, a two-person elevated-action flow, and fuller dashboard panels.
Those are what you build out and evaluate for the thesis.
