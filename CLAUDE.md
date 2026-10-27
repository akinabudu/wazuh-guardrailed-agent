# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Where this project actually runs

Development happens on Windows, but **nothing in this project runs locally**. There is
no Docker daemon and no `wazuh-docker/` directory on the dev machine. The live stack runs
on an AWS spot instance:

| | |
|---|---|
| Name | `wazuh-lab-host` (CDK `WazuhLabStack` in `orglobal-website-cdk`) |
| Instance ID | `i-0e9ff5e3f6c91e4a1` |
| Type | t3.xlarge (4 vCPU, ~15 GB usable RAM) |
| OS | Ubuntu 24.04 |
| Region | `us-east-1` |
| AWS CLI profile | **`orglobal`** |
| Access | **SSM** (Session Manager), not SSH |
| Repo path | `/home/ubuntu/wazuh-guardrailed-agent` |

It is a **spot** instance, so it can be reclaimed; the public IP changes across restarts.
Address it by instance ID, never by a cached IP.

The host is one of three boxes created by `WazuhLabStack` (`orglobal-website-cdk`,
`lib/wazuh-lab-stack.ts`); the others are `wazuh-lab-endpoint` (`i-099188132492f3aa8`, the
monitored agent) and `wazuh-lab-attacker` (`i-08dc63265bcfde285`). The previous host,
`orglobal-sandbox` (`i-028474aa41eca073b`), no longer exists. Before `cdk destroy`, cancel the
lab's persistent spot requests or they relaunch the instances (see the stack's header comment).

**Some `cdk deploy WazuhLabStack` changes replace all three boxes, wiping their disks.** On
2026-10-25 an IAM-only deploy did exactly that: the AMI was resolved from Canonical's "current"
SSM parameter at deploy time, and `cdk diff` did not show it. The AMI is now pinned
(`ubuntuAmi` in `config.ts`); changing it, `hostVolumeGb`, or user data still rebuilds the lab.
Before deploying, create a change set with `--no-execute` and check its `Replacement` column,
and copy results off the host first. The live host volume is 120 GB (grown in place).

Do not confuse it with `ajaeq-prod-wazuh` (`i-0b8204e773abcb93a`, profile `ajaeq-cloud`).
That is a separate, unrelated instance — leave it alone.

### Running a command on it

Access is via `aws ssm send-command`; the SSM agent is registered and Online. There is a
helper that wraps the send / poll / fetch-output cycle:

```bash
./scripts/ssm.sh 'cd /home/ubuntu/wazuh-guardrailed-agent && git status -sb'
```

Raw equivalent, if the helper is unavailable:

```bash
aws ssm send-command --profile orglobal --region us-east-1 \
  --instance-ids i-0e9ff5e3f6c91e4a1 \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["<command>"]' \
  --query Command.CommandId --output text
# then poll:
aws ssm get-command-invocation --profile orglobal --region us-east-1 \
  --command-id <id> --instance-id i-0e9ff5e3f6c91e4a1 \
  --query StandardOutputContent --output text
```

Commands run as `root` in `/` — always `cd` to the repo first. Long builds exceed the
default SSM timeout, so pass `--timeout-seconds` and poll rather than assuming completion.

**`install.sh` refuses to run as root** (`install.sh:34`, "Run this installer as a normal
user with Docker access"), so it must be dropped to the `ubuntu` user:

```bash
./scripts/ssm.sh --timeout 1800   "sudo -iu ubuntu bash -lc 'cd /home/ubuntu/wazuh-guardrailed-agent && ./dashboard-plugin/install.sh --rebuild'"
```

**These are production actions.** Reads against this host may prompt for permission, and
anything that recreates a container interrupts a live stack. Confirm with the user before
deploying; do not route around a denial.

### Checking the stack

```bash
./scripts/ssm.sh 'docker ps --format "{{.Names}}\t{{.Status}}"'
```

Expect five containers: `single-node-wazuh.{dashboard,manager,indexer}-1`,
`guardrail-backend`, `guardrail-postgres`.

## The dashboard plugin is a committed binary

`dashboard-plugin/wazuhGuardrail-2.13.0.zip` is **tracked in git** and is what actually
gets deployed — `install.sh` reads the archive, not `dashboard-plugin/public/*`.

Editing plugin source without rebuilding leaves the committed artifact stale: git will
show the fix while a deploy still ships the old UI. Any commit touching
`dashboard-plugin/public/` or `dashboard-plugin/server/` must include the regenerated zip.

```bash
./dashboard-plugin/install.sh --rebuild   # on the instance: build + deploy
./dashboard-plugin/build.sh               # build only; needs just a Docker daemon
```

`build.sh` compiles inside `quay.io/wazuh/osd-dev:2.13.0` and needs only Docker.
`install.sh` additionally needs the provisioned Wazuh stack at `wazuh-docker/single-node`,
and recreates the `wazuh.dashboard` container. The plugin is pinned to Wazuh 4.9.2 /
OpenSearch Dashboards 2.13.0; a Wazuh upgrade means rebuilding against that release's SDK.

## Tests

Stdlib `unittest`, with environment stubbed at import — no live database needed:

```bash
cd backend && PYTHONPATH=. python -m unittest discover -s tests -t tests -v
```

42 tests across `test_agent`, `test_guardrails`, `test_main`, `test_wazuh`. There is no
`tests/__init__.py`, so `-t tests` is required or discovery fails with
"Start directory is not importable".

Dependencies are not installed on the dev machine by default; `backend/.venv/` is
gitignored and is the expected place for them.

## Architecture constraints worth preserving

- **The model proposes; deterministic code and a human decide.** Guardrails in
  `backend/guardrails.py` are the enforcement point — keep them deterministic.
- **The browser never reaches the backend.** The dashboard plugin's *server* side proxies
  every call over the private Docker network, signed with `WAZUH_GUARDRAIL_SHARED_SECRET`
  and checked in `backend/main.py`. There is deliberately no CORS middleware — do not add
  one, and do not expose the backend to the browser.
- **Analyst identity comes from the real Wazuh session**, resolved server-side in
  `dashboard-plugin/server/plugin.ts`. Never reintroduce a client-supplied analyst name.
- All service ports bind to `127.0.0.1` only; reach them through an SSH tunnel.
