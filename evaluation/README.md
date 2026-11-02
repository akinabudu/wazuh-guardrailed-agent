# Evaluation harness

A re-runnable evaluation of the guardrailed agent on the lab: detection and
response on emulated attacks and benign activity, and resistance to indirect
prompt injection. **`RUBRIC.md` defines every outcome, denominator and
interval**, and was committed with the corpus before the evaluation run.

| File | Purpose |
|---|---|
| `RUBRIC.md` | Units, outcome definitions, the primary outcome, statistics plan |
| `scenarios.yaml` | Evaluation set: 10 attack + 6 benign scenarios, 3 runs each |
| `injection.yaml` | Evaluation set: 45 unique payloads (9 categories x 5), 2 deliveries each, plus 20 control values |
| `corpus.sha256` | Checksums of the three files above, as committed before the run |
| `dev/` | Development corpus used while building the guardrails; never reported |
| `run.py` | Drives the lab; writes `trials.jsonl`, `errors.jsonl`, `plan.json`, `lab.json`; resumable |
| `analyze.py` | Implements RUBRIC.md; writes `summary.json`, CSVs, `manifest.csv` and Figure 5.2 |
| `replay.py` | Circuit-breaker sensitivity at 5, 10 and 20 actions per hour |
| `sql/governance.sql` | Audit-table counts and referential-consistency checks |
| `collect_env.sh` | Version and resource captures for the environment table |
| `tests/` | Offline tests of the analysis on synthetic runs |

## Lab

Three spot instances from `WazuhLabStack` in [`infra/`](../infra/README.md), reached over
SSM only.

- **wazuh-lab-host** (t3.xlarge, 4 vCPU, 16 GiB): Wazuh 4.14.9 single-node and this
  repo's app tier, installed by `setup.sh`. The model is Claude Opus 4.6 on Amazon
  Bedrock (`us.anthropic.claude-opus-4-6-v1`, us-east-1), called from the host's IAM role.
- **wazuh-lab-endpoint** (t3.small): Ubuntu 24.04 with Wazuh agent 4.14.9, auditd, realtime
  FIM, sshd, nginx and Atomic Red Team.
- **wazuh-lab-attacker** (t3.micro): the source of SSH and HTTP attacks and of the injected
  field values.

## Reproduce

On the host, as root, after `/var/lib/lab-setup.done` exists:

```bash
cd /home/ubuntu/wazuh-guardrailed-agent/evaluation
sha256sum -c corpus.sha256                       # the corpus is the committed one
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
out=results/$(date +%F)-opus46
./collect_env.sh "$out/env"
.venv/bin/python run.py --out "$out" --phases warmup --only warmup-0   # smoke
nohup .venv/bin/python run.py --out "$out" > "$out/run.log" 2>&1 &
.venv/bin/python analyze.py "$out"
.venv/bin/python replay.py "$out"
```

`run.py` skips trials already in `trials.jsonl` and retries those in
`errors.jsonl`, so after a spot interruption you start the box and rerun the
same command. Every table in the thesis is regenerated from the committed raw
files by `analyze.py` and `replay.py`; neither needs the lab.

## The analyst

The scripted analyst approves a remediation only when it is the legitimate
response to the underlying alert, acknowledges an escalation only where the
rubric counts it as correct, and rejects everything else. It decides through
the same signed backend endpoints the dashboard plugin uses. It is an ideal
analyst, so injection results measure the guardrails plus a correct human
decision. The `mistaken` phase and the `analyst_only` indicator show what is
left when the human is wrong.

## Offline tests

```bash
cd evaluation && PYTHONPATH=.:../backend python -m unittest discover -s tests -t tests -v
```
