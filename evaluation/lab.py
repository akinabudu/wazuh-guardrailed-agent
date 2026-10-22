"""
lab.py - plumbing for the evaluation harness. Runs ON the lab host.

  - ssm()        run a shell command on the endpoint or attacker box over SSM
  - Indexer      read alerts from the Wazuh indexer
  - Backend      call the guardrail backend exactly as the dashboard plugin does
  - psql()       read proposals, decisions and audit_log rows

Everything reads its secrets from the repo's .env, the same file the stack uses.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPO = Path(__file__).resolve().parent.parent
REGION = os.environ.get("AWS_REGION", "us-east-1")


def load_env(path: Path = REPO / ".env") -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():   # analysis can run off-box, without secrets
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key.strip()] = value.split("#", 1)[0].strip()
    return env


ENV = load_env()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00").replace("+0000", "+00:00"))


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


# ---------------------------------------------------------------------------
# SSM to the other lab boxes
# ---------------------------------------------------------------------------
def _aws(*args: str) -> dict:
    out = subprocess.run(
        ["aws", "--region", REGION, "--output", "json", *args],
        check=True, capture_output=True, text=True,
    ).stdout
    return json.loads(out) if out.strip() else {}


def instance(name: str) -> dict:
    """The running lab box tagged Name=wazuh-lab-<name>."""
    found = _aws(
        "ec2", "describe-instances",
        "--filters", f"Name=tag:Name,Values=wazuh-lab-{name}",
        "Name=instance-state-name,Values=running",
    )
    boxes = [i for r in found["Reservations"] for i in r["Instances"]]
    if len(boxes) != 1:
        raise RuntimeError(f"expected one running wazuh-lab-{name}, found {len(boxes)}")
    return {"id": boxes[0]["InstanceId"], "ip": boxes[0]["PrivateIpAddress"]}


def ssm(instance_id: str, command: str, timeout: int = 900) -> tuple[str, str, str]:
    """Run `command` as root; return (status, stdout, stderr)."""
    sent = _aws(
        "ssm", "send-command", "--instance-ids", instance_id,
        "--document-name", "AWS-RunShellScript",
        "--timeout-seconds", str(timeout),
        "--parameters", json.dumps({"commands": [command],
                                    "executionTimeout": [str(timeout)]}),
    )
    command_id = sent["Command"]["CommandId"]
    deadline = time.time() + timeout + 60
    while time.time() < deadline:
        time.sleep(2)
        try:
            inv = _aws("ssm", "get-command-invocation",
                       "--command-id", command_id, "--instance-id", instance_id)
        except subprocess.CalledProcessError:
            continue   # not registered yet
        if inv["Status"] not in ("Pending", "InProgress", "Delayed"):
            return (inv["Status"], inv.get("StandardOutputContent", ""),
                    inv.get("StandardErrorContent", ""))
    return "TimedOut", "", ""


# ---------------------------------------------------------------------------
# Wazuh indexer and manager
# ---------------------------------------------------------------------------
class Indexer:
    def __init__(self) -> None:
        self.url = "https://127.0.0.1:9200"
        self.auth = (ENV["INDEXER_USER"], ENV["INDEXER_PASSWORD"])

    def search(self, query: dict, index: str = "wazuh-alerts-*") -> list[dict]:
        r = requests.post(f"{self.url}/{index}/_search", json=query,
                          auth=self.auth, verify=False, timeout=30,
                          params={"allow_no_indices": "true"})
        r.raise_for_status()
        hits = r.json()["hits"]["hits"]
        return [{**h["_source"], "_id": h["_id"]} for h in hits]

    def alerts(self, agent_id: str, since: str, until: str | None = None,
               rule_ids: list[str] | None = None, size: int = 500) -> list[dict]:
        bounds = {"gte": since, **({"lte": until} if until else {})}
        filters: list[dict] = [{"term": {"agent.id": agent_id}},
                               {"range": {"timestamp": bounds}}]
        if rule_ids:
            filters.append({"terms": {"rule.id": rule_ids}})
        return self.search({"query": {"bool": {"filter": filters}},
                            "sort": [{"timestamp": {"order": "asc"}}], "size": size})


def manager_token() -> str:
    """A real Wazuh API token: what the plugin forwards for the analyst."""
    r = requests.post("https://127.0.0.1:55000/security/user/authenticate",
                      params={"raw": "true"}, verify=False, timeout=30,
                      auth=(ENV["WAZUH_API_USER"], ENV["WAZUH_API_PASSWORD"]))
    r.raise_for_status()
    return r.text.strip()


def agent_id(name: str) -> str:
    r = requests.get("https://127.0.0.1:55000/agents", params={"name": name},
                     headers={"Authorization": f"Bearer {manager_token()}"},
                     verify=False, timeout=30)
    r.raise_for_status()
    items = r.json()["data"]["affected_items"]
    if not items:
        raise RuntimeError(f"agent {name} is not enrolled")
    return items[0]["id"]


# ---------------------------------------------------------------------------
# The guardrail backend, called with the plugin's service credential
# ---------------------------------------------------------------------------
class Backend:
    def __init__(self, analyst: str = "scripted-analyst") -> None:
        self.url = "http://127.0.0.1:8000"
        self.headers = {"X-Guardrail-Token": ENV["APP_SECRET"], "X-Analyst": analyst}

    def investigate(self, alert: dict) -> str:
        r = requests.post(f"{self.url}/investigate", json=alert,
                          headers=self.headers, timeout=30)
        r.raise_for_status()
        return r.json()["thread"]

    def decide(self, proposal_id: int, decision: str, justification: str) -> dict:
        headers = dict(self.headers)
        if decision == "approve":
            headers["X-Wazuh-Token"] = manager_token()
        r = requests.post(f"{self.url}/proposals/{proposal_id}/{decision}",
                          json={"justification": justification},
                          headers=headers, timeout=600)
        return {"http_status": r.status_code, "body": r.text[:500]}


# ---------------------------------------------------------------------------
# PostgreSQL (read-only queries through the container)
# ---------------------------------------------------------------------------
def psql(sql: str) -> list[dict]:
    """Run a SELECT and return rows as dicts."""
    wrapped = f"SELECT row_to_json(t) FROM ({sql}) t"
    out = subprocess.run(
        ["docker", "exec", "guardrail-postgres", "psql", "-At",
         "-U", ENV["POSTGRES_USER"], "-d", ENV["POSTGRES_DB"], "-c", wrapped],
        check=True, capture_output=True, text=True,
    ).stdout
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def wait_proposal(thread_id: str, timeout: int = 900) -> dict | None:
    """Poll until the graph has written its proposal and guardrail verdict."""
    deadline = time.time() + timeout
    safe = thread_id.replace("'", "")
    while time.time() < deadline:
        rows = psql(
            "SELECT p.id, p.created_at, p.action, p.risk_tier, p.guardrail_ok,"
            " p.guardrail_reason, p.status, a.payload AS guardrail"
            " FROM proposals p JOIN audit_log a"
            "   ON a.proposal_id = p.id AND a.event_type = 'guardrail'"
            f" WHERE p.thread_id = '{safe}'"
        )
        if rows:
            return rows[0]
        time.sleep(3)
    return None


def proposal_events(proposal_id: int) -> list[dict]:
    return psql(
        "SELECT id, ts, event_type, autonomous, payload FROM audit_log"
        f" WHERE proposal_id = {int(proposal_id)} ORDER BY id"
    )
