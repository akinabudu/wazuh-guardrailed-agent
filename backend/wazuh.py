"""
wazuh.py - thin client for the Wazuh indexer and manager.

Three jobs:
  - query_events()   : read alerts/events from the indexer (for hunting)
  - verify_events()  : confirm cited event ids actually exist (evidence check)
  - active_response(): execute an APPROVED action via the manager

SECURITY: everything returned by query_events() is UNTRUSTED DATA. It is
attacker-influenced (hostnames, filenames, usernames, etc.). Callers must
treat it as data to reason over, never as instructions. Never interpolate it
into the instruction part of a model prompt.
"""

from __future__ import annotations

import os
import httpx


class WazuhClient:
    def __init__(self) -> None:
        self.indexer_url = os.environ["WAZUH_INDEXER_URL"].rstrip("/")
        self.manager_url = os.environ["WAZUH_URL"].rstrip("/")
        self.indexer_auth = (os.environ["INDEXER_USER"], os.environ["INDEXER_PASSWORD"])
        self.api_auth = (os.environ["WAZUH_API_USER"], os.environ["WAZUH_API_PASSWORD"])
        # Lab uses self-signed certs; verify=False is acceptable on-box only.
        # In production, mount the Wazuh CA and set verify to its path.
        self._client = httpx.Client(verify=False, timeout=30.0)

    # -- hunting -------------------------------------------------------------
    def query_events(self, query: dict, index: str = "wazuh-alerts-*") -> list[dict]:
        """Run an OpenSearch query against the indexer. Returns raw hits."""
        r = self._client.post(
            f"{self.indexer_url}/{index}/_search",
            json=query, auth=self.indexer_auth,
            params={"allow_no_indices": "true", "ignore_unavailable": "true"},
        )
        r.raise_for_status()
        events = []
        for hit in r.json().get("hits", {}).get("hits", []):
            event = dict(hit["_source"])
            event.pop("id", None)
            event["evidence_id"] = hit["_id"]
            events.append(event)
        return events

    # -- evidence grounding --------------------------------------------------
    def verify_events(self, event_ids: list[str]) -> bool:
        """Return True only if every cited event id exists in the indexer."""
        if not event_ids:
            return False
        query = {"query": {"ids": {"values": event_ids}}, "size": len(event_ids)}
        try:
            r = self._client.post(
                f"{self.indexer_url}/wazuh-alerts-*/_search",
                json=query, auth=self.indexer_auth,
            )
            r.raise_for_status()
            found = {h["_id"] for h in r.json().get("hits", {}).get("hits", [])}
            return set(event_ids).issubset(found)
        except httpx.HTTPError:
            # On any doubt, fail closed: unverifiable evidence is not verified.
            return False

    # -- remediation (only ever called for APPROVED actions) -----------------
    def _manager_headers(self) -> dict[str, str]:
        r = self._client.post(
            f"{self.manager_url}/security/user/authenticate",
            params={"raw": "true"}, auth=self.api_auth,
        )
        r.raise_for_status()
        return {"Authorization": f"Bearer {r.text.strip()}"}

    def check_connections(self) -> None:
        indexer = self._client.get(self.indexer_url, auth=self.indexer_auth)
        indexer.raise_for_status()
        manager = self._client.get(
            self.manager_url, headers=self._manager_headers()
        )
        manager.raise_for_status()

    def active_response(
        self, action: str, target: str, agent_id: str, token: str
    ) -> dict:
        """
        Trigger a Wazuh active-response command on an endpoint.
        NOTE: this is invoked by the executor ONLY after guardrails + approval.
        Map your allowlisted actions to configured active-response scripts.
        """
        command_map = {
            "block_ip":       "firewall-drop",
            "kill_process":   "kill-process",     # custom AR script you configure
            "isolate_host":   "isolate-host",     # custom AR script you configure
            "disable_account":"disable-account",
        }
        command = command_map.get(action)
        if command is None:
            raise ValueError(f"no active-response mapping for '{action}'")

        payload = {
            "command": command,
            "arguments": [target],
            "alert": {"data": {"srcip": target}},
        }
        r = self._client.put(
            f"{self.manager_url}/active-response?agents_list={agent_id}",
            json=payload, headers={"Authorization": f"Bearer {token}"},
        )
        r.raise_for_status()
        return r.json()
