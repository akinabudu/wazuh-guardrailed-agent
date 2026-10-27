"""
notify.py - Telegram alerting, NOTIFY-ONLY.

This never carries an approval. It only pings an analyst to go and open the
dashboard, where the real (authenticated, in-boundary) decision happens.

Keep the content THIN: a proposal id and a risk level. Never put evidence,
log contents, or any telemetry in the message - it is the one message that
leaves the organisation's AWS account.
"""

from __future__ import annotations

import os
import httpx


def notify_pending_approval(proposal_id: int, tier: str) -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        return  # alerting disabled; silently no-op

    # Deliberately minimal. No target, no evidence, no log text.
    text = (f"\u26a0\ufe0f Approval needed\n"
            f"Proposal #{proposal_id} ({tier} risk)\n"
            f"Open the dashboard to review and decide.")
    try:
        httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=10.0,
        )
    except httpx.HTTPError:
        # Notification failure must never block the pipeline.
        pass
