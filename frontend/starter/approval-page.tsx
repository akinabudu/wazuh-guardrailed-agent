"use client";

// Starter approval page for the operator dashboard.
// setup.sh copies this to  frontend/dashboard/src/app/page.tsx
// It renders the approval queue and lets an analyst approve or reject.
//
// This is a minimal starting point - style it, add auth, add the live-activity
// and metrics panels, and switch polling to WebSocket/SSE for real-time updates.

import { useEffect, useState } from "react";
import { getQueue, approve, reject, Proposal } from "@/lib/api";

export default function ApprovalQueue() {
  const [items, setItems] = useState<Proposal[]>([]);
  const [busy, setBusy] = useState<number | null>(null);

  async function refresh() {
    try {
      setItems(await getQueue());
    } catch (e) {
      console.error("failed to load queue", e);
    }
  }

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 5000); // poll; replace with SSE/WebSocket
    return () => clearInterval(t);
  }, []);

  async function decide(id: number, action: "approve" | "reject") {
    setBusy(id);
    try {
      action === "approve" ? await approve(id) : await reject(id);
      await refresh();
    } finally {
      setBusy(null);
    }
  }

  return (
    <main style={{ maxWidth: 720, margin: "2rem auto", fontFamily: "system-ui" }}>
      <h1 style={{ fontSize: 22, fontWeight: 600 }}>Approval queue</h1>
      <p style={{ color: "#666" }}>{items.length} proposal(s) awaiting review</p>

      {items.map((p) => (
        <div key={p.id} style={{ border: "1px solid #ddd", borderRadius: 12, padding: 16, marginTop: 16 }}>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <strong>#{p.id} · {p.action.action} → {p.action.target}</strong>
            <span style={{ fontSize: 12, background: "#f3e8d0", padding: "2px 8px", borderRadius: 8 }}>
              {p.tier} risk
            </span>
          </div>
          <p style={{ margin: "8px 0", fontSize: 14 }}>{p.action.reason}</p>
          <p style={{ margin: "8px 0", fontSize: 12, color: "#555" }}>
            Evidence (verified): {p.evidence.join(", ") || "—"}
          </p>
          <div style={{ display: "flex", gap: 8 }}>
            <button disabled={busy === p.id} onClick={() => decide(p.id, "approve")}
              style={{ flex: 1, height: 38, background: "#1a8a5a", color: "#fff", border: 0, borderRadius: 8 }}>
              Approve
            </button>
            <button disabled={busy === p.id} onClick={() => decide(p.id, "reject")}
              style={{ flex: 1, height: 38, borderRadius: 8 }}>
              Reject
            </button>
          </div>
        </div>
      ))}
    </main>
  );
}
