// api-client.ts
// setup.sh copies this to  frontend/dashboard/src/lib/api.ts
// Thin client for the FastAPI backend.

const BASE = "/backend";

// The header auth here is a placeholder that matches the backend stub.
// Replace with a real session token once auth is wired.
const ANALYST = "analyst1";

export interface Action {
  action: string;
  target: string;
  reason: string;
}

export interface Proposal {
  id: number;
  created_at: string;
  action: Action;
  reasoning: string;
  evidence: string[];
  tier: string;
}

export async function getQueue(): Promise<Proposal[]> {
  const r = await fetch(`${BASE}/queue`, { cache: "no-store" });
  if (!r.ok) throw new Error("queue failed");
  return (await r.json()).pending;
}

export async function approve(id: number, justification?: string): Promise<void> {
  const r = await fetch(`${BASE}/proposals/${id}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Analyst": ANALYST },
    body: JSON.stringify({ justification }),
  });
  if (!r.ok) throw new Error(await r.text());
}

export async function reject(id: number, justification?: string): Promise<void> {
  const r = await fetch(`${BASE}/proposals/${id}/reject`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Analyst": ANALYST },
    body: JSON.stringify({ justification }),
  });
  if (!r.ok) throw new Error(await r.text());
}
