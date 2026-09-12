import React, { useCallback, useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import {
  AppMountParameters,
  HttpStart,
} from 'opensearch_dashboards/public';

type Proposal = {
  id: number;
  agent_id: string;
  tier: string;
  action: { action: string; target: string; reason: string };
  evidence: string[];
};

const panel: React.CSSProperties = {
  background: '#fff',
  border: '1px solid #d3dae6',
  borderRadius: 8,
  boxShadow: '0 1px 3px rgba(0,0,0,.08)',
  marginBottom: 16,
  padding: 20,
};

function App({ http }: { http: HttpStart }) {
  const [username, setUsername] = useState('');
  const [agentID, setAgentID] = useState('000');
  const [ruleID, setRuleID] = useState('');
  const [description, setDescription] = useState('');
  const [items, setItems] = useState<Proposal[]>([]);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    const session = await http.get<{ username: string }>(
      '/api/wazuh_guardrail/session',
    );
    const queue = await http.get<{ pending: Proposal[] }>(
      '/api/wazuh_guardrail/queue',
    );
    setUsername(session.username);
    setItems(queue.pending);
  }, [http]);

  useEffect(() => {
    refresh().catch(error => setMessage(error.body?.message || error.message));
    const timer = window.setInterval(() => {
      refresh().catch(() => undefined);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  async function investigate(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage('');
    try {
      const result = await http.post<{ thread: string }>(
        '/api/wazuh_guardrail/investigate',
        {
          body: JSON.stringify({
            agent_id: agentID.trim(),
            rule_id: ruleID.trim() || undefined,
            description: description.trim() || undefined,
          }),
        },
      );
      setMessage(`Investigation started: ${result.thread}`);
    } catch (error) {
      setMessage(error.body?.message || error.message);
    } finally {
      setBusy(false);
    }
  }

  async function decide(proposal: Proposal, decision: 'approve' | 'reject') {
    const justification = window.prompt(
      `${decision === 'approve' ? 'Approval' : 'Rejection'} justification`,
      '',
    );
    if (justification === null) return;
    setBusy(true);
    setMessage('');
    try {
      await http.post(
        `/api/wazuh_guardrail/proposals/${proposal.id}/${decision}`,
        { body: JSON.stringify({ justification }) },
      );
      setMessage(`Proposal #${proposal.id} ${decision}d.`);
      await refresh();
    } catch (error) {
      setMessage(error.body?.message || error.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main
      style={{
        background: '#f5f7fa',
        color: '#343741',
        minHeight: '100%',
        padding: '28px 32px',
      }}
    >
      <div style={{ margin: '0 auto', maxWidth: 960 }}>
        <header style={{ marginBottom: 24 }}>
          <h1 style={{ fontSize: 28, margin: '0 0 6px' }}>Guardrailed AI</h1>
          <div style={{ color: '#69707d' }}>
            Signed in as {username || 'checking session'}
          </div>
        </header>

        <form onSubmit={investigate} style={panel}>
          <h2 style={{ fontSize: 18, marginTop: 0 }}>Start an investigation</h2>
          <div style={{ display: 'grid', gap: 12, gridTemplateColumns: '1fr 1fr' }}>
            <label>
              Wazuh agent ID
              <input
                required
                value={agentID}
                onChange={event => setAgentID(event.target.value)}
                style={{ boxSizing: 'border-box', display: 'block', padding: 9, width: '100%' }}
              />
            </label>
            <label>
              Rule ID
              <input
                value={ruleID}
                onChange={event => setRuleID(event.target.value)}
                style={{ boxSizing: 'border-box', display: 'block', padding: 9, width: '100%' }}
              />
            </label>
          </div>
          <label style={{ display: 'block', marginTop: 12 }}>
            Alert description
            <textarea
              value={description}
              onChange={event => setDescription(event.target.value)}
              style={{ boxSizing: 'border-box', display: 'block', minHeight: 72, padding: 9, width: '100%' }}
            />
          </label>
          <button disabled={busy} style={{ marginTop: 14, padding: '9px 16px' }}>
            Investigate with AI
          </button>
        </form>

        {message && <div style={{ ...panel, borderLeft: '4px solid #006bb4' }}>{message}</div>}

        <section>
          <h2 style={{ fontSize: 20 }}>Your approval queue ({items.length})</h2>
          {items.length === 0 && <div style={panel}>No proposals need your review.</div>}
          {items.map(proposal => (
            <article key={proposal.id} style={panel}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <strong>
                  #{proposal.id}: {proposal.action.action} {proposal.action.target}
                </strong>
                <span>{proposal.tier} risk</span>
              </div>
              <p>{proposal.action.reason}</p>
              <p style={{ color: '#69707d', fontSize: 13 }}>
                Agent {proposal.agent_id}; evidence {proposal.evidence.join(', ') || 'none'}
              </p>
              <div style={{ display: 'flex', gap: 8 }}>
                <button disabled={busy} onClick={() => decide(proposal, 'approve')}>
                  Approve with Wazuh RBAC
                </button>
                <button disabled={busy} onClick={() => decide(proposal, 'reject')}>
                  Reject
                </button>
              </div>
            </article>
          ))}
        </section>
      </div>
    </main>
  );
}

export function renderApp(http: HttpStart, params: AppMountParameters) {
  ReactDOM.render(<App http={http} />, params.element);
  return () => ReactDOM.unmountComponentAtNode(params.element);
}
