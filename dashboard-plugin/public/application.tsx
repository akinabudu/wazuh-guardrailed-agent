import React, { useCallback, useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import {
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiConfirmModal,
  EuiEmptyPrompt,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiHorizontalRule,
  EuiIcon,
  EuiLoadingSpinner,
  EuiOverlayMask,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiStat,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import {
  AppMountParameters,
  HttpStart,
} from 'opensearch_dashboards/public';
import './application.scss';

type Proposal = {
  id: number;
  agent_id: string;
  tier: string;
  action: { action: string; target: string; reason: string };
  evidence: string[];
};

type Decision = {
  proposal: Proposal;
  value: 'approve' | 'reject';
};

type WazuhAgent = {
  id: string;
  name: string;
  status: string;
  ip: string;
};

function errorMessage(error: any): string {
  return error.body?.message || error.message || 'The request failed.';
}

function App({ http }: { http: HttpStart }) {
  const [agentID, setAgentID] = useState('');
  const [agents, setAgents] = useState<WazuhAgent[]>([]);
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [ruleID, setRuleID] = useState('');
  const [description, setDescription] = useState('');
  const [items, setItems] = useState<Proposal[]>([]);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState<'success' | 'danger'>('success');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [decision, setDecision] = useState<Decision | null>(null);
  const [justification, setJustification] = useState('');

  const refresh = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const queue = await http.get<{ pending: Proposal[] }>(
        '/api/wazuh_guardrail/queue',
      );
      setItems(queue.pending);
    } catch (error) {
      if (!quiet) {
        setMessageType('danger');
        setMessage(errorMessage(error));
      }
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [http]);

  const loadAgents = useCallback(async () => {
    setAgentsLoading(true);
    try {
      const result = await http.get<{ agents: WazuhAgent[] }>(
        '/api/wazuh_guardrail/agents',
      );
      setAgents(result.agents);
      setAgentID(current =>
        result.agents.some(agent => agent.id === current)
          ? current
          : result.agents[0]?.id || '',
      );
    } catch (error) {
      setMessageType('danger');
      setMessage(errorMessage(error));
    } finally {
      setAgentsLoading(false);
    }
  }, [http]);

  useEffect(() => {
    refresh();
    loadAgents();
    const timer = window.setInterval(() => refresh(true), 10000);
    return () => window.clearInterval(timer);
  }, [loadAgents, refresh]);

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
      setMessageType('success');
      setMessage(`Investigation started: ${result.thread}`);
      setRuleID('');
      setDescription('');
    } catch (error) {
      setMessageType('danger');
      setMessage(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function submitDecision() {
    if (!decision) return;
    setBusy(true);
    setMessage('');
    try {
      await http.post(
        `/api/wazuh_guardrail/proposals/${decision.proposal.id}/${decision.value}`,
        { body: JSON.stringify({ justification: justification.trim() }) },
      );
      setMessageType('success');
      setMessage(`Proposal #${decision.proposal.id} ${decision.value}d.`);
      setDecision(null);
      setJustification('');
      await refresh(true);
    } catch (error) {
      setMessageType('danger');
      setMessage(errorMessage(error));
      setDecision(null);
    } finally {
      setBusy(false);
    }
  }

  function openDecision(proposal: Proposal, value: 'approve' | 'reject') {
    setJustification('');
    setDecision({ proposal, value });
  }

  return (
    <main className="wzApp guardrailApp">
      <div className="guardrailApp__header">
        <div className="guardrailApp__content">
          <EuiFlexGroup alignItems="center" justifyContent="spaceBetween">
            <EuiFlexItem>
              <EuiFlexGroup alignItems="center" gutterSize="m" responsive={false}>
                <EuiFlexItem grow={false}>
                  <div className="guardrailApp__mark">
                    <EuiIcon type="securitySignal" size="xl" />
                  </div>
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiTitle size="l">
                    <h1>Guardrailed AI</h1>
                  </EuiTitle>
                  <EuiText color="subdued" size="s">
                    <p>Human-supervised threat investigation and response</p>
                  </EuiText>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty
                size="s"
                iconType="refresh"
                onClick={() => {
                  refresh();
                  loadAgents();
                }}
                isDisabled={loading || agentsLoading}
              >
                Refresh
              </EuiButtonEmpty>
            </EuiFlexItem>
          </EuiFlexGroup>
        </div>
      </div>

      <div className="guardrailApp__content guardrailApp__body">
        <EuiFlexGroup gutterSize="m">
          <EuiFlexItem>
            <EuiPanel paddingSize="m">
              <EuiStat
                title={loading ? <EuiLoadingSpinner size="m" /> : items.length}
                description="Awaiting your review"
                titleColor={items.length ? 'warning' : 'success'}
              />
            </EuiPanel>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiPanel paddingSize="m">
              <EuiStat title="Human" description="Response approval mode" />
            </EuiPanel>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiPanel paddingSize="m">
              <EuiStat title="Wazuh RBAC" description="Agent access boundary" />
            </EuiPanel>
          </EuiFlexItem>
        </EuiFlexGroup>

        {message && (
          <>
            <EuiSpacer size="m" />
            <EuiCallOut
              title={message}
              color={messageType}
              iconType={messageType === 'success' ? 'check' : 'alert'}
              onDismiss={() => setMessage('')}
            />
          </>
        )}

        <EuiSpacer size="l" />
        <EuiFlexGroup alignItems="flexStart" gutterSize="l">
          <EuiFlexItem grow={4} className="guardrailApp__investigate">
            <EuiPanel paddingSize="l">
              <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
                <EuiFlexItem grow={false}>
                  <EuiIcon type="search" color="primary" size="l" />
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiTitle size="s">
                    <h2>Start an investigation</h2>
                  </EuiTitle>
                  <EuiText color="subdued" size="s">
                    <p>Ask the local model to analyze a Wazuh agent or alert.</p>
                  </EuiText>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiHorizontalRule margin="m" />
              <form onSubmit={investigate}>
                <EuiFormRow label="Wazuh agent ID" fullWidth>
                  <EuiSelect
                    required
                    value={agentID}
                    onChange={event => setAgentID(event.target.value)}
                    options={
                      agents.length
                        ? agents.map(agent => ({
                            value: agent.id,
                            text: `${agent.id} - ${agent.name} (${agent.status})${
                              agent.ip ? ` - ${agent.ip}` : ''
                            }`,
                          }))
                        : [
                            {
                              value: '',
                              text: agentsLoading
                                ? 'Loading agents...'
                                : 'No accessible agents',
                              disabled: true,
                            },
                          ]
                    }
                    disabled={agentsLoading || !agents.length}
                    fullWidth
                    compressed
                  />
                </EuiFormRow>
                <EuiFormRow
                  label="Rule ID"
                  helpText="Optional. Add the triggering rule when you have it."
                  fullWidth
                >
                  <EuiFieldText
                    value={ruleID}
                    onChange={event => setRuleID(event.target.value)}
                    fullWidth
                    compressed
                  />
                </EuiFormRow>
                <EuiFormRow label="Alert context" fullWidth>
                  <EuiTextArea
                    placeholder="Describe the alert, behavior, or question to investigate."
                    value={description}
                    onChange={event => setDescription(event.target.value)}
                    fullWidth
                    resize="vertical"
                  />
                </EuiFormRow>
                <EuiSpacer size="m" />
                <EuiButton
                  type="submit"
                  fill
                  iconType="securitySignal"
                  isLoading={busy}
                  isDisabled={!agentID.trim() || agentsLoading}
                  fullWidth
                >
                  Investigate with AI
                </EuiButton>
              </form>
              <EuiSpacer size="m" />
              <EuiText color="subdued" size="xs">
                <p>
                  The model can propose a response, but Wazuh RBAC and the
                  guardrail policy decide what reaches your approval queue.
                </p>
              </EuiText>
            </EuiPanel>
          </EuiFlexItem>

          <EuiFlexItem grow={7}>
            <EuiPanel paddingSize="l">
              <EuiFlexGroup alignItems="center" justifyContent="spaceBetween">
                <EuiFlexItem>
                  <EuiTitle size="s">
                    <h2>Approval queue</h2>
                  </EuiTitle>
                  <EuiText color="subdued" size="s">
                    <p>Only proposals for agents you can access appear here.</p>
                  </EuiText>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiBadge color={items.length ? 'warning' : 'hollow'}>
                    {items.length} pending
                  </EuiBadge>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiHorizontalRule margin="m" />

              {loading ? (
                <div className="guardrailApp__loading">
                  <EuiLoadingSpinner size="xl" />
                </div>
              ) : items.length === 0 ? (
                <EuiEmptyPrompt
                  iconType="checkInCircleFilled"
                  title={<h3>Your queue is clear</h3>}
                  body={<p>No proposals need your review.</p>}
                />
              ) : (
                <div className="guardrailApp__queue">
                  {items.map(proposal => (
                    <EuiPanel
                      key={proposal.id}
                      className="guardrailApp__proposal"
                      paddingSize="m"
                      hasShadow={false}
                    >
                      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween">
                        <EuiFlexItem>
                          <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
                            <EuiFlexItem grow={false}>
                              <span className="guardrailApp__proposalId">#{proposal.id}</span>
                            </EuiFlexItem>
                            <EuiFlexItem>
                              <EuiTitle size="xs">
                                <h3>{proposal.action.action.replace(/_/g, ' ')}</h3>
                              </EuiTitle>
                            </EuiFlexItem>
                          </EuiFlexGroup>
                        </EuiFlexItem>
                        <EuiFlexItem grow={false}>
                          <EuiBadge color={proposal.tier === 'elevated' ? 'danger' : 'warning'}>
                            {proposal.tier} approval
                          </EuiBadge>
                        </EuiFlexItem>
                      </EuiFlexGroup>
                      <EuiSpacer size="s" />
                      <EuiText size="s">
                        <p>{proposal.action.reason}</p>
                      </EuiText>
                      <div className="guardrailApp__metadata">
                        <span><strong>Target</strong> {proposal.action.target}</span>
                        <span><strong>Agent</strong> {proposal.agent_id}</span>
                        <span><strong>Evidence</strong> {proposal.evidence.length || 'None'}</span>
                      </div>
                      <EuiSpacer size="m" />
                      <EuiFlexGroup gutterSize="s" justifyContent="flexEnd" responsive={false}>
                        <EuiFlexItem grow={false}>
                          <EuiButtonEmpty
                            color="danger"
                            iconType="cross"
                            isDisabled={busy}
                            onClick={() => openDecision(proposal, 'reject')}
                          >
                            Reject
                          </EuiButtonEmpty>
                        </EuiFlexItem>
                        <EuiFlexItem grow={false}>
                          <EuiButton
                            fill
                            iconType="lock"
                            isDisabled={busy}
                            onClick={() => openDecision(proposal, 'approve')}
                          >
                            Approve with Wazuh RBAC
                          </EuiButton>
                        </EuiFlexItem>
                      </EuiFlexGroup>
                    </EuiPanel>
                  ))}
                </div>
              )}
            </EuiPanel>
          </EuiFlexItem>
        </EuiFlexGroup>
      </div>

      {decision && (
        <EuiOverlayMask>
          <EuiConfirmModal
            title={`${decision.value === 'approve' ? 'Approve' : 'Reject'} proposal #${decision.proposal.id}`}
            onCancel={() => setDecision(null)}
            onConfirm={submitDecision}
            cancelButtonText="Cancel"
            confirmButtonText={decision.value === 'approve' ? 'Approve proposal' : 'Reject proposal'}
            buttonColor={decision.value === 'approve' ? 'primary' : 'danger'}
            defaultFocusedButton={decision.value === 'approve' ? 'confirm' : 'cancel'}
          >
            <EuiText size="s">
              <p>
                <strong>{decision.proposal.action.action.replace(/_/g, ' ')}</strong>{' '}
                on <strong>{decision.proposal.action.target}</strong>
              </p>
            </EuiText>
            <EuiSpacer size="m" />
            <EuiFormRow label="Justification" fullWidth>
              <EuiTextArea
                value={justification}
                onChange={event => setJustification(event.target.value)}
                placeholder="Record why you made this decision."
                fullWidth
                autoFocus
              />
            </EuiFormRow>
          </EuiConfirmModal>
        </EuiOverlayMask>
      )}
    </main>
  );
}

export function renderApp(http: HttpStart, params: AppMountParameters) {
  ReactDOM.render(<App http={http} />, params.element);
  return () => ReactDOM.unmountComponentAtNode(params.element);
}
