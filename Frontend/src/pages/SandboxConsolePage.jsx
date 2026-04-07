import React, { useEffect, useMemo, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const REFRESH_INTERVAL_MS = 5000;

function formatDate(ts) {
  if (!ts) return '-';
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return ts;
  return date.toLocaleString();
}

function formatPercent(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) return '--';
  return (Math.max(0, Math.min(1, value)) * 100).toFixed(2) + '%';
}

function decisionLabel(decision) {
  if (decision === 'BLOCKED') return 'Malicious';
  if (decision === 'ALLOWED') return 'Safe';
  if (decision === 'UNCERTAIN') return 'Suspicious';
  return 'Pending';
}

function decisionTone(decision) {
  if (decision === 'BLOCKED') return 'bad';
  if (decision === 'ALLOWED') return 'good';
  if (decision === 'UNCERTAIN') return 'warn';
  return 'neutral';
}

function analysisLabel(session) {
  const engine = String(session?.analysis_engine || '').trim();
  if (engine === 'ml') return 'ML analysis';
  if (engine === 'heuristic') return 'Heuristic analysis';
  if (engine) return engine;
  return 'Sandbox review';
}

function buildRestrictionItems(restrictions) {
  if (!restrictions) return [];

  const items = [];
  if (restrictions.network) {
    items.push('Network is ' + restrictions.network + '.');
  }
  if (restrictions.private_home) {
    items.push('The sandbox uses a private home directory.');
  }
  if (restrictions.private_tmp) {
    items.push('Temporary files are isolated from the host.');
  }
  if (restrictions.no_new_privileges) {
    items.push('Privilege escalation is blocked.');
  }
  if (restrictions.caps_dropped) {
    items.push('Linux capabilities are dropped.');
  }
  if (Array.isArray(restrictions.blocked_paths) && restrictions.blocked_paths.length > 0) {
    items.push(restrictions.blocked_paths.length + ' host path' + (restrictions.blocked_paths.length === 1 ? ' is' : 's are') + ' blocked from the session.');
  }
  return items;
}

function SessionTree({ nodes, level = 0 }) {
  if (!nodes || nodes.length === 0) {
    return null;
  }

  return (
    <div className='sandbox-tree'>
      {nodes.map((node) => (
        <div key={node.path} className='sandbox-tree-node' style={{ paddingLeft: `${level * 16}px` }}>
          <div className='sandbox-tree-row'>
            <span className={'sandbox-node-type ' + (node.type === 'directory' ? 'dir' : 'file')}>
              {node.type === 'directory' ? 'DIR' : 'FILE'}
            </span>
            <span className='sandbox-node-name'>{node.name}</span>
            {node.type === 'file' && typeof node.size_bytes === 'number' && (
              <span className='sandbox-node-size'>{node.size_bytes} B</span>
            )}
          </div>
          {node.type === 'directory' && node.children?.length > 0 && (
            <SessionTree nodes={node.children} level={level + 1} />
          )}
        </div>
      ))}
    </div>
  );
}

function MetricBar({ label, value, tone = 'accent', helper = '' }) {
  const normalized = typeof value === 'number' && !Number.isNaN(value)
    ? Math.max(0, Math.min(100, value * 100))
    : null;

  return (
    <div className='metric-card compact'>
      <div className='metric-head'>
        <span>{label}</span>
        <strong>{normalized === null ? '--' : normalized.toFixed(2) + '%'}</strong>
      </div>
      <div className='metric-track'>
        <div className={'metric-fill ' + tone} style={{ width: (normalized === null ? 0 : normalized) + '%' }} />
      </div>
      {helper && <p className='metric-helper'>{helper}</p>}
    </div>
  );
}

export default function SandboxConsolePage({ sandboxStatus }) {
  const [sessions, setSessions] = useState([]);
  const [selectedSessionId, setSelectedSessionId] = useState('');
  const [selectedSession, setSelectedSession] = useState(null);
  const [message, setMessage] = useState('');

  useEffect(() => {
    let active = true;

    const loadSessions = async () => {
      try {
        const response = await fetch(API_BASE_URL + '/api/sandbox/sessions?limit=20', { cache: 'no-store' });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload?.detail || 'Failed to load sandbox sessions');
        }
        if (!active) return;
        const items = Array.isArray(payload.items) ? payload.items : [];
        setSessions(items);
        setSelectedSessionId((current) => {
          if (!items.length) return '';
          if (current && items.some((item) => item.session_id === current)) return current;
          return items[0]?.session_id || '';
        });
        setMessage(items.length === 0 ? 'No sandbox sessions yet. Open a review file in Project Sandbox first.' : '');
      } catch (error) {
        if (!active) return;
        setMessage(error?.message || 'Failed to load sandbox sessions');
      }
    };

    loadSessions();
    const timer = setInterval(loadSessions, REFRESH_INTERVAL_MS);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [selectedSessionId]);

  useEffect(() => {
    let active = true;
    if (!selectedSessionId) {
      setSelectedSession(null);
      return undefined;
    }

    const loadSession = async () => {
      try {
        const response = await fetch(API_BASE_URL + '/api/sandbox/sessions/' + encodeURIComponent(selectedSessionId), { cache: 'no-store' });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload?.detail || 'Failed to load sandbox session');
        }
        if (!active) return;
        setSelectedSession(payload);
      } catch (error) {
        if (!active) return;
        setSelectedSession(null);
        setMessage(error?.message || 'Failed to load sandbox session');
      }
    };

    loadSession();
    const timer = setInterval(loadSession, REFRESH_INTERVAL_MS);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [selectedSessionId]);

  const runtimeReady = Boolean(sandboxStatus?.runtime_ready ?? sandboxStatus?.runtime?.ready);
  const runtimeMessage = sandboxStatus?.runtime?.message || sandboxStatus?.message || 'Sandbox runtime status unavailable.';
  const selectedDecision = selectedSession?.decision || '';
  const selectedDecisionLabel = decisionLabel(selectedDecision);
  const selectedDecisionTone = decisionTone(selectedDecision);
  const selectedRiskTone = selectedDecision === 'BLOCKED' ? 'bad' : selectedDecision === 'UNCERTAIN' ? 'warn' : 'good';
  const findings = Array.isArray(selectedSession?.reasons) && selectedSession.reasons.length > 0
    ? selectedSession.reasons
    : ['No high-risk behavior or rule-based finding was returned for this session.'];
  const restrictionItems = buildRestrictionItems(selectedSession?.restrictions || null);
  const blockedPaths = Array.isArray(selectedSession?.restrictions?.blocked_paths)
    ? selectedSession.restrictions.blocked_paths
    : [];
  const sessionTree = Array.isArray(selectedSession?.tree) ? selectedSession.tree : [];

  return (
    <section className='page sandbox-console-page'>
      <div className='sandbox-console-hero card spacious-card'>
        <div>
          <p className='hero-kicker'>Project Sandbox</p>
          <h2>Sandbox Console</h2>
          <p className='page-help'>Review isolated sessions here. The page now focuses on the file, the verdict, the scan method, and the sandbox restrictions that matter.</p>
        </div>
        <div className='hero-pill-stack'>
          <span className={'hero-pill ' + (runtimeReady ? 'good' : 'warn')}>
            Runtime: {runtimeReady ? 'ONLINE' : 'OFFLINE'}
          </span>
          <span className='hero-pill'>Sessions: {sessions.length}</span>
          {selectedSession && (
            <span className={'hero-pill ' + selectedDecisionTone}>
              Verdict: {selectedDecisionLabel}
            </span>
          )}
        </div>
      </div>

      {message && <div className='card status-note warn spacious-card'><p>{message}</p></div>}

      <div className='summary-grid compact sandbox-console-stats'>
        <article className='card stat-card spacious-card'>
          <h4>Runtime Status</h4>
          <p className='stat-small'>{runtimeReady ? 'Ready' : 'Needs setup'}</p>
        </article>
        <article className='card stat-card spacious-card'>
          <h4>Selected File</h4>
          <p className='stat-small'>{selectedSession?.sample_name || 'No session selected'}</p>
        </article>
        <article className='card stat-card spacious-card'>
          <h4>Verdict</h4>
          <p className={'sandbox-decision-text ' + selectedDecisionTone}>{selectedSession ? selectedDecisionLabel : '-'}</p>
        </article>
      </div>

      <div className='sandbox-console-layout'>
        <aside className='card sandbox-session-list spacious-card'>
          <div className='sandbox-section-head'>
            <div>
              <h3>Sessions</h3>
              <p className='muted-text'>Choose a session to inspect the final verdict and the sandbox limits used for that file.</p>
            </div>
          </div>
          {sessions.length === 0 ? (
            <p className='muted-text'>No disposable sessions have been launched yet.</p>
          ) : (
            <div className='sandbox-session-items'>
              {sessions.map((session) => (
                <button
                  key={session.session_id}
                  type='button'
                  className={'sandbox-session-btn ' + (selectedSessionId === session.session_id ? 'active' : '')}
                  onClick={() => setSelectedSessionId(session.session_id)}
                >
                  <div className='sandbox-session-top'>
                    <span className='sandbox-session-name' title={session.sample_name || session.session_id}>{session.sample_name || session.session_id}</span>
                    <span className={'sandbox-mini-badge ' + decisionTone(session.decision)}>{decisionLabel(session.decision)}</span>
                  </div>
                  <span className='sandbox-session-meta'>{formatDate(session.ts)}</span>
                  <span className='sandbox-session-meta'>{analysisLabel(session)}</span>
                </button>
              ))}
            </div>
          )}
        </aside>

        <div className='sandbox-console-main'>
          <section className='card sandbox-session-overview spacious-card'>
            <div className='sandbox-section-head'>
              <div>
                <h3>Selected Session</h3>
                <p className='muted-text'>The essentials for the file currently highlighted in the session list.</p>
              </div>
            </div>
            {!selectedSession ? (
              <p className='muted-text'>Select a sandbox session to inspect it.</p>
            ) : (
              <div className='summary-grid compact sandbox-summary-grid'>
                <article className='card stat-card'>
                  <h4>File</h4>
                  <p className='stat-small'>{selectedSession.sample_name || '-'}</p>
                </article>
                <article className='card stat-card'>
                  <h4>Verdict</h4>
                  <p className={'sandbox-decision-text ' + selectedDecisionTone}>{selectedDecisionLabel}</p>
                </article>
                <article className='card stat-card'>
                  <h4>Scan Method</h4>
                  <p className='stat-small'>{analysisLabel(selectedSession)}</p>
                </article>
                <article className='card stat-card'>
                  <h4>Scanned At</h4>
                  <p className='stat-small'>{formatDate(selectedSession.ts)}</p>
                </article>
              </div>
            )}
          </section>

          <section className='card sandbox-analysis-panel spacious-card'>
            <div className='sandbox-section-head'>
              <div>
                <h3>Risk And Findings</h3>
                <p className='muted-text'>This section keeps the actual risk signals and hides repeated model metadata that does not help the review decision.</p>
              </div>
            </div>
            {!selectedSession ? (
              <p className='muted-text'>No sandbox session selected.</p>
            ) : (
              <div className='sandbox-analysis-grid'>
                <div className='metric-stack'>
                  <MetricBar
                    label='Fused Risk'
                    value={selectedSession.fused_risk}
                    tone={selectedRiskTone}
                    helper='Final score used for the verdict shown above.'
                  />
                  <MetricBar
                    label='Static Model Output'
                    value={selectedSession.static_prob}
                    tone='accent'
                    helper='Direct score from the analyzer when available.'
                  />
                  {selectedSession.scanner_warning && (
                    <div className='sandbox-inline-note warn'>
                      <h4>Scanner Warning</h4>
                      <p>{selectedSession.scanner_warning}</p>
                    </div>
                  )}
                </div>
                <div className='evidence-list compact-evidence sandbox-findings-grid'>
                  {findings.map((reason, index) => (
                    <article key={reason + '-' + index} className='evidence-item compact'>
                      <h4>Finding {index + 1}</h4>
                      <p>{reason}</p>
                    </article>
                  ))}
                </div>
              </div>
            )}
          </section>

          <div className='sandbox-detail-grid'>
            <section className='card sandbox-restrictions spacious-card'>
              <div className='sandbox-section-head'>
                <div>
                  <h3>Isolation Rules</h3>
                  <p className='muted-text'>These are the controls that protected the host while this session was running.</p>
                </div>
              </div>
              {!selectedSession ? (
                <p className='muted-text'>Restrictions will appear here after you select a sandbox session.</p>
              ) : (
                <>
                  <div className='sandbox-restriction-list'>
                    {restrictionItems.length === 0 ? (
                      <p className='muted-text'>No restriction metadata was recorded for this session.</p>
                    ) : (
                      restrictionItems.map((item) => (
                        <p key={item} className='sandbox-rule-item'>{item}</p>
                      ))
                    )}
                  </div>
                  {blockedPaths.length > 0 && (
                    <div className='watch-section'>
                      <h4>Blocked Paths</h4>
                      <div className='sandbox-restriction-grid'>
                        {blockedPaths.map((item) => (
                          <p key={item} className='path-chip'>{item}</p>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </section>

            <section className='card sandbox-file-browser spacious-card'>
              <div className='sandbox-section-head'>
                <div>
                  <h3>Sandbox Files</h3>
                  <p className='muted-text'>Contents captured for this session.</p>
                </div>
              </div>
              {!selectedSession ? (
                <p className='muted-text'>No sandbox session selected.</p>
              ) : sessionTree.length === 0 ? (
                <p className='muted-text'>No file tree was recorded for this session.</p>
              ) : (
                <SessionTree nodes={sessionTree} />
              )}
            </section>
          </div>
        </div>
      </div>
    </section>
  );
}
