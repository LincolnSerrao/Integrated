import React, { useEffect, useMemo, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const REFRESH_INTERVAL_MS = 5000;
const DEFAULT_MODEL_NAME = 'Cyber Shield Zero-Day Detector';
const DEFAULT_ARCHITECTURE = 'Feed-Forward Neural Network';
const DEFAULT_ARTIFACT = 'cyber_shield_zero_day.pth';

function statusClass(status) {
  if (status === 'Malicious') return 'tag bad';
  if (status === 'Suspicious') return 'tag warn';
  return 'tag ok';
}

function formatDate(ts) {
  if (!ts) return '-';
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return ts;
  return date.toLocaleString();
}

function prettifySource(source) {
  if (source === 'directory-monitor') return 'Live Capture';
  if (source === 'download-monitor') return 'Legacy Monitor';
  if (!source) return 'Manual Scan';
  return source;
}

function formatPercent(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) return '--';
  return (Math.max(0, Math.min(1, value)) * 100).toFixed(2) + '%';
}

function buildEvidence(entry, modelName) {
  const notes = [];
  if (entry.engine === 'ml') {
    notes.push(modelName + ' produced the model score shown here.');
  }
  if (Array.isArray(entry.reasons) && entry.reasons.length > 0) {
    notes.push(...entry.reasons);
  }
  if (entry.scanner_warning) {
    notes.push('Warning: ' + entry.scanner_warning);
  }
  if (entry.scanner_stage) {
    notes.push('Stage: ' + entry.scanner_stage);
  }
  if (notes.length === 0) {
    notes.push('No extra rule-based findings were returned for this scan entry.');
  }
  return notes.join(' | ');
}

function InlineBar({ value, tone = 'accent' }) {
  const normalized = typeof value === 'number' && !Number.isNaN(value)
    ? Math.max(0, Math.min(100, value * 100))
    : 0;
  const text = typeof value === 'number' && !Number.isNaN(value) ? normalized.toFixed(2) + '%' : '--';

  return (
    <div className='inline-bar-cell'>
      <span>{text}</span>
      <div className='inline-bar-track'>
        <div className={'inline-bar-fill ' + tone} style={{ width: normalized + '%' }} />
      </div>
    </div>
  );
}

export default function LogsPage({ mlStatus, sandboxStatus }) {
  const [items, setItems] = useState([]);
  const [message, setMessage] = useState('');
  const defaultModelName = mlStatus?.model_name || DEFAULT_MODEL_NAME;
  const runtimeReady = Boolean(sandboxStatus?.runtime_ready ?? sandboxStatus?.runtime?.ready);

  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        const response = await fetch(API_BASE_URL + '/api/scan/logs?limit=100&current_session_only=true', { cache: 'no-store' });
        if (!response.ok) {
          const payload = await response.json();
          throw new Error(payload?.detail || 'Failed to load scan logs');
        }

        const payload = await response.json();
        if (!active) return;
        setItems(Array.isArray(payload.items) ? payload.items : []);
        setMessage('');
      } catch (error) {
        if (!active) return;
        setMessage(error?.message || ('Cannot reach backend at ' + API_BASE_URL));
      }
    };

    load();
    const timer = setInterval(load, REFRESH_INTERVAL_MS);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  const summary = useMemo(() => {
    const malicious = items.filter((item) => item.overall_result === 'Malicious').length;
    const suspicious = items.filter((item) => item.overall_result === 'Suspicious').length;
    const safe = items.filter((item) => item.overall_result === 'Safe').length;
    return { malicious, suspicious, safe };
  }, [items]);

  return (
    <section className='page logs-page'>
      <div className='page-header-block'>
        <h2>Logs Page</h2>
        <p className='page-help'>This page now keeps one file per row. Scroll left to right to inspect the full stored analysis, including model identity, thresholds, session ids, warnings, and evidence.</p>
      </div>
      {message && <p className='scan-message'>{message}</p>}

      <div className='summary-grid compact log-summary-grid'>
        <article className='card stat-card spacious-card'>
          <h4>Entries</h4>
          <p>{items.length}</p>
        </article>
        <article className='card stat-card spacious-card'>
          <h4>Safe</h4>
          <p>{summary.safe}</p>
        </article>
        <article className='card stat-card spacious-card'>
          <h4>Suspicious</h4>
          <p>{summary.suspicious}</p>
        </article>
        <article className='card stat-card spacious-card'>
          <h4>Malicious</h4>
          <p>{summary.malicious}</p>
        </article>
        <article className='card stat-card spacious-card'>
          <h4>Active Model</h4>
          <p className='stat-small'>{defaultModelName}</p>
        </article>
        <article className='card stat-card spacious-card'>
          <h4>Sandbox Runtime</h4>
          <p className='stat-small'>{runtimeReady ? 'Ready' : 'Needs setup'}</p>
        </article>
      </div>

      <div className='card logs-table-card spacious-card'>
        <div className='logs-table-scroll'>
          <table className='logs-wide-table'>
            <thead>
              <tr>
                <th>File</th>
                <th>Status</th>
                <th>Date</th>
                <th>Source</th>
                <th>Action</th>
                <th>Engine</th>
                <th>Model</th>
                <th>Architecture</th>
                <th>Artifact</th>
                <th>Decision</th>
                <th>Origin</th>
                <th>Session</th>
                <th>Fused Risk</th>
                <th>Static Output</th>
                <th>Allow</th>
                <th>Block</th>
                <th>Stage</th>
                <th>Warning</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 ? (
                <tr>
                  <td colSpan={19} className='logs-empty-cell'>No scan logs yet in this session.</td>
                </tr>
              ) : (
                items.map((entry, idx) => {
                  const status = entry.overall_result || 'Suspicious';
                  const modelName = entry.model_name || defaultModelName;
                  const architectureName = entry.model_architecture || DEFAULT_ARCHITECTURE;
                  const artifactName = entry.model_artifact_name || DEFAULT_ARTIFACT;
                  const evidence = buildEvidence(entry, modelName);
                  const fusedTone = status === 'Malicious' ? 'bad' : status === 'Suspicious' ? 'warn' : 'good';

                  return (
                    <tr key={(entry.ts || 'na') + '-' + (entry.file_name || 'file') + '-' + idx}>
                      <td className='logs-cell-file'>
                        <strong>{entry.file_name || '-'}</strong>
                      </td>
                      <td><span className={statusClass(status)}>{status}</span></td>
                      <td>{formatDate(entry.ts)}</td>
                      <td>{prettifySource(entry.source)}</td>
                      <td>{entry.post_action || 'manual_scan'}</td>
                      <td>{entry.engine || '-'}</td>
                      <td>{entry.engine === 'ml' ? modelName : modelName}</td>
                      <td>{architectureName}</td>
                      <td>{artifactName}</td>
                      <td>{entry.decision || '-'}</td>
                      <td>{entry.analysis_origin || 'backend'}</td>
                      <td>{entry.sandbox_session_id || '-'}</td>
                      <td><InlineBar value={entry.fused_risk} tone={fusedTone} /></td>
                      <td><InlineBar value={entry.static_prob} tone='accent' /></td>
                      <td>{typeof entry.allow_threshold === 'number' ? entry.allow_threshold.toFixed(2) : '--'}</td>
                      <td>{typeof entry.block_threshold === 'number' ? entry.block_threshold.toFixed(2) : '--'}</td>
                      <td>{entry.scanner_stage || '-'}</td>
                      <td className='logs-cell-wrap'>{entry.scanner_warning || '-'}</td>
                      <td className='logs-cell-wrap'>{evidence}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
