import React, { useEffect, useMemo, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const LOG_LIMIT = 500;

function formatDate(ts) {
  if (!ts) return 'No scans yet';
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return ts;
  return date.toLocaleString();
}

function summarizeRoots(roots) {
  if (!Array.isArray(roots) || roots.length === 0) return 'configured watch locations';
  if (roots.length <= 3) return roots.join(', ');
  return `${roots.slice(0, 3).join(', ')} and ${roots.length - 3} more`;
}

export default function DashboardPage() {
  const [config, setConfig] = useState(null);
  const [logs, setLogs] = useState([]);
  const [message, setMessage] = useState('');

  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        const [configResponse, logsResponse] = await Promise.all([
          fetch(`${API_BASE_URL}/api/scan/config`),
          fetch(`${API_BASE_URL}/api/scan/logs?limit=${LOG_LIMIT}`)
        ]);

        if (!configResponse.ok) {
          const payload = await configResponse.json().catch(() => ({}));
          throw new Error(payload?.detail || 'Failed to load scan configuration');
        }

        if (!logsResponse.ok) {
          const payload = await logsResponse.json().catch(() => ({}));
          throw new Error(payload?.detail || 'Failed to load scan history');
        }

        const [configPayload, logsPayload] = await Promise.all([
          configResponse.json(),
          logsResponse.json()
        ]);

        if (!active) return;
        setConfig(configPayload);
        setLogs(Array.isArray(logsPayload.items) ? logsPayload.items : []);
        setMessage('');
      } catch (error) {
        if (!active) return;
        setMessage(error?.message || `Cannot reach backend at ${API_BASE_URL}`);
      }
    };

    load();
    return () => {
      active = false;
    };
  }, []);

  const stats = useMemo(() => {
    const blocked = logs.filter((item) => item.overall_result === 'Malicious').length;
    const suspicious = logs.filter((item) => item.overall_result === 'Suspicious').length;
    return {
      lastScan: formatDate(logs[0]?.ts),
      filesScanned: logs.length,
      threatsBlocked: blocked,
      suspiciousFiles: suspicious
    };
  }, [logs]);

  const watchedRoots = Array.isArray(config?.watched_roots) ? config.watched_roots : [];
  const watchSummary = summarizeRoots(watchedRoots);
  const modeLabel = config?.mode || 'Unavailable';
  const autoScanLabel = config ? 'ON' : 'Unavailable';
  const helperMessage = config?.message || 'Automatic sandboxing monitors the configured watch locations.';

  return (
    <section className="page dashboard-page">
      <div className="dashboard-hero card">
        <div>
          <p className="hero-kicker">Cyber Shield Innovators</p>
          <h2>Automatic protection for every download</h2>
          <p className="page-help">{helperMessage}</p>
          <p className="scan-meta">Watching: {watchSummary}</p>
          {message && <p className="scan-message">{message}</p>}
        </div>
        <div className="hero-pill-stack">
          <span className="hero-pill">Auto Scan: {autoScanLabel}</span>
          <span className="hero-pill">Mode: {modeLabel}</span>
        </div>
      </div>

      <div className="summary-grid compact">
        <article className="card stat-card">
          <h4>Last Scan</h4>
          <p>{stats.lastScan}</p>
        </article>
        <article className="card stat-card">
          <h4>Files Scanned</h4>
          <p>{stats.filesScanned}</p>
        </article>
        <article className="card stat-card">
          <h4>Threats Blocked</h4>
          <p>{stats.threatsBlocked}</p>
        </article>
      </div>

      <div className="dashboard-columns">
        <article className="card">
          <h3>Main Threats We Stop</h3>
          <div className="threat-tags">
            <span className="threat-tag">Virus</span>
            <span className="threat-tag">Malware</span>
            <span className="threat-tag">Ransomware</span>
            <span className="threat-tag">Hidden Payload</span>
            <span className="threat-tag">Suspicious Files: {stats.suspiciousFiles}</span>
          </div>
        </article>

        <article className="card">
          <h3>Automatic Capture Flow</h3>
          <ul className="bullet-list">
            <li>New files in watched locations are detected automatically</li>
            <li>Completed downloads and copied files are moved into a review session</li>
            <li>Removable-media mount points under common Linux paths are scanned too</li>
            <li>Use <strong>SANDBOX_EXTRA_WATCH_DIRS</strong> to add more folders later</li>
          </ul>
        </article>
      </div>
    </section>
  );
}
