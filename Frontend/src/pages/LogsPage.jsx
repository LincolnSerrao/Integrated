import React, { useEffect, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const REFRESH_INTERVAL_MS = 5000;

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

function formatEngine(engine) {
  if (engine === 'ml') return 'Feedforward NN (PE)';
  if (engine === 'heuristic') return 'Heuristic';
  if (engine === 'steg') return 'Steg';
  return engine || '-';
}

function formatSource(source) {
  if (source === 'download-monitor') return 'Downloads';
  return 'Manual';
}

function trimTrailingZeros(valueText) {
  return valueText.replace(/\.0+$|(\.\d*?[1-9])0+$/, '$1');
}

function formatPreciseNumber(value, maxFractionDigits = 14) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  const absValue = Math.abs(value);
  if (absValue === 0) return '0';
  if (absValue < 0.000001 || absValue >= 1000000) {
    return value.toExponential(12).replace(/\.?0+e/, 'e');
  }
  return trimTrailingZeros(value.toLocaleString('en-US', {
    useGrouping: false,
    maximumFractionDigits: maxFractionDigits
  }));
}

function formatRiskPercent(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '-';
  const formatted = formatPreciseNumber(value * 100, 14);
  return formatted === null ? '-' : `${formatted}%`;
}

export default function LogsPage() {
  const [items, setItems] = useState([]);
  const [message, setMessage] = useState('');

  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan/logs?limit=100`);
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
        setMessage(error?.message || `Cannot reach backend at ${API_BASE_URL}`);
      }
    };

    load();
    const timer = setInterval(load, REFRESH_INTERVAL_MS);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  return (
    <section className="page">
      <h2>Logs Page</h2>
      <p className="page-help">This is your scan history. Newest scan appears at the top.</p>
      {message && <p className="scan-message">{message}</p>}

      <div className="card table-wrap">
        <table>
          <thead>
            <tr>
              <th>File Name</th>
              <th>Status</th>
              <th>Risk</th>
              <th>Engine</th>
              <th>Source</th>
              <th>Date</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={6}>No scan logs yet.</td>
              </tr>
            ) : (
              items.map((entry, idx) => {
                const status = entry.overall_result || 'Suspicious';
                const risk = formatRiskPercent(entry.fused_risk);
                return (
                  <tr key={`${entry.ts || 'na'}-${entry.file_name || 'file'}-${idx}`}>
                    <td>{entry.file_name || '-'}</td>
                    <td><span className={statusClass(status)}>{status}</span></td>
                    <td>{risk}</td>
                    <td>{formatEngine(entry.engine)}</td>
                    <td>{formatSource(entry.source)}</td>
                    <td>{formatDate(entry.ts)}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
