import React from 'react';

function buildModeLabel(sandboxStatus, mlStatus) {
  if (!sandboxStatus || !mlStatus) return 'Mode: Checking...';
  if (sandboxStatus.ready) return 'Mode: Full Protection';
  if (mlStatus.ready) return 'Mode: Full AI Protection';
  return 'Mode: Fallback Only';
}

export default function DashboardPage({ sandboxStatus, mlStatus, stagingDir }) {
  const sandboxReady = Boolean(sandboxStatus?.ready);
  const mlReady = Boolean(mlStatus?.ready);
  const providerName = sandboxStatus?.provider_name || 'Sandbox';
  const statusMessage = sandboxStatus?.message || `Checking ${providerName} availability...`;
  const targetDir = stagingDir || 'D:\\Download';

  return (
    <section className="page dashboard-page">
      <div className="dashboard-hero card">
        <div>
          <p className="hero-kicker">Cyber Shield Innovators</p>
          <h2>Automatic protection for every download</h2>
          <p className="page-help">
            Files are scanned automatically only when the browser or app downloads directly into
            {' '}<strong>{targetDir}</strong>. Manual upload is optional for extra checks.
          </p>
        </div>
        <div className="hero-pill-stack">
          <span className={`hero-pill ${sandboxReady ? 'good' : 'warn'}`}>
            {providerName}: {sandboxReady ? 'ON' : 'OFF'}
          </span>
          <span className={`hero-pill ${mlReady ? 'good' : 'warn'}`}>
            ML Scan: {mlReady ? 'ON' : 'OFF'}
          </span>
          <span className={`hero-pill ${(sandboxReady || mlReady) ? 'good' : 'warn'}`}>
            {buildModeLabel(sandboxStatus, mlStatus)}
          </span>
        </div>
      </div>

      <div className={`card status-note ${sandboxReady ? 'good' : 'warn'}`}>
        <h3>{providerName} Status</h3>
        <p>{statusMessage}</p>
        {sandboxStatus?.product_name && (
          <p className="muted-text">Detected OS: {sandboxStatus.product_name}</p>
        )}
      </div>

      <div className="summary-grid compact">
        <article className="card stat-card">
          <h4>Last Scan</h4>
          <p>Live in Logs Page</p>
        </article>
        <article className="card stat-card">
          <h4>{providerName}</h4>
          <p>{sandboxReady ? 'Ready' : 'Unavailable'}</p>
        </article>
        <article className="card stat-card">
          <h4>Manual Upload</h4>
          <p>Available</p>
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
          </div>
        </article>

        <article className="card">
          <h3>Automatic Download Flow</h3>
          <ul className="bullet-list">
            <li>Set the browser or app download path to <strong>{targetDir}</strong></li>
            <li>Download the file as usual</li>
            <li>The monitor detects the finished file there</li>
            <li>
              {sandboxReady
                ? `The file is pushed into ${providerName} for review`
                : `The file can still be scanned, but ${providerName} is currently unavailable on this machine`}
            </li>
          </ul>
        </article>
      </div>
    </section>
  );
}
