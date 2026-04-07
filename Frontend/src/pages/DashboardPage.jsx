import React from 'react';

export default function DashboardPage({ sandboxStatus, mlStatus, scanConfig }) {
  const sandboxReady = Boolean(sandboxStatus?.ready);
  const mlReady = Boolean(mlStatus?.ready);
  const providerName = sandboxStatus?.provider_name || 'Sandbox';
  const statusMessage = sandboxStatus?.message || ('Checking ' + providerName + ' availability...');
  const quarantineDir = scanConfig?.quarantine_dir || scanConfig?.staging_dir || 'staging/Download';
  const captureInboxDir = scanConfig?.capture_inbox_dir || 'capture/DownloadInbox';
  const releaseDir = scanConfig?.release_dir || '~/Downloads';
  const externalDirectories = scanConfig?.detected_external_directories || [];

  function buildModeLabel() {
    if (sandboxReady && mlReady) return 'Mode: Quarantine + AI Scan';
    if (sandboxReady) return 'Mode: Quarantine Review';
    if (mlReady) return 'Mode: AI Scan Only';
    return 'Mode: Fallback Only';
  }

  return (
    <section className='page dashboard-page'>
      <div className='dashboard-hero card'>
        <div>
          <p className='hero-kicker'>Cyber Shield Innovators</p>
          <h2>Always-On Capture Is Active</h2>
          <p className='page-help'>
            Downloads are redirected into <strong>{captureInboxDir}</strong> first. Files are analyzed in quarantine and only
            released after review.
          </p>
        </div>
        <div className='hero-pill-stack'>
          <span className={'hero-pill ' + (sandboxReady ? 'good' : 'warn')}>
            {providerName}: {sandboxReady ? 'ON' : 'OFF'}
          </span>
          <span className={'hero-pill ' + (mlReady ? 'good' : 'warn')}>
            ML Scan: {mlReady ? 'ON' : 'OFF'}
          </span>
          <span className={'hero-pill ' + ((sandboxReady || mlReady) ? 'good' : 'warn')}>
            {buildModeLabel()}
          </span>
        </div>
      </div>

      <div className={'card status-note ' + (sandboxReady ? 'good' : 'warn')}>
        <h3>{providerName} Status</h3>
        <p>{statusMessage}</p>
      </div>

      <div className='summary-grid compact'>
        <article className='card stat-card'>
          <h4>Capture Inbox</h4>
          <p className='stat-small'>{captureInboxDir}</p>
        </article>
        <article className='card stat-card'>
          <h4>Release Folder</h4>
          <p className='stat-small'>{releaseDir}</p>
        </article>
        <article className='card stat-card'>
          <h4>Mounted Drives</h4>
          <p>{externalDirectories.length}</p>
        </article>
      </div>

      <div className='dashboard-columns'>
        <article className='card'>
          <h3>Capture Scope</h3>
          <ul className='bullet-list'>
            <li>Capture starts automatically whenever this software is running</li>
            <li>System downloads are redirected into the capture inbox before the user receives the file</li>
            <li>Mounted external drives are watched automatically</li>
            <li>Safe files can be released to a user-chosen folder after review</li>
            <li>Unsafe files stay quarantined unless the user explicitly overrides the warning</li>
          </ul>
          <p className='scan-message'>
            Restart browsers or transfer apps if they were already open before this software started, so they use the
            capture inbox as the active download location.
          </p>
        </article>

        <article className='card'>
          <h3>Mounted Drives Detected Right Now</h3>
          {externalDirectories.length === 0 ? (
            <p className='muted-text'>No mounted external drives detected right now.</p>
          ) : (
            <div className='watch-path-list compact-list'>
              {externalDirectories.map((directory) => (
                <p key={directory} className='path-chip'>{directory}</p>
              ))}
            </div>
          )}

          <div className='watch-section'>
            <h4>Quarantine Destination</h4>
            <p className='path-chip'>{quarantineDir}</p>
          </div>
        </article>
      </div>
    </section>
  );
}
