import React from 'react';

export default function DashboardPage({ sandboxStatus, mlStatus, scanConfig }) {
  const captureReady = Boolean(sandboxStatus?.ready);
  const runtimeStatus = sandboxStatus?.runtime || null;
  const runtimeReady = Boolean(runtimeStatus?.ready);
  const mlReady = Boolean(mlStatus?.ready);
  const providerName = sandboxStatus?.provider_name || 'Sandbox';
  const statusMessage = sandboxStatus?.message || ('Checking ' + providerName + ' availability...');
  const runtimeProviderName = runtimeStatus?.provider_name || 'Linux Sandbox Runtime';
  const runtimeMessage = runtimeStatus?.message || 'Checking sandbox runtime readiness...';
  const quarantineDir = scanConfig?.quarantine_dir || scanConfig?.staging_dir || 'staging/Download';
  const captureInboxDir = scanConfig?.capture_inbox_dir || 'capture/DownloadInbox';
  const releaseDir = scanConfig?.release_dir || '~/Downloads';
  const modelName = mlStatus?.model_name || 'Cyber Shield Zero-Day Detector';
  const externalDirectories = Array.isArray(scanConfig?.detected_external_directories)
    ? scanConfig.detected_external_directories.filter((item) => item && item !== '/mnt')
    : [];

  function buildModeLabel() {
    if (captureReady && runtimeReady && mlReady) return 'Mode: Project Sandbox + ' + modelName;
    if (captureReady && runtimeReady) return 'Mode: Project Sandbox';
    if (captureReady && mlReady) return 'Mode: Capture + ' + modelName;
    if (captureReady) return 'Mode: Capture Waiting For Runtime';
    return 'Mode: Setup Needed';
  }

  return (
    <section className='page dashboard-page'>
      <div className='dashboard-hero card spacious-card'>
        <div className='hero-copy'>
          <p className='hero-kicker'>Cyber Shield Innovators</p>
          <h2>Always-On Capture Is Active</h2>
          <p className='page-help'>
            Downloads are redirected into <strong>{captureInboxDir}</strong> first. Files are analyzed from review storage and only
            released after review.
          </p>
        </div>
        <div className='hero-pill-stack'>
          <span className={'hero-pill ' + (captureReady ? 'good' : 'warn')}>
            {providerName}: {captureReady ? 'ON' : 'OFF'}
          </span>
          <span className={'hero-pill ' + (runtimeReady ? 'good' : 'warn')}>
            Runtime: {runtimeReady ? 'ON' : 'SETUP NEEDED'}
          </span>
          <span className={'hero-pill ' + (mlReady ? 'good' : 'warn')}>
            {modelName}: {mlReady ? 'READY' : 'OFF'}
          </span>
          <span className={'hero-pill ' + ((captureReady || mlReady || runtimeReady) ? 'good' : 'warn')}>
            {buildModeLabel()}
          </span>
        </div>
      </div>

      <div className={'card status-note spacious-card ' + (captureReady ? 'good' : 'warn')}>
        <h3>{providerName} Status</h3>
        <p>{statusMessage}</p>
      </div>

      <div className={'card status-note spacious-card ' + (runtimeReady ? 'good' : 'warn')}>
        <h3>{runtimeProviderName}</h3>
        <p>{runtimeMessage}</p>
        {!runtimeReady && (
          <p className='scan-message'>
            This project sandbox needs a real Linux isolation tool. On Arch Linux, installing <strong>firejail</strong> is the
            practical lightweight path for this build.
          </p>
        )}
      </div>

      <div className='summary-grid compact dashboard-stats'>
        <article className='card stat-card spacious-card'>
          <h4>Capture Inbox</h4>
          <p className='stat-small'>{captureInboxDir}</p>
        </article>
        <article className='card stat-card spacious-card'>
          <h4>Review Storage</h4>
          <p className='stat-small'>{quarantineDir}</p>
        </article>
        <article className='card stat-card spacious-card'>
          <h4>Release Folder</h4>
          <p className='stat-small'>{releaseDir}</p>
        </article>
        <article className='card stat-card spacious-card'>
          <h4>Mounted Volumes</h4>
          <p>{externalDirectories.length}</p>
        </article>
        <article className='card stat-card spacious-card'>
          <h4>Active Model</h4>
          <p className='stat-small'>{modelName}</p>
        </article>
        <article className='card stat-card spacious-card'>
          <h4>Model Assets</h4>
          <p className='stat-small'>{mlStatus?.model_exists && mlStatus?.norm_exists ? 'Present' : 'Missing'}</p>
        </article>
      </div>

      <div className='dashboard-columns'>
        <article className='card spacious-card'>
          <h3>Protection Layers</h3>
          <ul className='bullet-list roomy-list'>
            <li>Capture starts automatically whenever this software is running</li>
            <li>System downloads are redirected into the capture inbox before the user receives the file</li>
            <li>Mounted external volumes are watched automatically</li>
            <li>{modelName} scores files before a file is released back to the host</li>
            <li>Files can be opened inside a disposable project-scoped Linux sandbox instead of on the host</li>
          </ul>
          <p className='scan-message'>
            Restart browsers or transfer apps if they were already open before this software started, so they use the
            capture inbox as the active download location.
          </p>
        </article>

        <article className='card spacious-card'>
          <h3>Mounted Volumes Detected Right Now</h3>
          {externalDirectories.length === 0 ? (
            <p className='muted-text'>No mounted external volumes detected right now.</p>
          ) : (
            <div className='watch-path-list compact-list'>
              {externalDirectories.map((directory) => (
                <p key={directory} className='path-chip'>{directory}</p>
              ))}
            </div>
          )}

          <div className='watch-section'>
            <h4>What Is Blocked In The Project Sandbox</h4>
            <ul className='bullet-list roomy-list'>
              <li>Network access is disabled by default</li>
              <li>Your normal home directory is blocked from the review session</li>
              <li>Mounted media paths are blocked from the review session</li>
              <li>The project directory is blocked from the review session</li>
            </ul>
          </div>
        </article>
      </div>
    </section>
  );
}
