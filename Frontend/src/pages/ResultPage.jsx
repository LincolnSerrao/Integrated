import React, { useEffect, useMemo, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const CLEARED_RESULT_KEY = 'clearedResultMarker';
const REVIEW_PROMPT_KEY = 'reviewPromptMarker';
const LATEST_POLL_INTERVAL_MS = 5000;
const DEFAULT_MODEL_NAME = 'Cyber Shield Zero-Day Detector';

function resultClass(result) {
  if (result === 'No file selected') return 'overall warn';
  if (result === 'Malicious') return 'overall bad';
  if (result === 'Suspicious') return 'overall warn';
  return 'overall safe';
}

function getErrorMessage(error) {
  if (error instanceof TypeError) {
    return 'Cannot reach backend at ' + API_BASE_URL;
  }
  return error?.message || 'Request failed';
}

function buildMarker(payload) {
  return (payload?.file_name || '') + ':' + (payload?.ts || '') + ':' + (payload?.post_action || '');
}

function buildLatestPayload(payload) {
  return {
    file_name: payload.file_name,
    scan_result: payload,
    overall_result: payload.overall_result,
    status: payload.post_action || 'logged'
  };
}

function isActionableLatest(payload) {
  if (!payload) return false;
  return !payload.post_action || payload.post_action === 'manual_review_required' || payload.post_action === 'logged';
}

function formatPercent(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) return '--';
  return (Math.max(0, Math.min(1, value)) * 100).toFixed(2);
}

function formatThreshold(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) return '--';
  return value.toFixed(2);
}

function prettifyWatchSource(source) {
  if (source === 'directory-monitor') return 'Live Capture';
  if (source === 'download-monitor') return 'Legacy Monitor';
  if (!source) return 'Manual Scan';
  return source;
}

function MetricBar({ label, value, helper, tone = 'neutral' }) {
  const normalized = typeof value === 'number' && !Number.isNaN(value)
    ? Math.max(0, Math.min(100, value * 100))
    : null;

  return (
    <div className='metric-card'>
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

function buildEvidence(scan, modelName, runtimeReady, runtimeMessage) {
  if (!scan) {
    return [{ title: 'No active result', detail: 'Upload or capture a file to see a real analysis result.' }];
  }

  const evidence = [];
  if (scan.engine === 'ml') {
    evidence.push({
      title: modelName + ' score',
      detail: 'The percentage shown is the direct model output for this file after feature extraction.'
    });
  }

  if (typeof scan.allow_threshold === 'number' && typeof scan.block_threshold === 'number') {
    evidence.push({
      title: 'Decision thresholds',
      detail: 'Allowed below ' + scan.allow_threshold.toFixed(2) + ', blocked above ' + scan.block_threshold.toFixed(2) + ', otherwise held for review.'
    });
  }

  if (Array.isArray(scan.reasons) && scan.reasons.length > 0) {
    evidence.push(...scan.reasons.map((reason) => ({ title: 'Observed signal', detail: reason })));
  } else if (scan.engine === 'ml') {
    evidence.push({
      title: 'Rule-based findings',
      detail: 'No separate rule-based error strings were returned for this file. The verdict came from the trained model score.'
    });
  }

  if (scan.scanner_warning) {
    evidence.push({
      title: 'Scanner warning',
      detail: scan.scanner_warning
    });
  }

  if (scan.scanner_stage) {
    evidence.push({
      title: 'Scanner stage',
      detail: scan.scanner_stage
    });
  }

  evidence.push({
    title: 'Sandbox runtime',
    detail: runtimeReady ? 'Project sandbox runtime is available for isolated opening of this file.' : runtimeMessage
  });

  return evidence;
}

export default function ResultPage({ overallResult, onLatestResultChange, sandboxStatus, mlStatus }) {
  const [fileInfo, setFileInfo] = useState(null);
  const [message, setMessage] = useState('');
  const [isBusy, setIsBusy] = useState(false);
  const [isManualUpload, setIsManualUpload] = useState(false);

  useEffect(() => {
    const raw = localStorage.getItem('latestSandboxFile');
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        setFileInfo(parsed);
        setIsManualUpload(true);
        return;
      } catch (_) {
        localStorage.removeItem('latestSandboxFile');
      }
    }

    const loadLatest = async () => {
      try {
        const response = await fetch(API_BASE_URL + '/api/scan/latest', { cache: 'no-store' });
        if (!response.ok) return;
        const payload = await response.json();
        if (!isActionableLatest(payload)) {
          setFileInfo(null);
          setMessage('No review file is waiting in this session.');
          return;
        }
        const clearedMarker = localStorage.getItem(CLEARED_RESULT_KEY);
        const marker = buildMarker(payload);
        if (clearedMarker && clearedMarker === marker) {
          return;
        }
        setFileInfo(buildLatestPayload(payload));
        setIsManualUpload(false);
        setMessage(payload.message || '');
      } catch (_) {
        // ignore initial latest failures
      }
    };

    loadLatest();
  }, []);

  useEffect(() => {
    let active = true;

    const loadLatest = async () => {
      if (fileInfo?.file_name) {
        return;
      }

      try {
        const response = await fetch(API_BASE_URL + '/api/scan/latest', { cache: 'no-store' });
        if (!response.ok) {
          if (response.status === 404 && active) {
            setFileInfo(null);
            setMessage('No review file is waiting in this session.');
          }
          return;
        }

        const payload = await response.json();
        if (!active) return;
        if (!isActionableLatest(payload)) {
          setFileInfo(null);
          setMessage('No review file is waiting in this session.');
          return;
        }

        const clearedMarker = localStorage.getItem(CLEARED_RESULT_KEY);
        const marker = buildMarker(payload);
        if (clearedMarker && clearedMarker === marker) {
          return;
        }

        setFileInfo(buildLatestPayload(payload));
        setIsManualUpload(false);
        setMessage(payload.message || '');
      } catch (_) {
        // keep current UI
      }
    };

    loadLatest();
    const timer = setInterval(loadLatest, LATEST_POLL_INTERVAL_MS);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [fileInfo?.file_name]);

  useEffect(() => {
    const fileName = fileInfo?.file_name;
    if (!fileName) return;

    let active = true;
    const refresh = async () => {
      try {
        const response = await fetch(API_BASE_URL + '/api/scan/results/' + encodeURIComponent(fileName), { cache: 'no-store' });
        if (response.status === 404) {
          if (!active) return;
          localStorage.removeItem('latestSandboxFile');
          setFileInfo(null);
          setIsManualUpload(false);
          setMessage('No file is currently available for review.');
          return;
        }
        if (!response.ok || !active) return;
        const payload = await response.json();
        setFileInfo(payload);
        if (isManualUpload) {
          localStorage.setItem('latestSandboxFile', JSON.stringify(payload));
        }
      } catch (_) {
        // keep cached result
      }
    };

    refresh();
    const timer = setInterval(refresh, LATEST_POLL_INTERVAL_MS);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [fileInfo?.file_name, isManualUpload]);

  useEffect(() => {
    onLatestResultChange?.(fileInfo?.overall_result || null);
  }, [fileInfo?.overall_result, onLatestResultChange]);

  const scan = fileInfo?.scan_result || null;
  const hasFile = Boolean(fileInfo?.file_name);
  const runtimeStatus = sandboxStatus?.runtime || null;
  const runtimeReady = Boolean(runtimeStatus?.ready);
  const runtimeMessage = runtimeStatus?.message || 'Project sandbox runtime is not ready.';
  const postAction = scan?.post_action || null;
  const modelName = scan?.model_name || mlStatus?.model_name || DEFAULT_MODEL_NAME;
  const architectureName = scan?.model_architecture || mlStatus?.architecture_name || 'Feed-Forward Neural Network';
  const artifactName = scan?.model_artifact_name || mlStatus?.model_artifact_name || 'cyber_shield_zero_day.pth';
  const risk = (scan?.engine === 'ml_unavailable' || scan?.engine === 'sandbox_unavailable') ? null : (typeof scan?.fused_risk === 'number' ? scan.fused_risk : null);
  const riskPercent = risk === null ? null : Math.max(0, Math.min(100, risk * 100));
  const resultText = hasFile ? (fileInfo?.overall_result || overallResult) : 'No file selected';
  const warningText = scan?.scanner_warning || '';
  const originalPath = scan?.original_path || null;
  const watchSource = scan?.watch_source || null;
  const isPendingQuarantineItem = hasFile && !isManualUpload && (!postAction || postAction === 'manual_review_required' || postAction === 'logged');
  const isSafePendingItem = isPendingQuarantineItem && resultText === 'Safe';
  const isUnsafePendingItem = isPendingQuarantineItem && resultText !== 'Safe';
  const showSaveButton = hasFile && isManualUpload;
  const showRestoreButton = isSafePendingItem;
  const showOverrideButton = isUnsafePendingItem;
  const showProjectSandboxButton = hasFile;
  const showDeleteButton = (hasFile && isManualUpload) || isPendingQuarantineItem;
  const showClearButton = hasFile;

  const tags = useMemo(() => {
    if (!scan) {
      return ['Project Sandbox: Idle', 'Threat Pattern: Idle', 'Model: Idle'];
    }

    const decisionTag = 'Decision: ' + (scan.decision || 'UNCERTAIN');
    const engineTag = 'Engine: ' + (scan.engine || 'unknown');
    const modelTag = 'Model: ' + (scan.engine === 'ml' ? modelName : 'Unavailable or heuristic fallback');
    const sourceTag = 'Value Source: ' + (scan.analysis_origin === 'project-sandbox' ? 'Project sandbox analysis' : 'Backend analysis');
    const runtimeTag = 'Runtime: ' + (scan.analysis_runtime || scan.sandbox_mode || 'unknown');
    return [decisionTag, engineTag, modelTag, sourceTag, runtimeTag];
  }, [scan, modelName]);

  const evidenceItems = useMemo(() => buildEvidence(scan, modelName, runtimeReady, runtimeMessage), [scan, modelName, runtimeReady, runtimeMessage]);

  const saveFile = async () => {
    if (!fileInfo?.file_name) {
      setMessage('No review file available. Upload from Scan Page first.');
      return;
    }

    setIsBusy(true);
    setMessage('Preparing file for save...');

    try {
      const response = await fetch(API_BASE_URL + '/api/scan/files/' + encodeURIComponent(fileInfo.file_name));
      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload?.detail || 'Failed to fetch file');
      }

      const blob = await response.blob();
      if (window.showSaveFilePicker) {
        const handle = await window.showSaveFilePicker({ suggestedName: fileInfo.file_name });
        const writable = await handle.createWritable();
        await writable.write(blob);
        await writable.close();
      } else {
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = fileInfo.file_name;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(url);
      }

      await fetch(API_BASE_URL + '/api/scan/files/' + encodeURIComponent(fileInfo.file_name), { method: 'DELETE' });
      localStorage.removeItem('latestSandboxFile');
      setFileInfo(null);
      setIsManualUpload(false);
      setMessage('File saved and removed from review storage.');
    } catch (error) {
      setMessage(getErrorMessage(error));
    } finally {
      setIsBusy(false);
    }
  };

  const restoreFile = async (targetDirectory = null, progressMessage = 'Restoring file to its source location...') => {
    if (!fileInfo?.file_name) {
      setMessage('No review file available to restore.');
      return false;
    }

    setIsBusy(true);
    setMessage(progressMessage);

    try {
      const response = await fetch(API_BASE_URL + '/api/scan/files/' + encodeURIComponent(fileInfo.file_name) + '/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_directory: targetDirectory })
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || 'Restore failed');
      }

      localStorage.removeItem('latestSandboxFile');
      setFileInfo(null);
      setIsManualUpload(false);
      setMessage('File restored to ' + payload.restored_path);
      return true;
    } catch (error) {
      setMessage(getErrorMessage(error));
      return false;
    } finally {
      setIsBusy(false);
    }
  };

  const downloadToUserChosenLocation = async (progressMessage) => {
    if (!fileInfo?.file_name) {
      setMessage('No review file available to release.');
      return false;
    }

    setIsBusy(true);
    setMessage(progressMessage);

    try {
      const response = await fetch(API_BASE_URL + '/api/scan/files/' + encodeURIComponent(fileInfo.file_name));
      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload?.detail || 'Failed to fetch review file');
      }

      const blob = await response.blob();
      if (window.showSaveFilePicker) {
        const handle = await window.showSaveFilePicker({ suggestedName: fileInfo.file_name });
        const writable = await handle.createWritable();
        await writable.write(blob);
        await writable.close();
      } else {
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = fileInfo.file_name;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(url);
      }

      const deleteResponse = await fetch(API_BASE_URL + '/api/scan/files/' + encodeURIComponent(fileInfo.file_name), {
        method: 'DELETE'
      });
      if (!deleteResponse.ok) {
        const payload = await deleteResponse.json();
        throw new Error(payload?.detail || 'Failed to clear review storage after save');
      }

      localStorage.removeItem('latestSandboxFile');
      setFileInfo(null);
      setIsManualUpload(false);
      setMessage('File saved to your chosen location and removed from quarantine.');
      return true;
    } catch (error) {
      setMessage(getErrorMessage(error));
      return false;
    } finally {
      setIsBusy(false);
    }
  };

  const chooseReleaseDirectory = async (progressMessage) => {
    if (window.showSaveFilePicker) {
      return downloadToUserChosenLocation(progressMessage);
    }

    const pickerResponse = await fetch(API_BASE_URL + '/api/scan/pick-release-directory', { method: 'POST' });
    const pickerPayload = await pickerResponse.json();
    if (!pickerResponse.ok) {
      throw new Error(pickerPayload?.detail || 'Directory picker failed');
    }

    const targetDirectory = String(pickerPayload.directory || '').trim();
    if (!targetDirectory) {
      setMessage('No save folder selected. File is still in quarantine.');
      return false;
    }

    return restoreFile(targetDirectory, progressMessage);
  };

  const promptSafeRelease = async () => {
    if (!fileInfo?.file_name) return;
    const shouldChooseDestination = window.confirm(
      'This file looks safe. Choose where to save it now?'
    );
    if (!shouldChooseDestination) {
      setMessage('Safe file is waiting in review storage until you choose a destination or delete it.');
      return;
    }

    try {
      await chooseReleaseDirectory('Moving safe file to your chosen folder...');
    } catch (error) {
      setMessage(getErrorMessage(error));
    }
  };

  const promptUnsafeRelease = async () => {
    if (!fileInfo?.file_name) return;
    const shouldOverride = window.confirm(
      'Warning: this file was flagged as ' + resultText + '. Release it anyway to a chosen folder?'
    );
    if (!shouldOverride) {
      await deleteFile();
      return;
    }

    try {
      await chooseReleaseDirectory('Releasing unsafe file to your chosen folder...');
    } catch (error) {
      setMessage(getErrorMessage(error));
    }
  };

  const deleteFile = async () => {
    if (!fileInfo?.file_name) {
      setMessage('No review file available to delete.');
      return;
    }

    setIsBusy(true);
    setMessage('Deleting file from review storage...');

    try {
      const response = await fetch(API_BASE_URL + '/api/scan/files/' + encodeURIComponent(fileInfo.file_name), {
        method: 'DELETE'
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || 'Delete failed');
      }

      localStorage.removeItem('latestSandboxFile');
      setFileInfo(null);
      setIsManualUpload(false);
      setMessage('Deleted: ' + payload.file_name);
    } catch (error) {
      setMessage(getErrorMessage(error));
    } finally {
      setIsBusy(false);
    }
  };

  const launchProjectSandbox = async () => {
    if (!fileInfo?.file_name) {
      setMessage('No review file available to open in the project sandbox.');
      return;
    }
    if (!runtimeReady) {
      setMessage(runtimeMessage);
      return;
    }

    setIsBusy(true);
    setMessage('Launching Project Sandbox...');

    try {
      const response = await fetch(API_BASE_URL + '/api/scan/files/' + encodeURIComponent(fileInfo.file_name) + '/launch-native-sandbox', {
        method: 'POST'
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || 'Sandbox launch failed');
      }
      setMessage(payload?.message || 'Project Sandbox launched.');
    } catch (error) {
      setMessage(getErrorMessage(error));
    } finally {
      setIsBusy(false);
    }
  };

  const clearResults = () => {
    const marker = buildMarker(scan || fileInfo || {});
    localStorage.setItem(CLEARED_RESULT_KEY, marker);
    localStorage.removeItem('latestSandboxFile');
    setFileInfo(null);
    setIsManualUpload(false);
    setMessage('Results cleared.');
  };

  useEffect(() => {
    if (!hasFile || isManualUpload || !isPendingQuarantineItem || isBusy) {
      return;
    }

    const marker = buildMarker(scan || fileInfo || {});
    if (!marker || localStorage.getItem(REVIEW_PROMPT_KEY) === marker) {
      return;
    }

    localStorage.setItem(REVIEW_PROMPT_KEY, marker);

    if (isSafePendingItem) {
      promptSafeRelease();
      return;
    }

    promptUnsafeRelease();
  }, [fileInfo, hasFile, isBusy, isManualUpload, isPendingQuarantineItem, isSafePendingItem, resultText, scan]);

  return (
    <section className='page result-page'>
      <div className='page-header-block'>
        <h2>Result Page</h2>
        <p className='page-help'>This page shows the current review item and explains the percentage using real backend values: model output, thresholds, warnings, and observed signals.</p>
      </div>

      <div className='result-grid roomy-grid'>
        <article className='card result-main spacious-card'>
          <p className='hero-kicker'>Active Model</p>
          <h3>{modelName}</h3>
          <p className='score'>
            {riskPercent === null ? '--' : riskPercent.toFixed(2)} <span>%</span>
          </p>
          <p className={resultClass(resultText)}>Result: {resultText}</p>
          <p className='muted-text'>
            {riskPercent === null
              ? 'Risk score is hidden because the trained-model verdict was unavailable for this run.'
              : 'This percentage is the backend fused risk value returned by the scanner for this exact file.'}
          </p>
          <div className='metric-stack'>
            <MetricBar label='Fused Risk' value={scan?.fused_risk} helper='Final score currently used for the decision.' tone={resultText === 'Malicious' ? 'bad' : resultText === 'Suspicious' ? 'warn' : 'good'} />
            <MetricBar label='Static Model Output' value={scan?.static_prob} helper={'Direct output from ' + modelName + '.'} tone='accent' />
          </div>
        </article>

        <article className='card result-layers spacious-card'>
          <h3>What The Percentage Means</h3>
          <div className='tag-list'>
            <span className='tag ok'>Architecture: {architectureName}</span>
            <span className='tag ok'>Artifact: {artifactName}</span>
            {tags.map((tag) => (
              <span key={tag} className='tag ok'>{tag}</span>
            ))}
          </div>
          <div className='summary-grid compact result-summary-grid'>
            <article className='card stat-card'>
              <h4>Allow Threshold</h4>
              <p>{formatThreshold(scan?.allow_threshold)}</p>
            </article>
            <article className='card stat-card'>
              <h4>Block Threshold</h4>
              <p>{formatThreshold(scan?.block_threshold)}</p>
            </article>
            <article className='card stat-card'>
              <h4>Analysis Origin</h4>
              <p className='stat-small'>{scan?.analysis_origin || '-'}</p>
            </article>
            <article className='card stat-card'>
              <h4>Sandbox Session</h4>
              <p className='stat-small'>{scan?.sandbox_session_id || '-'}</p>
            </article>
          </div>
          {warningText && <p className='scan-message'>{warningText}</p>}
          {watchSource && <p className='scan-meta'>Captured from: {prettifyWatchSource(watchSource)}</p>}
          {originalPath && <p className='scan-meta'>Original path: {originalPath}</p>}
          <p className='scan-meta'>Project sandbox runtime: {runtimeReady ? 'ready to launch' : runtimeMessage}</p>
          {isSafePendingItem && <p className='scan-meta'>Safe file waiting for destination selection before release.</p>}
          {isUnsafePendingItem && <p className='scan-meta'>Unsafe file stays in review storage until you delete it, open it in the project sandbox, or explicitly release it.</p>}
        </article>
      </div>

      <div className='card evidence-card spacious-card'>
        <h3>Evidence And Runtime Notes</h3>
        <div className='evidence-list'>
          {evidenceItems.map((item, index) => (
            <article key={item.title + '-' + index} className='evidence-item'>
              <h4>{item.title}</h4>
              <p>{item.detail}</p>
            </article>
          ))}
        </div>
      </div>

      <div className='action-row roomy-actions'>
        {showSaveButton && (
          <button type='button' className='btn' onClick={saveFile} disabled={isBusy || !hasFile}>Save</button>
        )}
        {showRestoreButton && (
          <button
            type='button'
            className='btn'
            onClick={() => promptSafeRelease()}
            disabled={isBusy || !hasFile}
          >
            Choose Save Folder
          </button>
        )}
        {showOverrideButton && (
          <button type='button' className='btn warn' onClick={() => promptUnsafeRelease()} disabled={isBusy || !hasFile}>Release Anyway</button>
        )}
        {showProjectSandboxButton && (
          <button
            type='button'
            className='btn secondary'
            onClick={launchProjectSandbox}
            disabled={isBusy || !hasFile || !runtimeReady}
            title={runtimeReady ? 'Open this review file inside the disposable project sandbox' : runtimeMessage}
          >
            Open In Project Sandbox
          </button>
        )}
        {showClearButton && (
          <button type='button' className='btn secondary' onClick={clearResults} disabled={isBusy}>Clear Results</button>
        )}
        {showDeleteButton && (
          <button type='button' className='btn danger' onClick={deleteFile} disabled={isBusy || !hasFile}>Delete</button>
        )}
      </div>
      {fileInfo?.file_name && <p className='scan-file'>Review file: {fileInfo.file_name}</p>}
      {message && <p className='scan-message'>{message}</p>}
    </section>
  );
}
