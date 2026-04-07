import React, { useEffect, useMemo, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const CLEARED_RESULT_KEY = 'clearedResultMarker';
const REVIEW_PROMPT_KEY = 'reviewPromptMarker';
const LATEST_POLL_INTERVAL_MS = 5000;

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

export default function ResultPage({ overallResult, onLatestResultChange }) {
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
        const response = await fetch(API_BASE_URL + '/api/scan/latest');
        if (!response.ok) return;
        const payload = await response.json();
        if (!isActionableLatest(payload)) {
          setFileInfo(null);
          setMessage('No quarantined file is waiting for review in this session.');
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
      if (isManualUpload && fileInfo?.file_name) {
        return;
      }

      try {
        const response = await fetch(API_BASE_URL + '/api/scan/latest');
        if (!response.ok) {
          if (response.status === 404 && active) {
            setFileInfo(null);
            setMessage('No quarantined file is waiting for review in this session.');
          }
          return;
        }

        const payload = await response.json();
        if (!active) return;
        if (!isActionableLatest(payload)) {
          setFileInfo(null);
          setMessage('No quarantined file is waiting for review in this session.');
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
  }, [fileInfo?.file_name, isManualUpload]);

  useEffect(() => {
    const fileName = fileInfo?.file_name;
    if (!fileName || !isManualUpload) return;

    const refresh = async () => {
      try {
        const response = await fetch(API_BASE_URL + '/api/scan/results/' + encodeURIComponent(fileName));
        if (response.status === 404) {
          localStorage.removeItem('latestSandboxFile');
          setFileInfo(null);
          setIsManualUpload(false);
          setMessage('No file is currently available in quarantine.');
          return;
        }
        if (!response.ok) return;
        const payload = await response.json();
        setFileInfo(payload);
        setIsManualUpload(true);
        localStorage.setItem('latestSandboxFile', JSON.stringify(payload));
      } catch (_) {
        // keep cached result
      }
    };

    refresh();
  }, [fileInfo?.file_name, isManualUpload]);

  useEffect(() => {
    onLatestResultChange?.(fileInfo?.overall_result || null);
  }, [fileInfo?.overall_result, onLatestResultChange]);

  const scan = fileInfo?.scan_result || null;
  const hasFile = Boolean(fileInfo?.file_name);
  const postAction = scan?.post_action || null;
  const risk = typeof scan?.fused_risk === 'number' ? scan.fused_risk : null;
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
  const showDeleteButton = (hasFile && isManualUpload) || isPendingQuarantineItem;
  const showClearButton = hasFile;

  const tags = useMemo(() => {
    if (!scan) {
      return ['Quarantine: Idle', 'Threat Pattern: Idle', 'Hidden Data: Idle', 'Adversarial Check: Idle'];
    }

    const decisionTag = 'Decision: ' + (scan.decision || 'UNCERTAIN');
    const engineTag = 'Engine: ' + (scan.engine || 'unknown');
    const warnTag = scan.scanner_warning ? 'Model: Fallback mode' : 'Model: Active';
    return [decisionTag, engineTag, warnTag];
  }, [scan, risk]);

  const saveFile = async () => {
    if (!fileInfo?.file_name) {
      setMessage('No quarantine file available. Upload from Scan Page first.');
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
      setMessage('File saved and removed from quarantine.');
    } catch (error) {
      setMessage(getErrorMessage(error));
    } finally {
      setIsBusy(false);
    }
  };

  const restoreFile = async (targetDirectory = null, progressMessage = 'Restoring file to its source location...') => {
    if (!fileInfo?.file_name) {
      setMessage('No quarantined file available to restore.');
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
      setMessage('No quarantined file available to release.');
      return false;
    }

    setIsBusy(true);
    setMessage(progressMessage);

    try {
      const response = await fetch(API_BASE_URL + '/api/scan/files/' + encodeURIComponent(fileInfo.file_name));
      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload?.detail || 'Failed to fetch quarantined file');
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
        throw new Error(payload?.detail || 'Failed to clear quarantine after save');
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
      setMessage('Safe file is waiting in quarantine until you choose a destination or delete it.');
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
      setMessage('No quarantine file available to delete.');
      return;
    }

    setIsBusy(true);
    setMessage('Deleting file from quarantine...');

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
    <section className='page'>
      <h2>Result Page</h2>
      <p className='page-help'>This page shows the current quarantine result for this session, not old historical items.</p>

      <div className='result-grid'>
        <article className='card result-main'>
          <h3>Risk Estimate</h3>
          <p className='score'>
            {riskPercent === null ? '--' : riskPercent.toFixed(2)} <span>%</span>
          </p>
          <p className={resultClass(resultText)}>Result: {resultText}</p>
          <p className='muted-text'>This value comes directly from the backend fused risk output.</p>
        </article>

        <article className='card result-layers'>
          <h3>What We Checked</h3>
          <div className='tag-list'>
            {tags.map((tag) => (
              <span key={tag} className='tag ok'>{tag}</span>
            ))}
          </div>
          {warningText && <p className='scan-message'>{warningText}</p>}
          {watchSource && <p className='scan-meta'>Captured from: {watchSource}</p>}
          {originalPath && <p className='scan-meta'>Original path: {originalPath}</p>}
          {isSafePendingItem && <p className='scan-meta'>Safe file waiting for destination selection before release.</p>}
          {isUnsafePendingItem && <p className='scan-meta'>Unsafe file remains quarantined until you delete it or clear the result.</p>}
        </article>
      </div>

      <div className='action-row'>
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
        {showClearButton && (
          <button type='button' className='btn secondary' onClick={clearResults} disabled={isBusy}>Clear Results</button>
        )}
        {showDeleteButton && (
          <button type='button' className='btn danger' onClick={deleteFile} disabled={isBusy || !hasFile}>Delete</button>
        )}
      </div>
      {fileInfo?.file_name && <p className='scan-file'>Quarantine file: {fileInfo.file_name}</p>}
      {message && <p className='scan-message'>{message}</p>}
    </section>
  );
}
