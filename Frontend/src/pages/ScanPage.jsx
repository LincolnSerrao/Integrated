import React, { useMemo, useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';

export default function ScanPage({ sandboxStatus, stagingDir, onLatestResultChange }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [message, setMessage] = useState('');
  const [result, setResult] = useState(null);
  const sandboxReady = Boolean(sandboxStatus?.ready);
  const targetDir = stagingDir || 'D:\\Download';
  const providerName = sandboxStatus?.provider_name || 'Sandbox';

  const currentStep = useMemo(() => {
    if (isUploading) return 2;
    if (result) return 6;
    if (selectedFile) return 1;
    return 0;
  }, [isUploading, result, selectedFile]);

  const handleFileChange = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setSelectedFile(file);
    setResult(null);
    setMessage('Uploading file to sandbox queue...');
    setIsUploading(true);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`${API_BASE_URL}/api/scan/upload`, {
        method: 'POST',
        body: formData
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.detail || 'Upload failed');
      }

      localStorage.setItem('latestSandboxFile', JSON.stringify(payload));
      onLatestResultChange?.(payload?.overall_result || null);
      setResult(payload);
      setMessage(`Queued: ${payload.file_name}`);
    } catch (error) {
      const isNetworkError = error instanceof TypeError && String(error.message || '').toLowerCase().includes('fetch');
      if (isNetworkError) {
        setMessage(`Cannot reach backend at ${API_BASE_URL}. Start FastAPI server and retry.`);
      } else {
        setMessage(error.message || 'Upload failed');
      }
      setResult(null);
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <section className="page">
      <h2>Scan Page</h2>
      <p className="page-help">
        Automatic sandboxing only works when the configured sandbox is available and the browser or app
        downloads directly into <strong>{targetDir}</strong>. Manual upload is always available.
      </p>

      <div className={`card status-note ${sandboxReady ? 'good' : 'warn'}`}>
        <h3>{providerName} Status</h3>
        <p>{sandboxStatus?.message || `Checking ${providerName} availability...`}</p>
      </div>

      <div className="card scan-config-card">
        <h3>Automatic Download Setup</h3>
        <p className="muted-text">
          Set your browser or app download location to <strong>{targetDir}</strong>.
          {' '}
          {sandboxReady
            ? `When the download finishes there, the sandbox monitor will try to open ${providerName} automatically.`
            : `This machine is not ready for ${providerName}, so downloads there will not open the sandbox automatically yet.`}
        </p>
      </div>

      <div className="card upload-card">
        <h3>Manual File Check</h3>
        <label htmlFor="scanFileInput" className="upload-dropzone">
          <span>{isUploading ? 'Uploading...' : 'Click here to choose a file'}</span>
          <span className="muted">File will be scanned immediately after upload</span>
          <input id="scanFileInput" type="file" onChange={handleFileChange} disabled={isUploading} />
        </label>
        {selectedFile && <p className="scan-file">Selected: {selectedFile.name}</p>}
        {message && <p className="scan-message">{message}</p>}
        {result?.staging_path && <p className="scan-meta">Staging path: {result.staging_path}</p>}
      </div>

      <ol className="step-list">
        <li className={`step ${currentStep >= 1 ? 'done' : ''}`}>1. File Detected</li>
        <li className={`step ${currentStep === 2 ? 'current' : currentStep > 2 ? 'done' : ''}`}>2. Queued in Sandbox</li>
        <li className={`step ${currentStep >= 3 ? 'done' : ''}`}>3. Checking New Threat Patterns</li>
        <li className={`step ${currentStep >= 4 ? 'done' : ''}`}>4. Checking Hidden Data</li>
        <li className={`step ${currentStep >= 5 ? 'done' : ''}`}>5. Checking Adversarial Attacks</li>
        <li className={`step ${currentStep >= 6 ? 'done' : ''}`}>6. Scan Completed</li>
      </ol>
    </section>
  );
}
