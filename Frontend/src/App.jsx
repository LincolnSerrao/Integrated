import React from 'react';
import { useMemo, useState } from 'react';
import Header from './components/Header';
import NavTabs from './components/NavTabs';
import DashboardPage from './pages/DashboardPage';
import ScanPage from './pages/ScanPage';
import ResultPage from './pages/ResultPage';
import LogsPage from './pages/LogsPage';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';

const pages = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'scan', label: 'Scan Page' },
  { id: 'result', label: 'Result Page' },
  { id: 'logs', label: 'Logs Page' }
];

function readCachedOverallResult() {
  try {
    const raw = localStorage.getItem('latestSandboxFile');
    if (!raw) return null;
    const payload = JSON.parse(raw);
    return payload?.overall_result || null;
  } catch (_) {
    return null;
  }
}

function mapResultToSystemStatus(result, sandboxStatus) {
  if (result === 'Malicious') return 'Threat Detected';
  if (result === 'Suspicious') return 'Monitoring';
  if (sandboxStatus && !sandboxStatus.ready) return 'Sandbox Offline';
  return 'Safe';
}

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [theme, setTheme] = useState('dark');
  const [sandboxStatus, setSandboxStatus] = useState(null);
  const [scanConfig, setScanConfig] = useState(null);
  const [mlStatus, setMlStatus] = useState(null);
  const [latestOverallResult, setLatestOverallResult] = useState(() => readCachedOverallResult());
  const systemStatus = mapResultToSystemStatus(latestOverallResult, sandboxStatus);

  // remember theme preference
  React.useEffect(() => {
    document.body.classList.toggle('light-mode', theme === 'light');
    localStorage.setItem('theme', theme);
  }, [theme]);

  React.useEffect(() => {
    const stored = localStorage.getItem('theme');
    if (stored === 'light' || stored === 'dark') {
      setTheme(stored);
    }
  }, []);

  React.useEffect(() => {
    let active = true;

    const loadSystemState = async () => {
      try {
        const [sandboxResponse, latestResponse, configResponse, mlResponse] = await Promise.allSettled([
          fetch(`${API_BASE_URL}/api/scan/sandbox-status`),
          fetch(`${API_BASE_URL}/api/scan/latest`),
          fetch(`${API_BASE_URL}/api/scan/config`),
          fetch(`${API_BASE_URL}/api/scan/ml-status`)
        ]);

        if (!active) return;

        if (sandboxResponse.status === 'fulfilled' && sandboxResponse.value.ok) {
          const payload = await sandboxResponse.value.json();
          setSandboxStatus(payload);
        } else {
          setSandboxStatus(null);
        }

        if (latestResponse.status === 'fulfilled' && latestResponse.value.ok) {
          const payload = await latestResponse.value.json();
          setLatestOverallResult(payload?.overall_result || null);
        } else {
          setLatestOverallResult((current) => current ?? readCachedOverallResult());
        }

        if (mlResponse.status === 'fulfilled' && mlResponse.value.ok) {
          const payload = await mlResponse.value.json();
          setMlStatus(payload);
        } else {
          setMlStatus(null);
        }

        if (configResponse.status === 'fulfilled' && configResponse.value.ok) {
          const payload = await configResponse.value.json();
          setScanConfig(payload);
        } else {
          setScanConfig(null);
        }
      } catch (_) {
        if (!active) return;
        setSandboxStatus(null);
        setScanConfig(null);
        setLatestOverallResult((current) => current ?? readCachedOverallResult());
      }
    };

    loadSystemState();
    const timer = setInterval(loadSystemState, 15000);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  const toggleTheme = () => {
    setTheme((t) => (t === 'dark' ? 'light' : 'dark'));
  };

  function statusClass(status) {
    if (status === 'Sandbox Offline') return 'status-pill danger';
    if (status === 'Threat Detected') return 'status-pill danger';
    if (status === 'Monitoring') return 'status-pill monitoring';
    return 'status-pill safe';
  }

  const activeContent = useMemo(() => {
    const stagingDir = scanConfig?.staging_dir || 'D:\\Download';

    if (activePage === 'dashboard') {
      return (
        <DashboardPage
          sandboxStatus={sandboxStatus}
          mlStatus={mlStatus}
          stagingDir={stagingDir}
        />
      );
    }
    if (activePage === 'scan') {
      return (
        <ScanPage
          sandboxStatus={sandboxStatus}
          stagingDir={stagingDir}
          onLatestResultChange={setLatestOverallResult}
        />
      );
    }
    if (activePage === 'result') {
      return (
        <ResultPage
          overallResult={latestOverallResult || 'Safe'}
          onLatestResultChange={setLatestOverallResult}
        />
      );
    }
    return <LogsPage />;
  }, [activePage, latestOverallResult, sandboxStatus, scanConfig]);

  return (
    <div className="app-shell">
      <Header systemStatus={systemStatus} statusClass={statusClass} />

      <div className="main-layout">
        <aside className="sidebar">
          <NavTabs pages={pages} activePage={activePage} onPageChange={setActivePage} />
          <button
            type="button"
            className="theme-toggle"
            onClick={toggleTheme}
            style={{ marginTop: '20px' }}
          >
            {theme === 'dark' ? '☀️ Light mode' : '🌙 Dark mode'}
          </button>
        </aside>

        <main className="content">{activeContent}</main>
      </div>
    </div>
  );
}
