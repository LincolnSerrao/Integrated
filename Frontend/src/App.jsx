import React from 'react';
import { useMemo, useState } from 'react';
import Header from './components/Header';
import NavTabs from './components/NavTabs';
import DashboardPage from './pages/DashboardPage';
import ScanPage from './pages/ScanPage';
import ResultPage from './pages/ResultPage';
import LogsPage from './pages/LogsPage';
import SandboxConsolePage from './pages/SandboxConsolePage';

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';
const AUTO_OPEN_RESULT_KEY = 'autoOpenResultMarker';

const pages = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'scan', label: 'Scan Page' },
  { id: 'result', label: 'Result Page' },
  { id: 'logs', label: 'Logs Page' },
  { id: 'sandbox', label: 'Sandbox Console' }
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

function isActionableLatest(payload) {
  if (!payload) return false;
  return !payload.post_action || payload.post_action === 'manual_review_required' || payload.post_action === 'logged';
}

function buildLatestMarker(payload) {
  return (payload?.file_name || '') + ':' + (payload?.ts || '') + ':' + (payload?.post_action || '');
}

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [theme, setTheme] = useState('dark');
  const [sandboxStatus, setSandboxStatus] = useState(null);
  const [scanConfig, setScanConfig] = useState(null);
  const [mlStatus, setMlStatus] = useState(null);
  const [latestOverallResult, setLatestOverallResult] = useState(() => readCachedOverallResult());
  const systemStatus = mapResultToSystemStatus(latestOverallResult, sandboxStatus);

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
          fetch(API_BASE_URL + '/api/scan/sandbox-status', { cache: 'no-store' }),
          fetch(API_BASE_URL + '/api/scan/latest', { cache: 'no-store' }),
          fetch(API_BASE_URL + '/api/scan/config', { cache: 'no-store' }),
          fetch(API_BASE_URL + '/api/scan/ml-status', { cache: 'no-store' })
        ]);

        if (!active) return;

        if (sandboxResponse.status === 'fulfilled' && sandboxResponse.value.ok) {
          setSandboxStatus(await sandboxResponse.value.json());
        } else {
          setSandboxStatus(null);
        }

        if (latestResponse.status === 'fulfilled' && latestResponse.value.ok) {
          const payload = await latestResponse.value.json();
          setLatestOverallResult(payload?.overall_result || null);
          if (isActionableLatest(payload)) {
            const marker = buildLatestMarker(payload);
            const previousMarker = localStorage.getItem(AUTO_OPEN_RESULT_KEY);
            if (marker && marker !== previousMarker) {
              localStorage.setItem(AUTO_OPEN_RESULT_KEY, marker);
              setActivePage('result');
            }
          }
        } else {
          setLatestOverallResult((current) => current ?? readCachedOverallResult());
        }

        if (configResponse.status === 'fulfilled' && configResponse.value.ok) {
          setScanConfig(await configResponse.value.json());
        } else {
          setScanConfig(null);
        }

        if (mlResponse.status === 'fulfilled' && mlResponse.value.ok) {
          setMlStatus(await mlResponse.value.json());
        } else {
          setMlStatus(null);
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
    setTheme((currentTheme) => (currentTheme === 'dark' ? 'light' : 'dark'));
  };

  function statusClass(status) {
    if (status === 'Sandbox Offline') return 'status-pill danger';
    if (status === 'Threat Detected') return 'status-pill danger';
    if (status === 'Monitoring') return 'status-pill monitoring';
    return 'status-pill safe';
  }

  const activeContent = useMemo(() => {
    if (activePage === 'dashboard') {
      return (
        <DashboardPage
          sandboxStatus={sandboxStatus}
          mlStatus={mlStatus}
          scanConfig={scanConfig}
          onScanConfigChange={setScanConfig}
        />
      );
    }
    if (activePage === 'scan') {
      return (
        <ScanPage
          sandboxStatus={sandboxStatus}
          scanConfig={scanConfig}
          mlStatus={mlStatus}
          onLatestResultChange={setLatestOverallResult}
        />
      );
    }
    if (activePage === 'result') {
      return (
        <ResultPage
          overallResult={latestOverallResult || 'Safe'}
          onLatestResultChange={setLatestOverallResult}
          sandboxStatus={sandboxStatus}
          mlStatus={mlStatus}
        />
      );
    }
    if (activePage === 'logs') {
      return <LogsPage mlStatus={mlStatus} sandboxStatus={sandboxStatus} />;
    }
    return <SandboxConsolePage sandboxStatus={sandboxStatus} mlStatus={mlStatus} />;
  }, [activePage, latestOverallResult, mlStatus, sandboxStatus, scanConfig]);

  return (
    <div className='app-shell'>
      <Header systemStatus={systemStatus} statusClass={statusClass} />

      <div className='main-layout'>
        <aside className='sidebar'>
          <NavTabs pages={pages} activePage={activePage} onPageChange={setActivePage} />
          <button
            type='button'
            className='theme-toggle'
            onClick={toggleTheme}
            style={{ marginTop: '20px' }}
          >
            {theme === 'dark' ? 'Light mode' : 'Dark mode'}
          </button>
        </aside>

        <main className='content'>{activeContent}</main>
      </div>
    </div>
  );
}
