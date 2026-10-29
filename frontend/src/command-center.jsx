import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Database,
  Download,
  Eye,
  EyeOff,
  FileText,
  Globe2,
  History,
  Mail,
  Menu,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  Upload,
  XCircle,
} from 'lucide-react';
import { createScanReportPdf, scanReportPdfBase64 } from './report-utils';
import './command-center.css';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || `${window.location.protocol}//${window.location.hostname}:8000`;
const AuthContext = createContext(null);

const navItems = [
  ['dashboard', 'Dashboard', Shield],
  ['email-scanner', 'Email scan', Mail],
  ['website-scanner', 'URL scan', Globe2],
  ['scan-history', 'History', History],
  ['datasets', 'Datasets', Database],
  ['settings', 'Settings', Settings],
];

function route() {
  return (window.location.hash.replace('#/', '').replace('#', '') || 'dashboard').split('?')[0];
}

function rememberUrlForScan(url) {
  localStorage.setItem('kesihba-pending-url', url);
}

async function api(path, options) {
  const headers = new Headers(options?.headers || {});
  if (options?.method && options.method.toUpperCase() !== 'GET') {
    headers.set('X-KESIHBA-CSRF', '1');
  }
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
    credentials: 'include',
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = body?.detail;
    const message = Array.isArray(detail) ? detail[0]?.msg : detail;
    throw new Error(typeof message === 'string' ? message : `Request failed (${response.status}).`);
  }
  return body;
}

async function apiWithTimeout(path, options, timeoutMs = 20000) {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await api(path, { ...options, signal: controller.signal });
  } catch (error) {
    if (error?.name === 'AbortError') {
      throw new Error('The scan took too long. Check the backend network connection and try again.');
    }
    throw error;
  } finally {
    window.clearTimeout(timeoutId);
  }
}

function App() {
  const [page, setPage] = useState(route());
  const [menuOpen, setMenuOpen] = useState(false);
  const [user, setUser] = useState(null);
  const [authView, setAuthView] = useState(null);
  const [authCancelAction, setAuthCancelAction] = useState(null);
  const [emailDeliveryConfigured, setEmailDeliveryConfigured] = useState(null);
  const [serviceStatus, setServiceStatus] = useState({
    backend: 'loading',
    models: 'loading',
    threats: 'loading',
  });
  const [intelDetail, setIntelDetail] = useState('Threat intelligence status is loading.');

  useEffect(() => {
    const onHashChange = () => {
      setPage(route());
      setMenuOpen(false);
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadStatus() {
      try {
        const health = await api('/health');
        if (!cancelled) {
          setServiceStatus((current) => ({
            ...current,
            backend: health?.status === 'ok' ? 'connected' : 'unavailable',
          }));
        }
      } catch {
        if (!cancelled) {
          setServiceStatus((current) => ({
            ...current,
            backend: 'disconnected',
          }));
        }
      }

      try {
        const models = await api('/api/models');
        if (!cancelled) {
          const modelAvailable = Boolean(models?.email_model?.available || models?.url_model?.available);
          setServiceStatus((current) => ({
            ...current,
            models: modelAvailable ? 'connected' : 'unavailable',
          }));
        }
      } catch {
        if (!cancelled) {
          setServiceStatus((current) => ({
            ...current,
            models: 'unavailable',
          }));
        }
      }

      try {
        const intel = await api('/api/intelligence/status');
        if (!cancelled) {
          const liveFeeds = Array.isArray(intel?.feeds) ? intel.feeds.some((feed) => feed?.enabled) : false;
          const vtConnection = intel?.virustotal?.connection?.status;
          const vtAvailable = ['connected', 'not_configured'].includes(vtConnection);
          const vtState = vtConnection === 'connected'
            ? 'connected'
            : vtConnection === 'not_configured'
              ? 'unavailable'
              : ['configured', 'not_checked'].includes(vtConnection)
                ? 'loading'
                : 'disconnected';
          const vtMessage = intel?.virustotal?.connection?.message || intel?.virustotal?.connection?.error;
          setIntelDetail([
            `VirusTotal: ${vtConnection || 'unknown'}${vtMessage ? ` (${vtMessage})` : ''}`,
            `Threat feeds: ${liveFeeds ? 'available' : 'unavailable'}`,
          ].join(' · '));
          setServiceStatus((current) => ({
            ...current,
            threats: vtConnection === 'connected' ? 'connected' : vtState,
          }));
        }
      } catch {
        if (!cancelled) {
          setIntelDetail('Unable to read threat intelligence status.');
          setServiceStatus((current) => ({
            ...current,
            threats: 'unavailable',
          }));
        }
      }
    }

    loadStatus();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    api('/api/auth/me').then(({ user: signedInUser }) => {
      if (!cancelled) setUser(signedInUser || null);
    }).catch(() => {});
    api('/api/auth/status').then((status) => {
      if (!cancelled) setEmailDeliveryConfigured(Boolean(status.email_delivery_configured));
    }).catch(() => {
      if (!cancelled) setEmailDeliveryConfigured(false);
    });
    return () => { cancelled = true; };
  }, []);

  async function signOut() {
    try {
      await api('/api/auth/logout', { method: 'POST' });
      setUser(null);
      setAuthView(null);
      setAuthCancelAction(null);
      window.location.hash = '#/dashboard';
    } catch (error) {
      window.alert(error.message);
    }
  }

  const title = navItems.find(([id]) => id === page)?.[1] || 'Dashboard';
  function openAuth(mode, onCancel) {
    setAuthCancelAction(() => onCancel || null);
    setAuthView(mode);
  }
  function closeAuth(cancelled = true) {
    if (cancelled) authCancelAction?.();
    setAuthCancelAction(null);
    setAuthView(null);
  }
  const authValue = { user, setUser, openAuth, emailDeliveryConfigured };

  return (
    <AuthContext.Provider value={authValue}>
    <div className="app-shell">
      <aside className={`sidebar ${menuOpen ? 'open' : ''}`}>
        <a className="brand" href="#/dashboard" aria-label="KESHIHBA dashboard" onClick={() => setMenuOpen(false)}>
          <span className="brand-mark"><Shield size={20} /></span>
          <span><strong>KESHIHBA</strong><small>Phishing Threat Intelligence</small></span>
        </a>
        <nav>
          <p>Scan workflow</p>
          {navItems.map(([id, label, Icon]) => (
            <a className={page === id ? 'active' : ''} href={`#/${id}`} key={id} onClick={() => setMenuOpen(false)}>
              <Icon size={17} />{label}
            </a>
          ))}
        </nav>
        <div className="side-help">
          <strong>Recommended order</strong>
          <span>1. Scan email or URL</span>
          <span>2. Read reasons</span>
          <span>3. Follow recommendation</span>
        </div>
      </aside>
      {menuOpen && <button className="overlay" onClick={() => setMenuOpen(false)} aria-label="Close menu" />}
      <div className="workspace">
        <header className="topbar">
          <button className="menu-button" onClick={() => setMenuOpen(true)} aria-label="Open menu" aria-expanded={menuOpen}><Menu size={20} /></button>
          <div className="topbar-copy">
            <strong>{title}</strong>
          </div>
          <div className="status-strip" aria-live="polite">
            <StatusPill label="API" description="Backend API" state={serviceStatus.backend} />
            <StatusPill label="Models" description="Detection models" state={serviceStatus.models} />
            <StatusPill label="Intel" description={intelDetail} state={serviceStatus.threats} />
          </div>
          <a className="quick-link" href="#/email-scanner">Start scan</a>
          <div className="header-account">
            {user ? (
              <>
                <span className="account-identity"><strong>{user.name}</strong><small>{user.email}</small></span>
                <Button type="button" secondary onClick={signOut}>Sign out</Button>
              </>
            ) : <Button type="button" onClick={() => openAuth('login')}>Log in</Button>}
          </div>
        </header>
        <main className="main-content"><Page page={page} /></main>
      </div>
      {authView && <AuthScreen mode={authView} onModeChange={setAuthView} onClose={closeAuth} onAuthenticated={setUser} />}
    </div>
    </AuthContext.Provider>
  );
}

function useAuth() {
  return useContext(AuthContext);
}

function StatusPill({ label, description, state }) {
  const displayState = {
    loading: 'Checking',
    connected: 'Connected',
    disconnected: 'Disconnected',
    unavailable: 'Unavailable',
  }[state] || 'Unavailable';

  return (
    <span className={`service-status ${state || 'unavailable'}`} title={`${description}: ${displayState}`} aria-label={`${description}: ${displayState}`}>
      <span className="status-dot" />{label}<span className="status-state">{displayState}</span>
    </span>
  );
}

function Page({ page }) {
  if (page === 'email-scanner') return <EmailScanner />;
  if (page === 'website-scanner') return <URLScanner />;
  if (page === 'scan-history') return <HistoryPage />;
  if (page === 'datasets') return <DatasetPage />;
  if (page === 'settings') return <SettingsPage />;
  return <Dashboard />;
}

function Intro({ eyebrow, title, children }) {
  return <div className="intro"><p className="eyebrow">{eyebrow}</p><h1>{title}</h1>{children && <p>{children}</p>}</div>;
}

function Button({ secondary = false, className = '', children, ...props }) {
  return <button className={`button ${secondary ? 'secondary' : ''} ${className}`.trim()} {...props}>{children}</button>;
}

function Field({ label, hint, children }) {
  return <label className="field"><span>{label}</span>{children}{hint && <small>{hint}</small>}</label>;
}

function AuthScreen({ mode, onModeChange, onClose, onAuthenticated }) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const signingUp = mode === 'signup';
  const strength = [
    password.length >= 12,
    /[a-z]/.test(password) && /[A-Z]/.test(password),
    /\d/.test(password),
    /[^A-Za-z0-9]/.test(password),
  ].filter(Boolean).length;

  async function submit(event) {
    event.preventDefault();
    setError('');
    setMessage('');
    if (signingUp && password !== confirmation) {
      setError('Passwords do not match.');
      return;
    }
    setBusy(true);
    try {
      const result = await api(`/api/auth/${signingUp ? 'signup' : 'login'}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signingUp ? { name, email, password } : { email, password }),
      });
      if (!result.user) {
        setMessage(result.message);
        if (signingUp) onModeChange('login');
        return;
      }
      onAuthenticated(result.user);
      onClose(false);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-overlay" role="presentation">
      <section className="auth-card" role="dialog" aria-modal="true" aria-labelledby="auth-title">
        <button className="auth-close" type="button" onClick={onClose} aria-label="Close sign in"><XCircle size={20} /></button>
        <span className="auth-brand">
          <span className="brand-mark"><Shield size={20} /></span>
          <span><strong>KESHIHBA</strong><small>Phishing Threat Intelligence</small></span>
        </span>
        <p className="eyebrow">{signingUp ? 'Create account' : 'Welcome back'}</p>
        <h1 id="auth-title">{signingUp ? 'Sign up' : 'Log in'}</h1>
        <p className="auth-description">Scanning and PDF downloads remain available to everyone. An account is only needed to email reports.</p>
        <form className="form-stack auth-form" onSubmit={submit}>
          {signingUp && <Field label="Name"><input required minLength={2} maxLength={100} autoComplete="name" value={name} onChange={(event) => setName(event.target.value)} /></Field>}
          <Field label="Email address"><input required type="email" maxLength={254} autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} /></Field>
          <Field label="Password" hint={signingUp ? 'Use at least 12 characters. A mix of letters, numbers, and symbols is stronger.' : undefined}>
            <span className="password-field">
              <input required type={showPassword ? 'text' : 'password'} minLength={signingUp ? 12 : 1} maxLength={128} autoComplete={signingUp ? 'new-password' : 'current-password'} value={password} onChange={(event) => setPassword(event.target.value)} />
              <button type="button" onClick={() => setShowPassword((visible) => !visible)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button>
            </span>
          </Field>
          {signingUp && <>
            <div className="password-strength" aria-live="polite">
              <span className={`strength-meter strength-${strength}`} />
              <small>{password ? `Password strength: ${strength >= 4 ? 'strong' : strength >= 2 ? 'fair' : 'needs work'}` : 'Password strength'}</small>
            </div>
            <Field label="Confirm password"><input required type={showPassword ? 'text' : 'password'} maxLength={128} autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></Field>
          </>}
          {error && <ErrorBox message={error} />}
          {message && <p className="auth-message" role="status">{message}</p>}
          <Button type="submit" disabled={busy}>{busy ? 'Please wait...' : signingUp ? 'Create account' : 'Log in'}</Button>
        </form>
        {!signingUp && <p className="auth-note">Password reset is not configured. Contact the KESHIHBA administrator if you cannot access your account.</p>}
        <p className="auth-switch">
          {signingUp ? 'Already have an account?' : 'New to KESHIHBA?'}{' '}
          <button type="button" onClick={() => { setError(''); setMessage(''); onModeChange(signingUp ? 'login' : 'signup'); }}>
            {signingUp ? 'Log in' : 'Sign up'}
          </button>
        </p>
        <button className="auth-guest" type="button" onClick={onClose}>Continue as Guest</button>
      </section>
    </div>
  );
}

function Badge({ status }) {
  const className = String(status || 'unknown').toLowerCase().replace(/\s+/g, '-');
  return <span className={`badge ${className}`}>{status || 'Unknown'}</span>;
}

function formatPercent(value) {
  return typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : '--';
}

function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [models, setModels] = useState(null);
  const { user } = useAuth();

  useEffect(() => {
    api('/api/scans/summary').then(setSummary).catch(() => setSummary(null));
    api('/api/models').then(setModels).catch(() => setModels(null));
  }, [user?.id]);

  const counts = summary?.counts || {};
  return (
    <>
      <Intro eyebrow="Start here" title="Choose what you want to check">
        KESHIHBA scans suspicious emails and URLs. Each result gives a classification, risk score, reasons, and a recommended action.
      </Intro>
      <section className="action-grid">
        <ActionCard icon={Mail} title="Suspicious email" href="#/email-scanner" cta="Scan email">
          Paste an email or upload an .eml file to detect phishing, scam, spam, sender issues, and unsafe links.
        </ActionCard>
        <ActionCard icon={Globe2} title="Website or link" href="#/website-scanner" cta="Scan URL">
          Check URL structure, local URL model output, threat feeds, and VirusTotal reputation when configured.
        </ActionCard>
      </section>
      <section className="metrics-row">
        <Metric label="Total scans" value={counts.total ?? '--'} />
          <Metric label="No known threat" value={counts.safe ?? '--'} tone="safe" />
        <Metric label="Suspicious" value={counts.suspicious ?? '--'} tone="warning" />
        <Metric label="High risk" value={counts.high_risk ?? '--'} tone="danger" />
        <Metric label="Malicious" value={counts.malicious ?? '--'} tone="danger" />
        <Metric label="Unknown" value={counts.unknown ?? '--'} />
      </section>
      <section className="surface">
        <div className="section-head">
          <div><p className="eyebrow">Models in use</p><h2>Current detection data</h2></div>
          <a href="#/datasets">View datasets</a>
        </div>
        <div className="model-grid">
          <ModelSummary title="Email phishing model" data={models?.email_model} />
          <ModelSummary title="URL phishing model" data={models?.url_model} />
        </div>
      </section>
    </>
  );
}

function ActionCard({ icon: Icon, title, href, cta, children }) {
  return <a className="action-card" href={href}><Icon size={24} /><h2>{title}</h2><p>{children}</p><strong>{cta}</strong></a>;
}

function Metric({ label, value, tone = '' }) {
  return <div className="metric"><strong className={tone}>{value}</strong><span>{label}</span></div>;
}

function ModelSummary({ title, data }) {
  const confusion = data?.confusion_matrix_labels_0_then_1;
  return (
    <div className="model-card">
      <h3>{title}</h3>
      <p>{data?.dataset || 'Not trained yet'}</p>
      {data?.synthetic_dataset && (
        <div className="model-caveat" role="note">
          Synthetic-data benchmark only; this is not real-world validation. Real-world accuracy is unknown.
        </div>
      )}
      {data?.evaluation_type === 'cross_corpus_holdout' && (
        <div className="model-caveat" role="note">
          Cross-corpus research benchmark only; EPVME malicious emails are evaluated against Enron ham.
          This is not current real-world accuracy. A near-perfect score may reflect differences between the sources,
          not reliable phishing detection.
        </div>
      )}
      <dl>
        <div><dt>Training samples</dt><dd>{data?.train_samples ?? '--'}</dd></div>
        <div><dt>Test samples</dt><dd>{data?.test_samples ?? '--'}</dd></div>
        <div><dt>{data?.accuracy_label || 'Holdout accuracy'}</dt><dd>{formatPercent(data?.accuracy)}</dd></div>
        <div><dt>Precision</dt><dd>{formatPercent(data?.precision)}</dd></div>
        <div><dt>Recall</dt><dd>{formatPercent(data?.recall)}</dd></div>
        <div><dt>F1 score</dt><dd>{formatPercent(data?.f1)}</dd></div>
        <div><dt>False-positive rate</dt><dd>{formatPercent(data?.false_positive_rate)}</dd></div>
        <div><dt>False-negative rate</dt><dd>{formatPercent(data?.false_negative_rate)}</dd></div>
        <div><dt>Confusion matrix (TN, FP / FN, TP)</dt><dd>{Array.isArray(confusion) ? confusion.map((row) => row.join(', ')).join(' / ') : '--'}</dd></div>
      </dl>
      {data?.limitations && <small>{data.limitations}</small>}
    </div>
  );
}

function EmailScanner() {
  const [email, setEmail] = useState({ sender: '', subject: '', body: '' });
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [dragActive, setDragActive] = useState(false);

  const update = (key) => (event) => setEmail({ ...email, [key]: event.target.value });

  async function submit(event) {
    event.preventDefault();
    setResult(null);
    setError('');
    setLoading(true);
    try {
      setResult(await api('/api/analyze/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(email),
      }));
    } catch (requestError) {
      setError(`${requestError.message}. Start the backend and check VITE_API_BASE_URL.`);
    } finally {
      setLoading(false);
    }
  }

  async function uploadFile(file) {
    if (!file) return;
    const allowed = /\.(eml|pdf|doc|docx|txt|html|htm)$/i;
    if (!allowed.test(file.name) && !['message/rfc822', 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain', 'text/html'].includes(file.type)) {
      setError('Unsupported file type. Upload an .eml, .pdf, .doc, .docx, or .txt file.');
      return;
    }
    setResult(null);
    setError('');
    setLoading(true);
    try {
      const form = new FormData();
      form.append('file', file);
      setResult(await api('/api/analyze/email', {
        method: 'POST',
        body: form,
      }));
    } catch (requestError) {
      setError(`${requestError.message}. The backend could not process the uploaded file.`);
    } finally {
      setLoading(false);
    }
  }

  async function loadFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    await uploadFile(file);
    event.target.value = '';
  }

  async function handleDrop(event) {
    event.preventDefault();
    setDragActive(false);
    const file = event.dataTransfer?.files?.[0];
    if (file) await uploadFile(file);
  }

  return (
    <>
      <Intro eyebrow="Email scan" title="Paste or upload a suspicious email">
        Click Analyze Email to review spam, scam, phishing, and sender evidence. A low-risk result means no known threat was detected; it does not prove the message is safe.
      </Intro>
      <div className="two-column scanner-grid">
        <section className="surface">
          <form className="form-stack" onSubmit={submit}>
            <Field label="Sender email" hint="Use the From address when available.">
              <input type="email" value={email.sender} onChange={update('sender')} placeholder="security@example.com" />
            </Field>
            <Field label="Subject">
              <input value={email.subject} onChange={update('subject')} placeholder="Email subject" />
            </Field>
            <Field label="Email content">
              <textarea required value={email.body} onChange={update('body')} placeholder="Paste the full email body here" />
            </Field>
            <div className="button-row">
              <Button type="submit" disabled={loading}><Search size={16} />{loading ? 'Analyzing...' : 'Analyze Email'}</Button>
              <label
                className={`file-button ${dragActive ? 'drag-active' : ''}`}
                onDragOver={(event) => { event.preventDefault(); setDragActive(true); }}
                onDragLeave={() => setDragActive(false)}
                onDrop={handleDrop}
              >
                <Upload size={16} />Upload email file
                <input type="file" accept=".eml,.pdf,.doc,.docx,.txt,.html,.htm,message/rfc822,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain,text/html" onChange={loadFile} />
              </label>
            </div>
          </form>
          {error && <ErrorBox message={error} />}
        </section>
        {result ? <EmailResult result={result} /> : <EmptyResult icon={Mail} title="Email result appears here" text="Look for the risk score, reasons, extracted URLs, spam/scam score, and recommendation." />}
      </div>
    </>
  );
}

function URLScanner() {
  const [url, setUrl] = useState(() => localStorage.getItem('kesihba-pending-url') || '');
  const [result, setResult] = useState(null);
  const [batchMode, setBatchMode] = useState(false);
  const [batchInput, setBatchInput] = useState('');
  const [batchResults, setBatchResults] = useState([]);
  const [batchFilter, setBatchFilter] = useState('all');
  const [toolResults, setToolResults] = useState({});
  const [toolLoading, setToolLoading] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const pending = localStorage.getItem('kesihba-pending-url');
    if (pending) {
      setUrl(pending);
      localStorage.removeItem('kesihba-pending-url');
    }
  }, []);

  async function submit(event) {
    event.preventDefault();
    setResult(null);
    setBatchResults([]);
    setToolResults({});
    setError('');
    setLoading(true);
    try {
      if (batchMode) {
        const urls = batchInput.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
        if (!urls.length || urls.length > 10) throw new Error('Enter between 1 and 10 URLs.');
        const response = await apiWithTimeout('/api/analyze/urls', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ urls }),
        });
        setBatchResults(response.results || []);
      } else {
        setResult(await apiWithTimeout('/api/analyze/url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url }),
        }));
      }
    } catch (requestError) {
      setError(`${requestError.message}. Start the backend and check VITE_API_BASE_URL.`);
    } finally {
      setLoading(false);
    }
  }

  async function runTool(tool) {
    if (!result?.hostname) return;
    setError('');
    setToolLoading(tool);
    try {
      let data;
      if (tool === 'expand') {
        data = await api('/api/tools/link-expander', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: result.submitted_url || result.url }),
        });
      } else if (tool === 'ip') {
        data = await api(`/api/tools/ip-reputation?address=${encodeURIComponent(result.hostname)}`);
      } else {
        data = await api(`/api/tools/${tool}?hostname=${encodeURIComponent(result.hostname)}`);
      }
      setToolResults((current) => ({ ...current, [tool]: data }));
      if (tool === 'expand') {
        setResult((current) => ({
          ...current,
          final_url: data.final_url || null,
          redirect_chain: data.redirects || [],
          checks: {
            ...(current.checks || {}),
            redirect_analysis: data.status === 'expanded'
              ? 'completed'
              : data.status === 'unavailable'
                ? 'error'
                : 'unknown',
          },
          limitations: data.status === 'expanded'
            ? (current.limitations || []).filter((item) => !item.startsWith('HTTP redirect chains were not followed'))
            : current.limitations,
        }));
      }
    } catch (requestError) {
      setError(`${tool} check failed: ${requestError.message}`);
    } finally {
      setToolLoading('');
    }
  }

  const filteredBatchResults = batchResults.filter((item) => (
    batchFilter === 'all' || String(item.classification).toLowerCase() === batchFilter
  ));

  return (
    <>
      <Intro eyebrow="Cybersecurity investigation" title="Gather evidence on a suspicious link">
        Check URL structure, DNS and domain details, approximate public-IP network location, local model signals, and available threat reputation. Results identify the link and explain the findings; submitted pages are not automatically opened.
      </Intro>
      <div className="two-column scanner-grid">
        <section className="surface">
          <div className="button-row scan-mode" role="group" aria-label="URL scan mode">
            <Button className={batchMode ? 'secondary' : ''} type="button" aria-pressed={!batchMode} onClick={() => setBatchMode(false)}>Single URL</Button>
            <Button className={batchMode ? '' : 'secondary'} type="button" aria-pressed={batchMode} onClick={() => setBatchMode(true)}>Batch scan (up to 10)</Button>
          </div>
          <form className="form-stack url-scan-form" onSubmit={submit}>
            {batchMode ? (
              <Field label="URLs to scan" hint="Enter one URL per line or separate URLs with commas. Maximum 10.">
                <textarea required value={batchInput} onChange={(event) => setBatchInput(event.target.value)} placeholder={'https://example.com\nhttps://another.example/login'} />
              </Field>
            ) : (
              <Field label="Website URL" hint="The scanner checks the hostname and threat evidence without browsing the submitted page.">
                <input required value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com/login" />
              </Field>
            )}
            <Button className="url-submit" type="submit" disabled={loading}><Globe2 size={16} />{loading ? 'Scanning...' : batchMode ? 'Scan URLs' : 'Scan URL'}</Button>
          </form>
          {!batchMode && result?.hostname && (
            <div className="result-section">
              <h3>Additional checks</h3>
              <p className="explanation">These checks contact only public destinations, use short timeouts, and stop on private or local addresses.</p>
              <div className="button-row tool-buttons">
                {[
                  ['dns', 'DNS records'],
                  ['ssl', 'SSL certificate'],
                  ['domain-age', 'Domain age'],
                  ['expand', 'Expand redirects'],
                  ...(result.hostname.includes(':') || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(result.hostname) ? [['ip', 'IP reputation']] : []),
                ].map(([id, label]) => (
                  <Button key={id} type="button" secondary onClick={() => runTool(id)} disabled={Boolean(toolLoading)}>
                    {toolLoading === id ? 'Checking...' : label}
                  </Button>
                ))}
              </div>
              {Object.entries(toolResults).map(([tool, data]) => <ToolResult key={tool} name={tool} data={data} />)}
            </div>
          )}
          {error && <ErrorBox message={error} />}
        </section>
        {result && !batchMode ? <URLResult result={result} /> : <EmptyResult icon={Globe2} title="URL result appears here" text="Results separate the uncalibrated model score from the evidence-based risk score and show unavailable checks explicitly." />}
      </div>
      {batchResults.length > 0 && (
        <section className="surface batch-results">
          <div className="section-head">
            <div><p className="eyebrow">Batch results</p><h2>{batchResults.length} URLs analyzed</h2></div>
            <div className="button-row filters">
              {['all', 'no known threat detected', 'suspicious', 'high risk', 'malicious', 'unknown'].map((item) => (
                <Button key={item} type="button" secondary={batchFilter !== item} onClick={() => setBatchFilter(item)}>{item}</Button>
              ))}
            </div>
          </div>
          <div className="batch-result-list">
            {filteredBatchResults.map((item) => <URLResult key={item.url} result={item} />)}
            {!filteredBatchResults.length && <EmptyInline text={`No ${batchFilter} results in this batch.`} />}
          </div>
        </section>
      )}
    </>
  );
}

function ResultShell({ title, status, score, children }) {
  const value = Number.isFinite(Number(score)) ? Math.max(0, Math.min(Number(score), 100)) : 0;
  return (
    <section className="surface result-panel">
      <div className="result-top"><div><p className="eyebrow">Analysis result</p><h2>{title}</h2></div><Badge status={status} /></div>
      <div className="score-line"><strong>{Number.isFinite(Number(score)) ? `${score} / 100` : '--'}</strong><span>Risk score</span></div>
      <div className="progress"><span style={{ width: `${value}%` }} /></div>
      {children}
    </section>
  );
}

function EmailResult({ result }) {
  return (
    <ResultShell title={result.classification} status={result.classification} score={result.risk_score}>
      <ReportActions reportType="email" result={result} />
      <KeyValues values={[
        ['Spam score', `${result.spam_score}/100`],
        ['Scam score', `${result.scam_score}/100`],
        ['Email model score', result.model_score === null || result.model_score === undefined ? result.model_note : `${result.model_score}/100 (not calibrated)`],
        ['From', result.headers?.from || 'Not supplied'],
        ['Reply-To', result.headers?.reply_to || 'Not present'],
        ['Return-Path', result.headers?.return_path || 'Not present'],
        ['Authentication-Results', result.headers?.authentication_results ? `${result.headers.authentication_results} (header claim; not independently verified)` : 'Not present'],
        ['Threat types', (result.threat_types || []).join(', ') || 'None'],
      ]} />
      <ReasonList reasons={result.reasons || result.indicators} />
      <URLList urls={result.extracted_urls} />
      <EmbeddedURLResults results={result.embedded_url_results} />
      <Recommendation text={result.recommendation} />
    </ResultShell>
  );
}

function URLResult({ result }) {
  const vt = result.virustotal;
  const gsb = result.google_safe_browsing;
  const domain = result.domain_intelligence || {};
  const dns = domain.dns || {};
  const ssl = domain.ssl || {};
  const rdap = domain.rdap || {};
  const ipResults = domain.ip_geolocation?.results || [];
  const resolvedIps = domain.public_addresses || [...(dns.records?.A || []), ...(dns.records?.AAAA || [])];
  const networkOwners = ipResults.map((item) => [item.organization || item.isp, item.asn ? `AS${item.asn}` : null].filter(Boolean).join(' · ')).filter(Boolean);
  const approximateLocations = ipResults.map((item) => [item.city, item.region, item.country].filter(Boolean).join(', ')).filter(Boolean);
  const modelProbability = typeof result.model_probability === 'number'
    ? `${(result.model_probability * 100).toFixed(1)}/100 (uncalibrated model score)`
    : result.model_note;
  return (
    <ResultShell title={result.status || result.classification} status={result.status || result.classification} score={result.risk_score}>
      <ReportActions reportType="url" result={result} />
      <KeyValues values={[
        ['Submitted URL', result.submitted_url || result.url],
        ['Normalized URL', result.normalized_url || result.url],
        ['Category', result.category || 'undetermined'],
        ['Risk level', result.risk_level || 'unknown'],
        ['Confidence', result.confidence === null || result.confidence === undefined ? 'Not calculated' : result.confidence],
        ['Local model score', modelProbability],
        ['VirusTotal', result.reputation_status],
        ['Google Safe Browsing', gsb?.message || gsb?.status || 'Not checked'],
        ['Google Safe Browsing checked at', gsb?.checked_at || 'Not checked'],
        ['Google threat types', (gsb?.threat_types || []).join(', ') || 'No match reported'],
        ['VT status', vt?.status || 'Not checked'],
        ['VT malicious/suspicious', vt?.found ? `${vt.malicious || 0} / ${vt.suspicious || 0}` : vt?.status || 'Not available'],
        ['VT engines', vt?.total_engines ? `${vt.total_engines}` : 'Not available'],
        ['VT analysis date', vt?.analysis_date || 'Not available'],
        ['VT report checked at', vt?.checked_at || 'Not checked'],
        ['VT flagged engines', (vt?.vendor_results || []).map((item) => `${item.engine}: ${item.category}${item.result ? ` (${item.result})` : ''}`).join(' · ') || 'No flagged engine details returned'],
        ['Local model', result.model_used ? 'Available and used' : result.model_note],
        ['Threat feeds', (result.intelligence_sources || []).join(', ') || 'No feed match'],
        ['Feed refresh status', (result.threat_intelligence?.feed_status || []).map((feed) => {
          const state = !feed.enabled
            ? 'disabled'
            : feed.error
              ? `refresh error: ${feed.error}`
              : feed.updated_at
                ? `updated ${new Date(feed.updated_at).toLocaleString()}`
                : 'initial refresh not completed';
          return `${feed.name}: ${state}`;
        }).join(' · ') || 'Unavailable'],
        ['Analysis time', result.scan_timestamp ? new Date(result.scan_timestamp).toLocaleString() : 'Not available'],
      ]} />
      <section className="result-section">
        <h3>URL components and analysis status</h3>
        <KeyValues values={[
          ['Scheme', result.url_components?.scheme || 'Unavailable'],
          ['Hostname', result.url_components?.hostname || result.hostname || 'Unavailable'],
          ['Registered domain', result.url_components?.registered_domain || domain.registered_domain || 'Unavailable'],
          ['Subdomain', result.url_components?.subdomain || 'None identified'],
          ['IP host', result.url_components?.ip_address || 'No'],
          ['Port', result.url_components?.port || 'Default'],
          ['Path', result.url_components?.path || '/'],
          ['Query parameters', result.url_components?.query || 'None'],
          ['URL / hostname length', `${result.url_components?.url_length ?? '—'} / ${result.url_components?.hostname_length ?? '—'}`],
          ['Percent-encoded / punycode', `${result.url_components?.contains_percent_encoding ? 'Yes' : 'No'} / ${result.url_components?.uses_punycode ? 'Yes' : 'No'}`],
        ]} />
        <ul className="indicator-list">
          {Object.entries(result.checks || {}).map(([name, state]) => (
            <li key={name}><Badge status={state} /><span>{name.replaceAll('_', ' ')}: {state}</span></li>
          ))}
        </ul>
      </section>
      {result.redirect_chain?.length ? (
        <section className="result-section">
          <h3>Redirect chain</h3>
          <KeyValues values={[
            ['Final destination', result.final_url || 'Not resolved'],
            ...result.redirect_chain.map((hop, index) => [
              `Hop ${index + 1}`,
              `${hop.status_code || 'Unknown status'} — ${hop.url}${hop.location ? ` → ${hop.location}` : ''}`,
            ]),
          ]} />
        </section>
      ) : null}
      <section className="result-section network-report" aria-labelledby="network-report-title">
        <h3 id="network-report-title">Domain and network details</h3>
        <p className="explanation">Plain-language summary of where this domain points and who operates its public network address.</p>
        <KeyValues values={[
          ['Page hostname', result.hostname || domain.hostname || 'Unavailable'],
          ['Registered domain', domain.registered_domain || 'Unavailable'],
          ['Public IP address(es)', resolvedIps.join(', ') || 'No public IP address resolved'],
          ['Network owner / ASN', networkOwners.join(' | ') || 'Not reported'],
          ['Approximate IP region', approximateLocations.join(' | ') || 'Not available'],
          ['Domain registration', Number.isInteger(rdap.domain_age_days) ? `${rdap.domain_age_days} days old` : 'Age unavailable'],
          ['Connection certificate', ssl.checked ? (ssl.valid ? `Valid through ${ssl.not_after || 'reported date unavailable'}` : 'Invalid or expired') : 'Could not check'],
        ]} />
        <p className="network-location-note">IP location is approximate. It usually identifies the hosting provider, VPN, proxy, or CDN—not a person’s home or exact location. An ASN identifies the network operator announcing the IP range, not necessarily the website owner. Multiple IPs can be normal for load balancing or a CDN.</p>
        <details className="network-technical">
          <summary>Technical network details for analysts</summary>
          <KeyValues values={[
            ['Hostname', result.hostname || domain.hostname || 'Unavailable'],
            ['Registered domain', domain.registered_domain || 'Unavailable'],
            ['DNS A records (IPv4)', (dns.records?.A || []).join(', ') || 'None returned'],
            ['DNS AAAA records (IPv6)', (dns.records?.AAAA || []).join(', ') || 'None returned'],
            ['DNS CNAME records', (dns.records?.CNAME || []).join(', ') || 'None returned'],
            ['DNS NS records', (dns.records?.NS || []).join(', ') || 'None returned'],
            ['DNS MX records', (dns.records?.MX || []).join(', ') || 'None returned'],
            ['DNS TXT records', (dns.records?.TXT || []).join(' | ') || 'None returned'],
            ['DNS query status', dns.status || 'Unavailable'],
            ['TLS certificate issuer', ssl.issuer || 'Not reported'],
            ['TLS valid from', ssl.not_before || 'Not reported'],
            ['TLS valid until', ssl.not_after || 'Not reported'],
            ['Registration date', rdap.created_at || 'Not reported'],
            ['Registrar', rdap.registrar || 'Not reported'],
            ['RDAP status', rdap.checked ? 'Checked' : 'Unavailable'],
          ]} />
          {ipResults.map((item) => <p key={item.ip} className="explanation">{item.ip}: {item.isp || item.organization || 'Network owner unavailable'}{item.asn ? ` (AS${item.asn})` : ''}; approximate location {[item.city, item.region, item.country].filter(Boolean).join(', ') || 'not reported'}.</p>)}
        </details>
      </section>
      {vt?.gui_url && <ExternalLink href={vt.gui_url} label="Open VirusTotal report" />}
      {domain.ip_geolocation?.note && <p className="explanation">{domain.ip_geolocation.note}</p>}
      <FindingList findings={result.local_indicators || []} />
      {domain.checks?.length ? (
        <div className="result-section">
          <h3>Website intelligence checks</h3>
          <ul className="indicator-list">
            {domain.checks.map((check, index) => (
              <li key={`${check.message}-${index}`}><Badge status={check.severity} /><span>{check.message}</span></li>
            ))}
          </ul>
        </div>
      ) : null}
      <ReasonList reasons={result.reasons || result.indicators} />
      {(result.warnings?.length || domain.warnings?.length || Object.values(domain).some((item) => item?.status === 'unavailable')) ? (
        <div className="result-section">
          <h3>Analysis limitations</h3>
          <ul className="plain-list">
            {[...(result.warnings || []), ...(domain.warnings || []), ...(domain.checks || []).filter((check) => check.severity === 'unknown').map((check) => check.message)]
              .filter(Boolean)
              .map((warning) => <li key={warning}><AlertTriangle size={15} />{warning}</li>)}
          </ul>
        </div>
      ) : null}
      {result.limitations?.length ? (
        <div className="result-section">
          <h3>Limitations</h3>
          <ul className="plain-list">
            {result.limitations.map((limitation) => <li key={limitation}><AlertTriangle size={15} />{limitation}</li>)}
          </ul>
        </div>
      ) : null}
      <Recommendation text={result.recommendation} />
    </ResultShell>
  );
}

function ReportActions({ reportType, result }) {
  const { user, openAuth, emailDeliveryConfigured } = useAuth();
  const [emailPromptOpen, setEmailPromptOpen] = useState(false);
  const [recipient, setRecipient] = useState('');
  const [status, setStatus] = useState('');
  const [sending, setSending] = useState(false);
  const [emailSendError, setEmailSendError] = useState('');
  const label = reportType;

  async function downloadReport() {
    setStatus('');
    try {
      const report = await createScanReportPdf(result, reportType);
      report.save(`KESHIHBA-${reportType}-report.pdf`);
      setStatus('Report PDF downloaded.');
    } catch (error) {
      setStatus(`Could not create report: ${error.message}`);
    }
  }

  async function sendReport(event) {
    event.preventDefault();
    setStatus('');
    setEmailSendError('');
    setSending(true);
    try {
      const pdf = await createScanReportPdf(result, reportType);
      const response = await api('/api/auth/send-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recipient,
          report_type: reportType,
          pdf_base64: scanReportPdfBase64(pdf),
        }),
      });
      setStatus(response.message);
      setEmailPromptOpen(false);
    } catch (error) {
      setStatus(`Could not send the report: ${error.message}`);
      setEmailSendError(error.message);
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="report-actions">
      <div className="button-row">
        <Button type="button" secondary onClick={downloadReport}>
          <Download size={16} />Download PDF report
        </Button>
        <Button type="button" onClick={() => { setEmailSendError(''); setEmailPromptOpen(true); }}>
          <Mail size={16} />Send report by email
        </Button>
      </div>
      {status && <p className="report-status" role="status">{status}</p>}
      {emailPromptOpen && (
        <div className="dialog-overlay">
          <section className="email-dialog" role="dialog" aria-modal="true" aria-labelledby="email-dialog-title">
            <p className="eyebrow">{user ? 'Email report' : 'Account required'}</p>
            <h2 id="email-dialog-title">{user ? 'Confirm report delivery' : 'Sign in to email your report'}</h2>
            {!user ? (
              <>
                <p>Scanning and PDF downloads are available without an account. Sign in or create an account to send this report to an email address.</p>
                <div className="button-row">
                  <Button type="button" onClick={() => openAuth('login', () => setEmailPromptOpen(false))}>Log In</Button>
                  <Button type="button" secondary onClick={() => openAuth('signup', () => setEmailPromptOpen(false))}>Create Account</Button>
                  <Button type="button" secondary onClick={() => setEmailPromptOpen(false)}>Cancel</Button>
                </div>
              </>
            ) : emailDeliveryConfigured === null ? (
              <p>Checking the server's email configuration...</p>
            ) : !emailDeliveryConfigured ? (
              <>
                <p>Email delivery is not configured on this server. Your scan and PDF download remain available.</p>
                <Button type="button" secondary onClick={() => setEmailPromptOpen(false)}>Return to report</Button>
              </>
            ) : (
              <form className="form-stack" onSubmit={sendReport}>
                <p>Review the recipient before sending your {label} scan report. The PDF will be attached to an email sent by KESHIHBA.</p>
                <Field label="Recipient email address">
                  <input required type="email" maxLength={254} autoComplete="email" value={recipient} onChange={(event) => setRecipient(event.target.value)} placeholder="recipient@example.com" />
                </Field>
                {emailSendError && <ErrorBox message={emailSendError} />}
                <p className="report-note">Signed in as {user.email}. The report is sent only after you confirm below.</p>
                <div className="button-row">
                  <Button type="submit" disabled={sending}><Mail size={16} />{sending ? 'Sending...' : 'Confirm and send report'}</Button>
                  <Button type="button" secondary onClick={() => setEmailPromptOpen(false)} disabled={sending}>Cancel</Button>
                </div>
              </form>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

function FindingList({ findings }) {
  if (!findings.length) return null;
  return (
    <div className="result-section">
      <h3>Weighted indicators</h3>
      <ul className="indicator-list">
        {findings.map((finding, index) => {
          const severity = finding.weight >= 25 ? 'high' : finding.weight >= 12 ? 'medium' : 'low';
          return <li key={`${finding.category}-${index}`}><Badge status={severity} /><span>{finding.reason} (+{finding.weight})</span></li>;
        })}
      </ul>
    </div>
  );
}

function ToolResult({ name, data }) {
  if (name === 'expand') {
    return (
      <div className="tool-result">
        <strong>Redirect check: {data.status}</strong>
        <p>{data.error || (data.final_url ? `Final URL: ${data.final_url}` : 'No final destination was confirmed.')}</p>
        {data.redirects?.map((item, index) => <span key={`${item.url}-${index}`}>{item.status_code} — {item.url}{item.location ? ` → ${item.location}` : ''}</span>)}
      </div>
    );
  }
  const rows = name === 'dns'
    ? Object.entries(data.records || {}).map(([type, values]) => [`${type} records`, values.join(', ') || 'No records found'])
    : name === 'ssl'
      ? [['Status', data.checked ? (data.valid ? 'Valid' : 'Invalid') : 'Unavailable'], ['Issuer', data.issuer || 'Not reported'], ['Valid until', data.not_after || 'Not reported'], ['Error', data.error || 'None']]
      : name === 'domain-age'
        ? [['Registration date', data.created_at || 'Not available'], ['Domain age', Number.isInteger(data.domain_age_days) ? `${data.domain_age_days} days` : 'Not available'], ['Registrar', data.registrar || 'Not reported'], ['Status', data.checked ? 'Checked' : 'Unavailable']]
        : [['Status', data.status || 'Unknown'], ['Malicious detections', data.malicious ?? 'Not available'], ['Suspicious detections', data.suspicious ?? 'Not available'], ['Details', data.message || data.error || 'No details available']];
  return <div className="tool-result"><strong>{name.replace('-', ' ')} details</strong><KeyValues values={rows} /></div>;
}

function KeyValues({ values }) {
  return <div className="key-values">{values.map(([label, value]) => <div key={label}><span>{label}</span><b>{value || '--'}</b></div>)}</div>;
}

function ReasonList({ reasons = [] }) {
  return (
    <div className="result-section">
      <h3>Reasons for this output</h3>
      {reasons.length ? <ul className="indicator-list">{reasons.map((reason) => <li key={reason}><AlertTriangle size={15} />{reason}</li>)}</ul> : <p className="explanation">No strong risk reasons were found.</p>}
    </div>
  );
}

function URLList({ urls = [] }) {
  return (
    <div className="result-section">
      <h3>Extracted URLs</h3>
      {urls.length ? <div className="url-list">{urls.map((url) => (
        <a href="#/website-scanner" onClick={() => rememberUrlForScan(url)} key={url}>
          <span>{url}</span>
          <strong>Scan this URL</strong>
        </a>
      ))}</div> : <p className="explanation">No URLs were extracted.</p>}
    </div>
  );
}

function EmbeddedURLResults({ results = [] }) {
  return (
    <div className="result-section">
      <h3>Embedded URL analysis</h3>
      {results.length ? <div className="embedded-url-list">{results.map((item) => (
        <div className="embedded-url" key={item.url}>
          <div>
            <strong>{item.url}</strong>
            <span>{item.risk_score}/100 risk - {item.reputation_status}</span>
            {item.indicators?.length ? <ul className="plain-list">{item.indicators.map((finding, index) => <li key={`${finding}-${index}`}>{finding}</li>)}</ul> : null}
            {item.domain_intelligence?.dns?.records && <span>Resolved IPs: {[...(item.domain_intelligence.dns.records.A || []), ...(item.domain_intelligence.dns.records.AAAA || [])].join(', ') || 'Unavailable'}</span>}
            {item.domain_intelligence?.ip_geolocation?.results?.map((location) => <span key={location.ip}>Network location for {location.ip}: {[location.city, location.region, location.country, location.isp, location.organization, location.asn && `AS${location.asn}`].filter(Boolean).join(' · ')}</span>)}
          </div>
          <Badge status={item.classification} />
        </div>
      ))}</div> : <p className="explanation">No embedded URLs were analyzed.</p>}
    </div>
  );
}

function ExternalLink({ href, label }) {
  return <a className="external-link" href={href} target="_blank" rel="noreferrer">{label}</a>;
}

function Recommendation({ text }) {
  return <div className="recommendation"><ShieldAlert size={18} /><div><strong>What to do next</strong><p>{text}</p></div></div>;
}

function EmptyResult({ icon: Icon, title, text }) {
  return <section className="surface empty-result"><Icon size={28} /><h2>{title}</h2><p>{text}</p></section>;
}

function ErrorBox({ message }) {
  return <div className="error" role="alert"><XCircle size={17} />{message}</div>;
}

function HistoryPage() {
  const [scans, setScans] = useState([]);
  const [filter, setFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [search, setSearch] = useState('');
  const { user, openAuth } = useAuth();

  useEffect(() => {
    if (!user) {
      setScans([]);
      return;
    }
    api('/api/scans?limit=200').then(setScans).catch(() => setScans([]));
  }, [user?.id]);

  const visible = useMemo(() => scans.filter((scan) => {
    const matchesType = filter === 'all' || scan.scan_type === filter;
      const matchesRisk = riskFilter === 'all' || scan.classification.toLowerCase() === riskFilter;
    const haystack = `${scan.target} ${(scan.indicators || []).join(' ')}`.toLowerCase();
    return matchesType && matchesRisk && haystack.includes(search.trim().toLowerCase());
  }), [scans, filter, riskFilter, search]);

  return (
    <>
      <Intro eyebrow="History" title="Previous scans">
        {user ? 'Review scan metadata saved to your account. Guest scans are not added to personal history.' : 'Scan history is private to each account. You can scan emails and URLs without signing in.'}
      </Intro>
      {!user ? (
        <section className="surface history-guest">
          <History size={28} />
          <h2>Your scans stay yours</h2>
          <p>Sign in to view scan history saved to your account. Guest scanning and PDF downloads continue to work without an account.</p>
          <Button type="button" onClick={() => openAuth('login')}>Log in to view history</Button>
        </section>
      ) : (
      <section className="surface">
        <div className="button-row filters">
          {['all', 'email', 'website'].map((item) => <Button key={item} secondary={filter !== item} onClick={() => setFilter(item)}>{item}</Button>)}
        </div>
        <div className="history-filters">
          <input aria-label="Search scan history" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search URLs and findings" />
          <select aria-label="Filter by verdict" value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)}>
              {['all', 'no known threat detected', 'safe', 'suspicious', 'high risk', 'malicious', 'unknown'].map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </div>
        {visible.length ? <div className="scan-list">{visible.map((scan) => (
          <details className="history-item" key={scan.id}>
            <summary className="scan-row"><div><strong>{scan.target}</strong><span>{scan.scan_type} - {new Date(scan.created_at).toLocaleString()}</span></div><Badge status={scan.classification} /><b>{scan.risk_score}/100</b></summary>
            <div className="history-details">
              <span>Threat types: {(scan.threat_types || []).join(', ') || 'None recorded'}</span>
              {(scan.indicators || []).length
                ? <ul className="indicator-list">{scan.indicators.map((indicator) => <li key={indicator}><AlertTriangle size={15} />{indicator}</li>)}</ul>
                : <p className="explanation">No indicators were recorded for this scan.</p>}
            </div>
          </details>
        ))}</div> : <EmptyInline text={scans.length ? 'No history matches those filters.' : 'No scans yet. Run an email or URL scan first.'} />}
      </section>
      )}
    </>
  );
}

function DatasetPage() {
  const [models, setModels] = useState(null);
  useEffect(() => {
    api('/api/models').then(setModels).catch(() => setModels(null));
  }, []);
  return (
    <>
      <Intro eyebrow="Datasets" title="Currently used detection data">
        These are the datasets and metrics currently connected to the trained local classifiers.
      </Intro>
      <section className="model-grid">
        <ModelSummary title="Email phishing dataset" data={models?.email_model} />
        <ModelSummary title="Malicious URL dataset" data={models?.url_model} />
      </section>
      <section className="surface">
        <div className="section-head">
          <div><p className="eyebrow">Rule services</p><h2>Spam, scam, and reputation checks</h2></div>
        </div>
        <div className="service-list">
          {(models?.rule_detectors || []).map((service) => (
            <div key={service.name}>
              <strong>{service.name}</strong>
              <span>{service.method}</span>
              <p>{service.dataset}</p>
              <small>Detects: {(service.detects || []).join(', ')}</small>
            </div>
          ))}
        </div>
      </section>
      <section className="surface">
        <h2>How detection works</h2>
        <ul className="plain-list">
          {(models?.notes || []).map((note) => <li key={note}><CheckCircle2 size={15} />{note}</li>)}
        </ul>
      </section>
    </>
  );
}

function SettingsPage() {
  const [health, setHealth] = useState(null);
  const [intel, setIntel] = useState(null);
  const [models, setModels] = useState(null);
  useEffect(() => {
    api('/health').then(setHealth).catch(() => setHealth(null));
    api('/api/intelligence/status').then(setIntel).catch(() => setIntel(null));
    api('/api/models').then(setModels).catch(() => setModels(null));
  }, []);
  const feedRows = (intel?.feeds || []).map((feed) => [
    `${feed.name} feed`,
    !feed.enabled ? 'Disabled — API key not configured' : feed.entries > 0 ? `${feed.entries} indicators loaded` : feed.error ? `Unavailable — ${feed.error}` : 'Waiting for initial refresh',
  ]);
  return (
    <>
      <Intro eyebrow="Investigation setup" title="Detection services">
        Check which email and URL evidence sources are available. A connected service can still return no match, and no match does not prove a message or link is safe.
      </Intro>
      <section className="surface">
        <KeyValues values={[
          ['Analysis API', health?.status === 'ok' ? 'Online' : 'Unavailable'],
          ['Email phishing model', models?.email_model?.available ? 'Available' : 'Unavailable — rule checks still run'],
          ['URL phishing model', models?.url_model?.available ? 'Available' : 'Unavailable — URL rules still run'],
          ['Spam and scam checks', 'Explainable content and sender rules (no separate trained models)'],
          ['VirusTotal URL reputation', virusTotalConnectionLabel(intel?.virustotal)],
          ['Google Safe Browsing', intel?.google_safe_browsing?.enabled ? 'Configured (non-commercial use)' : 'Optional — API key not configured'],
          ['VirusTotal IP reputation', intel?.virustotal?.enabled ? 'Configured' : 'Optional — API key not configured'],
          ...feedRows,
          ['URL evidence', 'DNS, TLS certificate, domain registration, and approximate public-IP network location'],
          ['Backend address', API_BASE_URL],
        ]} />
        {intel?.feeds?.some((feed) => feed.updated_at) && <p className="explanation">Threat feed refresh times: {intel.feeds.filter((feed) => feed.updated_at).map((feed) => `${feed.name}: ${new Date(feed.updated_at).toLocaleString()}`).join(' · ')}</p>}
      </section>
    </>
  );
}

function EmptyInline({ text }) {
  return <div className="empty-inline"><FileText size={20} /><span>{text}</span></div>;
}

function virusTotalConnectionLabel(data) {
  if (!data?.enabled) return 'Optional — API key not configured';
  const connection = data.connection || {};
  const labels = {
    connected: 'Connected',
    authentication_error: 'API key rejected',
    rate_limited: 'Rate limited; try again later',
    unreachable: 'Provider unreachable',
    error: 'Provider check failed',
  };
  const label = labels[connection.status] || 'Configured; not checked';
  const keys = data.configured_key_count || 1;
  const detail = connection.message || connection.error;
  return `${label} (${keys} key${keys === 1 ? '' : 's'})${detail ? ` · ${detail}` : ''}`;
}

const root = createRoot(document.getElementById('root'));
root.render(<App />);
