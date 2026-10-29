import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  AlertTriangle, BarChart3, CheckCircle2, ChevronRight, FileText, Globe2,
  History, LayoutDashboard, Mail, Menu, Search, Settings, Shield,
  ShieldAlert, ShieldCheck, Upload,
} from 'lucide-react';
import './classic.css';

const navGroups = [
  { label: 'Overview', items: [['dashboard', 'Dashboard', LayoutDashboard]] },
  { label: 'Analysis', items: [['email-scanner', 'Email Scanner', Mail], ['website-scanner', 'Website Scanner', Globe2]] },
  { label: 'Reporting', items: [['scan-history', 'Scan History', History], ['threat-reports', 'Threat Reports', FileText], ['statistics', 'Statistics', BarChart3]] },
  { label: 'System', items: [['settings', 'Settings', Settings], ['about', 'About', Shield]] },
];

const historyRows = [
  { date: '28 Aug 2026', type: 'Website', target: 'example.com', risk: 12, status: 'Safe' },
  { date: '27 Aug 2026', type: 'Email', target: 'invoice-review@example.net', risk: 46, status: 'Suspicious' },
];

function getPage() { return window.location.hash.replace('#/', '').replace('#', '') || 'dashboard'; }

function App() {
  const [page, setPage] = useState(getPage());
  const [menuOpen, setMenuOpen] = useState(false);
  useEffect(() => { const onHashChange = () => { setPage(getPage()); setMenuOpen(false); }; window.addEventListener('hashchange', onHashChange); return () => window.removeEventListener('hashchange', onHashChange); }, []);
  const pageTitles = { dashboard: 'Security Overview', 'email-scanner': 'Email Scanner', 'website-scanner': 'Website Scanner', 'scan-history': 'Scan History', 'threat-reports': 'Threat Analysis Report', statistics: 'Statistics', settings: 'Settings', about: 'About KESHIHBA' };
  return <div className="app-shell"><aside className={`sidebar ${menuOpen ? 'sidebar-open' : ''}`}><div className="brand"><span className="brand-mark"><Shield size={21} /></span><span><strong>KESHIHBA</strong><small>Phishing Threat Intelligence</small></span></div><nav className="primary-nav" aria-label="Primary navigation">{navGroups.map((group) => <div className="nav-group" key={group.label}><p>{group.label}</p>{group.items.map(([href, label, Icon]) => <a className={page === href ? 'active' : ''} href={`#/${href}`} key={href}><Icon size={17} />{label}</a>)}</div>)}</nav><div className="sidebar-footer"><p>Secure. Analyze. Protect.</p><small>© 2026 KESHIHBA</small></div></aside>{menuOpen && <button className="sidebar-overlay" aria-label="Close navigation" onClick={() => setMenuOpen(false)} />}<div className="content-shell"><header className="top-header"><button className="menu-button" onClick={() => setMenuOpen(true)} aria-label="Open navigation"><Menu size={21} /></button><div className="breadcrumb"><Shield size={17} /><span>Security Center</span><ChevronRight size={15} /><strong>{pageTitles[page] || 'Security Overview'}</strong></div><div className="system-status"><span className="status-dot" />System Status: Operational</div></header><main className="page-content">{page === 'dashboard' && <Dashboard />}{page === 'email-scanner' && <EmailScanner />}{page === 'website-scanner' && <WebsiteScanner />}{page === 'scan-history' && <ScanHistory />}{page === 'threat-reports' && <ThreatReport />}{page === 'statistics' && <Statistics />}{page === 'settings' && <SettingsPage />}{page === 'about' && <About />}</main></div></div>;
}

function PageIntro({ eyebrow, title, children }) { return <div className="page-intro"><p className="eyebrow">{eyebrow}</p><h1>{title}</h1>{children && <p>{children}</p>}</div>; }
function Button({ children, secondary = false, ...props }) { return <button className={`button ${secondary ? 'button-secondary' : ''}`} {...props}>{children}</button>; }
function StatusBadge({ status }) { return <span className={`status-badge ${status.toLowerCase()}`}>{status}</span>; }
function Summary({ label, value, tone = '' }) { return <div className="summary-item"><strong className={tone}>{value}</strong><span>{label}</span></div>; }

function Dashboard() { return <><PageIntro eyebrow="Overview" title="Security Overview">Monitor phishing detection activity and recent security analysis.</PageIntro><section className="summary-row"><Summary label="Total Scans" value="0" /><Summary label="Safe" value="0" tone="safe" /><Summary label="Suspicious" value="0" tone="warning" /><Summary label="Malicious" value="0" tone="danger" /></section><section className="content-section"><div className="section-heading"><div><h2>Recent Scan Activity</h2><p>No scans have been recorded yet.</p></div><a className="text-link" href="#/scan-history">View history <ChevronRight size={15} /></a></div><div className="empty-table"><History size={22} /><strong>Your scan history is empty</strong><span>Completed email and website analyses will appear here.</span><a href="#/email-scanner">Start an email scan</a></div></section></>; }

function Field({ label, children }) { return <label className="field"><span>{label}</span>{children}</label>; }
function UploadBox({ onChange }) {
  return <div className="upload-box"><label className="upload-dropzone"><input type="file" accept=".eml" onChange={onChange} /><span className="upload-icon"><Upload size={32} /></span><strong>Drop an .EML file here</strong><p>or choose an email file from your computer</p><span className="upload-button">Choose File</span><small>EML files only</small></label></div>;
}
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

async function requestEmailAnalysis(email) {
  const response = await fetch(`${API_BASE_URL}/api/analyze/email`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(email) });
  if (!response.ok) throw new Error(`Analysis request failed (${response.status})`);
  return response.json();
}

function extractUrls(text) { return [...new Set(text.match(/https?:\/\/[^\s<>"']+/gi) || [])]; }
function valueOrUnknown(value) { return value === undefined || value === null || value === '' ? 'UNKNOWN' : value; }

function EmailScanner() {
  const [email, setEmail] = useState({ sender: '', subject: '', body: '' });
  const [mode, setMode] = useState('upload');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState('');
  const update = (key) => (event) => setEmail({ ...email, [key]: event.target.value });
  const submit = async (event) => { event.preventDefault(); setError(''); setResult(null); setLoading(true); try { setResult(await requestEmailAnalysis(email)); } catch (requestError) { setError(`${requestError.message}. Confirm the backend is running and VITE_API_BASE_URL points to it.`); } finally { setLoading(false); } };
  const readEml = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    const body = await file.text();
    setEmail({ sender: '', subject: '', body });
    setMode('paste');
  };
  return <><PageIntro eyebrow="Analysis" title="Email Scanner">Analyze suspicious email content, sender information, and embedded URLs.</PageIntro><div className="email-layout"><section className="form-panel"><div className="tabs"><button type="button" className={mode === 'paste' ? 'selected' : ''} onClick={() => setMode('paste')}>Paste Email</button><button type="button" className={mode === 'upload' ? 'selected' : ''} onClick={() => setMode('upload')}>Upload .EML</button></div>{mode === 'paste' ? <form className="form-stack" onSubmit={submit}><Field label="Sender Email"><input type="email" value={email.sender} onChange={update('sender')} placeholder="security@example.com" required /></Field><Field label="Subject"><input value={email.subject} onChange={update('subject')} placeholder="Email subject" /></Field><Field label="Email Content"><textarea value={email.body} onChange={update('body')} placeholder="Paste the complete email content here" required /></Field><div className="form-actions"><Button type="submit" disabled={loading}><ShieldCheck size={16} />{loading ? 'Analyzing...' : 'Analyze Email'}</Button>{fileName && <span className="file-indicator">Loaded: {fileName}</span>}</div>{error && <div className="error-message" role="alert"><AlertTriangle size={17} />{error}</div>}</form> : <div className="upload-panel"><UploadBox onChange={readEml} /></div>}</section>{result ? <EmailResult result={result} source={email} /> : <section className="result-placeholder"><Mail size={25} /><h2>Analysis Result</h2><p>Submit an email to review its classification, risk breakdown, headers, indicators, and threat intelligence findings.</p></section>}</div></>;
}
function ResultValue({ value }) { return <span className={valueOrUnknown(value) === 'UNKNOWN' ? 'unknown' : ''}>{valueOrUnknown(value)}</span>; }
function EmailResult({ result, source }) {
  const score = Number.isFinite(Number(result.risk_score)) ? Number(result.risk_score) : null;
  const urls = result.extracted_urls || result.urls || extractUrls(source.body);
  const indicators = result.indicators || result.detection_indicators || [];
  const breakdown = result.risk_breakdown || {};
  const headers = result.headers || {};
  return <section className="result-panel"><div className="result-title"><div><p className="eyebrow">Email Analysis Result</p><h2>{valueOrUnknown(result.classification || result.status)}</h2></div><StatusBadge status={result.classification || 'Unknown'} /></div><div className="risk-line"><strong>{score === null ? 'UNKNOWN' : `${score} / 100`}</strong><span>Overall Risk Score</span></div>{score !== null && <div className="progress"><span style={{ width: `${Math.max(0, Math.min(score, 100))}%` }} /></div>}<div className="result-section"><h3>Risk Breakdown</h3><div className="breakdown-list">{[['URL indicators', breakdown.url_indicators], ['Sender indicators', breakdown.sender_indicators], ['Content indicators', breakdown.content_indicators], ['Threat intelligence', breakdown.threat_intelligence], ['Impersonation indicators', breakdown.impersonation_indicators]].map(([label, value]) => <div key={label}><span>{label}</span><ResultValue value={value} /></div>)}</div></div><div className="result-section"><h3>Detection Indicators</h3>{indicators.length ? <ul className="indicator-list">{indicators.map((item) => <li key={item}><AlertTriangle size={16} />{item}</li>)}</ul> : <ResultValue value={undefined} />}</div><div className="result-section"><h3>Extracted URLs</h3>{urls.length ? <div className="url-table">{urls.map((url) => <div className="url-item" key={url}><strong>{typeof url === 'string' ? url : url.url}</strong><ResultValue value={typeof url === 'string' ? undefined : url.status} /><ResultValue value={typeof url === 'string' ? undefined : url.risk_score} /><Button secondary type="button">Analyze URL</Button></div>)}</div> : <ResultValue value={undefined} />}</div><div className="result-section"><h3>Sender Analysis</h3><div className="header-grid"><div><span>From</span><ResultValue value={headers.from || result.sender || source.sender} /></div><div><span>Reply-To</span><ResultValue value={headers.reply_to} /></div><div><span>Return-Path</span><ResultValue value={headers.return_path} /></div><div><span>Received</span><ResultValue value={headers.received} /></div><div><span>SPF</span><ResultValue value={headers.spf} /></div><div><span>DKIM</span><ResultValue value={headers.dkim} /></div><div><span>DMARC</span><ResultValue value={headers.dmarc} /></div></div></div><div className="result-section"><h3>Why was this email flagged?</h3><p className="explanation">{valueOrUnknown(result.explanation || result.reasons)}</p></div><div className="recommendation"><ShieldAlert size={18} /><div><strong>Security Recommendation</strong><p>{valueOrUnknown(result.recommendation)}</p></div></div></section>;
}

function WebsiteScanner() { const [scanned, setScanned] = useState(false); return <><PageIntro eyebrow="Analysis" title="Website Security Scanner">Analyze a website URL for phishing and malicious indicators.</PageIntro><section className="single-task narrow-task"><form className="form-stack" onSubmit={(event) => { event.preventDefault(); setScanned(true); }}><Field label="Website URL"><input placeholder="https://example.com" /></Field><Button type="submit"><Search size={16} />Scan Website</Button></form>{scanned && <div className="website-result"><div className="result-title"><div><p className="eyebrow">Website Analysis</p><h2>example.com</h2></div><StatusBadge status="Safe" /></div><div className="risk-line"><strong>SAFE</strong><span>Risk Score: 12 / 100</span></div><div className="progress safe-progress"><span style={{ width: '12%' }} /></div><table className="checks-table"><tbody>{[['HTTPS', 'PASS'], ['URL Structure', 'PASS'], ['Domain Analysis', 'PASS'], ['VirusTotal', 'CLEAN']].map(([label, value]) => <tr key={label}><td>{label}</td><td><CheckCircle2 size={15} />{value}</td></tr>)}</tbody></table></div>}</section></>; }
function ScanHistory() { const [filter, setFilter] = useState('All'); const rows = filter === 'All' ? historyRows : historyRows.filter((row) => row.status === filter || row.type === filter); return <><PageIntro eyebrow="Reporting" title="Scan History">Review completed phishing detection analyses.</PageIntro><section className="table-panel"><div className="table-toolbar"><div className="search-field"><Search size={16} /><input placeholder="Search scans..." /></div><div className="filter-group">{['All', 'Email', 'Website', 'Safe', 'Suspicious', 'Malicious'].map((item) => <button className={filter === item ? 'selected' : ''} onClick={() => setFilter(item)} key={item}>{item}</button>)}</div></div><div className="table-wrap"><table><thead><tr><th>Date</th><th>Type</th><th>Target</th><th>Risk Score</th><th>Status</th><th>Action</th></tr></thead><tbody>{rows.map((row) => <tr key={row.target}><td>{row.date}</td><td>{row.type}</td><td>{row.target}</td><td>{row.risk} / 100</td><td><StatusBadge status={row.status} /></td><td><a className="text-link" href="#/threat-reports">View</a></td></tr>)}</tbody></table></div></section></>; }
function ThreatReport() { return <><PageIntro eyebrow="Reporting" title="Threat Analysis Report">Review the evidence and recommendation for a completed security analysis.</PageIntro><section className="report-panel"><div className="report-header"><div><span className="label">Target</span><h2>fake-login-example.com</h2></div><StatusBadge status="Malicious" /></div><div className="report-score"><span>Risk Score</span><strong>87 / 100</strong></div><h3>Detection Evidence</h3><div className="evidence-list">{[['VirusTotal', '8 / 92 detections'], ['URL Analysis', 'Suspicious structure'], ['Domain Analysis', 'Possible impersonation'], ['Email Analysis', 'Credential request']].map(([a, b]) => <div key={a}><strong>{a}</strong><span>{b}</span></div>)}</div><div className="recommendation danger-recommendation"><ShieldAlert size={18} /><div><strong>Recommendation</strong><p>Do not interact with this website or provide credentials.</p></div></div><div className="form-actions"><Button>Export Report</Button><Button secondary>Back to Scan</Button></div></section></>; }
function Statistics() { return <><PageIntro eyebrow="Reporting" title="Statistics">Research metrics from the connected scan database.</PageIntro><div className="notice"><AlertTriangle size={17} /><span>Statistics will populate when backend scan records and evaluation results are available.</span></div><section className="summary-row"><Summary label="Total Samples" value="--" /><Summary label="Safe Samples" value="--" /><Summary label="Phishing Samples" value="--" /><Summary label="Average Risk Score" value="--" /></section><section className="research-panel"><h2>Evaluation Metrics</h2><div className="metric-list">{['Accuracy', 'Precision', 'Recall', 'F1-Score', 'Average Detection Time'].map((item) => <div key={item}><span>{item}</span><strong>--</strong></div>)}</div></section></>; }
function SettingsPage() { return <><PageIntro eyebrow="System" title="Settings">Review service connections and application preferences.</PageIntro><section className="settings-panel">{[['VirusTotal', 'Not Connected'], ['API Status', 'Operational'], ['Backend', 'Not Connected'], ['Database', 'Not Connected'], ['Theme', 'Light']].map(([label, value]) => <div key={label}><span>{label}</span><strong className={value === 'Operational' ? 'setting-good' : ''}>{value}</strong></div>)}</section></>; }
function About() { return <><PageIntro eyebrow="System" title="About KESHIHBA">A focused phishing detection research application.</PageIntro><section className="about-panel"><Shield size={28} /><h2>Secure. Analyze. Protect.</h2><p>KESHIHBA analyzes suspicious emails, websites, using explainable security indicators and threat intelligence.</p><p className="muted">Research project interface · 2026</p></section></>; }

createRoot(document.getElementById('root')).render(<App />);
