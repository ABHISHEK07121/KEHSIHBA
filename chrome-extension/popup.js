const API_BASE_URL = 'http://127.0.0.1:8000';
const state = document.getElementById('state');
const scanButton = document.getElementById('scan');
const targetInput = document.getElementById('target-url');

let activeUrl = '';
let activeTabId = null;

function clearState() {
  state.replaceChildren();
}

function addText(tag, text, className = '') {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  state.appendChild(element);
  return element;
}

function renderLoading(text) {
  clearState();
  state.className = 'state state--loading';
  addText('p', text);
}

function renderError(message) {
  clearState();
  state.className = 'state state--warning';
  addText('span', 'Unavailable', 'badge suspicious');
  addText('p', message);
}

function renderResult(rawResult, signals = null) {
  const result = mergePageSignals(rawResult, signals);
  const classification = String(result.classification || 'Unknown');
  const warning = ['malicious', 'high risk', 'suspicious'].includes(classification.toLowerCase()) || Number(result.risk_score) >= 35;
  clearState();
  state.className = `state ${warning ? 'state--warning' : 'state--safe'}`;
  if (warning) {
    addText('strong', 'KESHIHBA WARNING — review before interacting', 'warning-title');
  }
  addText('span', classification, `badge ${classification.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`);
  const scoreRow = document.createElement('div');
  scoreRow.className = 'score-row';
  const score = Number.isFinite(Number(result.risk_score)) ? Math.max(0, Math.min(100, Number(result.risk_score))) : null;
  const scoreTitle = document.createElement('h1');
  scoreTitle.textContent = score === null ? 'N/A' : `${score} / 100`;
  const scoreLabel = document.createElement('small');
  scoreLabel.textContent = 'URL risk score';
  scoreRow.append(scoreTitle, scoreLabel);
  state.appendChild(scoreRow);
  addText('p', 'Risk score is based on available evidence and is not a probability. A low score does not guarantee safety.');
  const track = document.createElement('div');
  track.className = 'score-track';
  const fill = document.createElement('span');
  fill.style.width = `${score ?? 0}%`;
  track.appendChild(fill);
  state.appendChild(track);
  addText('p', result.url || activeUrl, 'scanned-url');
  const vt = result.virustotal || {};
  addText('p', `VirusTotal: ${vt.message || vt.status || result.reputation_status || 'Not checked'}`);
  if (Number(vt.key_attempts) > 1) addText('p', `Key failover: tried ${vt.key_attempts} configured keys; ${vt.fallback_used ? 'a backup key was used' : 'no backup key was needed'}.`);
  const safeBrowsing = result.google_safe_browsing || result.threat_intelligence?.google_safe_browsing;
  if (safeBrowsing?.enabled) addText('p', `Google Safe Browsing fallback: ${safeBrowsing.message || safeBrowsing.status || 'checked'}`);
  const pageSignals = result.extension_page_signals;
  if (pageSignals) {
    addText('strong', 'On-device page checks', 'findings-title');
    addText('p', `Credential form detected: ${pageSignals.has_credential_form ? 'Yes' : 'No'}.`);
    addText('p', `Login wording detected: ${pageSignals.has_login_cue ? 'Yes' : 'No'}.`);
    addText('p', `Form sends credentials to another host: ${pageSignals.has_external_credential_action ? 'Yes' : 'No'}.`);
    if (pageSignals.brand_mismatches?.length) addText('p', `Brand names in page identity fields that do not match this host: ${pageSignals.brand_mismatches.join(', ')}.`);
  }
  const domain = result.domain_intelligence || {};
  const dns = domain.dns || {};
  const addresses = domain.public_addresses || [...(dns.records?.A || []), ...(dns.records?.AAAA || [])];
  addText('strong', 'Domain and network details', 'findings-title');
  addText('p', `Page hostname: ${result.hostname || domain.hostname || 'Unavailable'}`);
  addText('p', `Registered domain: ${domain.registered_domain || 'Unavailable'}`);
  addText('p', `Public IP address${addresses.length === 1 ? '' : 'es'}: ${addresses.join(', ') || 'No public address resolved'}`);
  const locations = domain.ip_geolocation?.results || [];
  locations.forEach((item) => {
    const details = [item.city, item.region, item.country, item.isp, item.organization, item.asn && `AS${item.asn}`].filter(Boolean);
    addText('p', `Network: ${item.ip}${details.length ? ` · ${details.join(' · ')}` : ''}`);
  });
  if (domain.ip_geolocation?.note) addText('p', domain.ip_geolocation.note);
  const reasons = result.reasons || result.indicators || [];
  if (reasons.length) {
    addText('strong', 'Why it was flagged', 'findings-title');
    reasons.slice(0, 6).forEach((item) => {
      const adjusted = item.replace(/Local URL model phishing probability is (\d+)%\.?/i, 'Local URL model score is $1/100 (uncalibrated; not a probability).');
      addText('p', adjusted);
    });
  } else {
    addText('p', 'No strong indicators were returned.');
  }
}

async function getActiveTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTabId = tab?.id ?? null;
  return tab?.url || '';
}

async function getPageSignals() {
  if (activeTabId === null) return null;
  try {
    let signals;
    try {
      signals = await chrome.tabs.sendMessage(activeTabId, { type: 'KESHIHBA_GET_PAGE_SIGNALS' });
    } catch {
      await chrome.scripting.executeScript({ target: { tabId: activeTabId }, files: ['page-inspector.js'] });
      signals = await chrome.tabs.sendMessage(activeTabId, { type: 'KESHIHBA_GET_PAGE_SIGNALS' });
    }
    return signals?.url === targetInput.value.trim() ? signals : null;
  } catch {
    return null;
  }
}

async function scanCurrentPage() {
  const urlToScan = targetInput.value.trim();
  if (!/^https?:\/\//i.test(urlToScan)) {
    renderError('Enter a complete HTTP or HTTPS URL to scan.');
    return;
  }
  scanButton.disabled = true;
  renderLoading('Checking URL risk and reputation...');
  try {
    const response = await fetch(`${API_BASE_URL}/api/analyze/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: urlToScan }),
    });
    if (!response.ok) throw new Error(`Backend returned ${response.status}`);
    const result = await response.json();
    renderResult(result, await getPageSignals());
  } catch (error) {
    renderError(`Could not reach the KESHIHBA backend. Start it at ${API_BASE_URL}.`);
  } finally {
    scanButton.disabled = false;
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  activeUrl = await getActiveTabUrl();
  targetInput.value = /^https?:\/\//i.test(activeUrl) ? activeUrl : '';
  if (targetInput.value) {
    await scanCurrentPage();
  } else {
    renderError('No web page is active. Paste an HTTP or HTTPS link to scan.');
  }
});

scanButton.addEventListener('click', scanCurrentPage);
