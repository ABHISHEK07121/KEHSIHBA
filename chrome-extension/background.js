importScripts('risk-utils.js');

const API_BASE_URL = 'http://127.0.0.1:8000';
const scannedTabUrls = new Map();
const inFlightScans = new Set();
const pageSignalsByTab = new Map();
const scanResultsByTab = new Map();

function isWebUrl(value) {
  return typeof value === 'string' && /^https?:\/\//i.test(value);
}

function shouldWarn(result) {
  const classification = String(result.classification || '').toLowerCase();
  const threatTypes = (result.threat_types || []).map((item) => String(item).toLowerCase());
  const indicators = (result.indicators || []).join(' ').toLowerCase();
  const vt = result.virustotal || {};
  return classification === 'malicious'
    || classification === 'high risk'
    || classification === 'suspicious'
    || Number(result.risk_score) >= 35
    || Number(vt.malicious) > 0
    || Number(vt.suspicious) >= 2
    || (result.intelligence_sources || []).length > 0
    || threatTypes.some((item) => ['brand_impersonation', 'suspicious_reputation', 'financial_scam', 'credential_theft', 'malware_distribution', 'phishing'].includes(item))
    || indicators.includes('impersonat');
}

function pageHost(url) {
  try { return new URL(url).hostname; } catch { return 'This page'; }
}

async function setTabStatus(tabId, result, url) {
  if (shouldWarn(result)) {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: '#b42318' });
    await chrome.action.setBadgeText({ tabId, text: '!' });
    await chrome.action.setTitle({ tabId, title: `KESHIHBA warning: ${result.classification} (${result.risk_score}/100)` });
    const reasons = (result.indicators || []).slice(0, 2).join(' ');
    try {
      await chrome.notifications.create(`kesihba-${tabId}-${Date.now()}`, {
        type: 'basic',
        iconUrl: chrome.runtime.getURL('warning.png'),
        title: `KESHIHBA: ${result.classification || 'High risk page'}`,
        message: `${pageHost(url)} — risk ${result.risk_score}/100.${reasons ? ` ${reasons}` : ''}`.slice(0, 240),
        contextMessage: 'Avoid entering passwords or payment details until verified.',
        priority: 2,
      });
    } catch {
      // Keep the red toolbar badge if system notifications are unavailable.
    }
  } else {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: '#24834a' });
    await chrome.action.setBadgeText({ tabId, text: '✓' });
    await chrome.action.setTitle({ tabId, title: 'No elevated URL risk detected by KESHIHBA; this does not prove the page is safe' });
  }
}

async function scanTab(tabId) {
  let tab;
  try { tab = await chrome.tabs.get(tabId); } catch { return; }
  if (!tab.active || tab.status !== 'complete' || !isWebUrl(tab.url)) return;
  const url = tab.url;
  const scanKey = `${tabId}:${url}`;
  if (scannedTabUrls.get(tabId) === url || inFlightScans.has(scanKey)) return;

  scannedTabUrls.set(tabId, url);
  inFlightScans.add(scanKey);
  await chrome.action.setBadgeBackgroundColor({ tabId, color: '#b7791f' });
  await chrome.action.setBadgeText({ tabId, text: '…' });
  await chrome.action.setTitle({ tabId, title: 'KESHIHBA is checking this page URL' });
  try {
    const response = await fetch(`${API_BASE_URL}/api/analyze/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    if (!response.ok) throw new Error(`Backend returned ${response.status}`);
    const result = await response.json();
    scanResultsByTab.set(tabId, { url, result });
    const currentTab = await chrome.tabs.get(tabId).catch(() => null);
    const signals = pageSignalsByTab.get(tabId);
    const combined = signals?.url === url ? mergePageSignals(result, signals) : result;
    if (currentTab?.url === url) await setTabStatus(tabId, combined, url);
  } catch {
    if (scannedTabUrls.get(tabId) === url) scannedTabUrls.delete(tabId);
    await chrome.action.setBadgeBackgroundColor({ tabId, color: '#b7791f' });
    await chrome.action.setBadgeText({ tabId, text: '?' });
    await chrome.action.setTitle({ tabId, title: 'KESHIHBA could not reach its local backend' });
  } finally {
    inFlightScans.delete(scanKey);
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'complete' || changeInfo.url) void scanTab(tabId);
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  void scanTab(tabId);
});

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message?.type !== 'KESHIHBA_PAGE_SIGNALS' || !Number.isInteger(sender.tab?.id)) return;
  const tabId = sender.tab.id;
  const signals = message.signals;
  if (!signals || signals.url !== sender.tab.url) return;
  pageSignalsByTab.set(tabId, signals);
  const previous = scanResultsByTab.get(tabId);
  if (previous?.url === signals.url && sender.tab.active) {
    void setTabStatus(tabId, mergePageSignals(previous.result, signals), signals.url);
  } else if (sender.tab.active) {
    void scanTab(tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  scannedTabUrls.delete(tabId);
  pageSignalsByTab.delete(tabId);
  scanResultsByTab.delete(tabId);
});
