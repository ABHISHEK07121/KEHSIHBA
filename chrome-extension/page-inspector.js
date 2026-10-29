(() => {
  if (globalThis.__KESHIHBA_PAGE_INSPECTOR__) return;
  globalThis.__KESHIHBA_PAGE_INSPECTOR__ = true;

  const BRAND_DOMAINS = {
    Interbank: ['interbank.pe', 'interbank.com.pe'],
    BCP: ['viabcp.com', 'bcp.com.pe'],
    BBVA: ['bbva.pe', 'bbva.com'],
    Scotiabank: ['scotiabank.com.pe', 'scotiabank.com'],
    Santander: ['santander.com', 'santander.com.pe'],
    PayPal: ['paypal.com'],
    Microsoft: ['microsoft.com', 'live.com', 'office.com'],
    Google: ['google.com', 'accounts.google.com'],
    Apple: ['apple.com', 'icloud.com'],
    Amazon: ['amazon.com', 'amazon.com.pe'],
    Netflix: ['netflix.com'],
    OpenAI: ['openai.com', 'chatgpt.com'],
  };

  function hostMatches(hostname, domains) {
    return domains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
  }

  function inspectPage() {
    const hostname = location.hostname.toLowerCase();
    const imageText = [...document.images].slice(0, 80)
      .map((image) => `${image.alt || ''} ${image.title || ''} ${image.getAttribute('aria-label') || ''}`)
      .join(' ');
    const metadata = [...document.querySelectorAll('meta[property="og:site_name"],meta[name="application-name"]')]
      .map((item) => item.content || '').join(' ');
    const pageText = document.body?.innerText?.slice(0, 16000) || '';
    const text = `${document.title} ${pageText} ${imageText} ${metadata}`
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
    const identityText = `${document.title} ${imageText} ${metadata}`
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
    const brandMismatches = Object.entries(BRAND_DOMAINS)
      .filter(([brand, domains]) => identityText.includes(brand.toLowerCase()) && !hostMatches(hostname, domains))
      .map(([brand]) => brand);
    const hasCredentialForm = Boolean(document.querySelector('input[type="password"],input[autocomplete="current-password"],input[autocomplete="new-password"]'));
    const hasExternalCredentialAction = [...document.forms].slice(0, 20).some((form) => {
      if (!form.querySelector('input[type="password"],input[autocomplete="current-password"],input[autocomplete="new-password"]')) return false;
      try { return new URL(form.action || location.href, location.href).hostname !== hostname; } catch { return true; }
    });
    const hasLoginCue = /(?:iniciar sesion|iniciar|ingresa|ingrese|acceder|login|log in|sign in|verify your account|verificar cuenta|contrasena|password|clave|usuario|documento de identidad)/i.test(text);
    return {
      url: location.href,
      brand_mismatches: brandMismatches,
      has_credential_form: hasCredentialForm,
      has_external_credential_action: hasExternalCredentialAction,
      has_login_cue: hasLoginCue,
    };
  }

  function publishSignals() {
    const signals = inspectPage();
    if (signals.brand_mismatches.length || signals.has_external_credential_action || signals.has_credential_form && signals.has_login_cue) {
      chrome.runtime.sendMessage({ type: 'KESHIHBA_PAGE_SIGNALS', signals }).catch(() => {});
    }
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === 'KESHIHBA_GET_PAGE_SIGNALS') {
      sendResponse(inspectPage());
    }
  });

  publishSignals();
})();
