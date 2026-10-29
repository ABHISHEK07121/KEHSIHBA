# Chrome Extension

KESHIHBA URL Guard is a Manifest V3 extension that automatically checks the active HTTP/HTTPS page URL with the local backend after navigation. Opening its popup also immediately scans the active page and displays the verdict and findings. A red `!` badge and Chrome notification appear for suspicious, high-risk, malicious, phishing, scam, credential-theft, malware, reputation, or brand-impersonation findings. The popup also lets you scan a pasted HTTP/HTTPS link and review detection reasons, threat reputation, DNS-resolved public IPs, and approximate IP network location when available.

To detect spoofed login pages, the extension locally checks visible text, image labels and addresses, site-name metadata, password/login cues, and password-form destinations against a short list of brands. A brand mismatch or a new-domain credential form raises a high-risk warning; an off-host password submission raises a suspicious warning. These are heuristics, not proof of fraud. Page text and entered form values stay in the browser; only the URL and detected brand/cue flags are used for URL analysis and warnings. It does not block navigation. This local page check requires access to HTTP/HTTPS pages, which Chrome may describe as permission to read site data.

## Load Locally

1. Start the backend at `http://127.0.0.1:8000`.
2. Open Chrome extensions: `chrome://extensions`.
3. Enable Developer mode.
4. Choose **Load unpacked** and select this `chrome-extension` folder.

The extension does not collect passwords, cookies, or browsing history. It scans active page URLs automatically and sends a pasted URL only when you click **Scan URL**. URL analysis can consult configured third-party reputation, DNS, registration, and network-location services. Do not use automatic scanning on sensitive browsing unless those lookups are acceptable. Chrome may also require notifications to be enabled in operating-system settings for alerts to appear.

After changing extension files, return to `chrome://extensions` and click **Reload** on KESHIHBA URL Guard.
