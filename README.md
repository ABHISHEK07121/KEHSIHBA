# KESHIHBA: Cybersecurity Threat Analysis and Evidence Collection

KESHIHBA is a cybersecurity research prototype for gathering investigation
evidence about suspicious emails, scam or spam messages, and potentially
malicious links and webpages. It combines explainable checks, local text
classifiers, DNS and domain details, approximate public-IP network
geolocation, and optional threat reputation sources. Scan results identify
the submitted or extracted link and show the findings that contributed to
its risk assessment.

This is a research prototype, not a guarantee of safety or a production
security service. Its saved model results are dataset-specific and do not
establish real-world effectiveness.

## What it analyzes

- **Email:** Pasted content or supported `.eml`, `.pdf`, `.doc`, `.docx`,
  `.txt`, and HTML uploads. Checks include urgency, credential and payment
  language, selected sender/brand mismatches, spam/scam terms, visible links,
  and destinations hidden behind HTML email hyperlinks. For `.eml` uploads,
  OCR checks up to three image attachments (up to 5 MB each) for readable
  message text and URLs, which are then analyzed with the email rules and URL
  scanner. Uploads are capped at 10 MiB and extracted content at 200,000
  characters. Parser failures are returned explicitly; incomplete attachment
  OCR is reported and yields `Unknown` when no stronger evidence exists.
- **URLs:** URL and hostname structure, selected suspicious patterns,
  local model evidence, and available reputation/domain signals.
- **Browser extension:** A Chrome Manifest V3 extension submits the active
  HTTP/HTTPS page URL to the backend when the user scans it.

## Investigation evidence

URL reports can include resolved public IP addresses, DNS records, TLS
certificate details, domain registration information, approximate IP
network location and provider, and available threat-reputation matches.
Email reports identify embedded links and show their URL findings so an
investigator can see which link triggered concern. These are investigation
leads: IP geolocation describes the network registration area, and a flagged
message or URL is not by itself proof of a person's identity or intent.
KESHIHBA analyzes URL metadata without automatically opening the submitted
webpage.

Email spam and scam detection uses hand-authored rules; there is no separate
trained spam or scam model. The overall risk score is heuristic, not a
calibrated probability. `No Known Threat Detected` means only that available checks did not find
enough risk evidence. If the URL model is unavailable and other checks are
inconclusive, the result is `Unknown`; neither result proves safety. Local
model scores are not calibrated probabilities.

## Architecture

- `backend/`: FastAPI API, analysis services, dataset audit/training scripts,
  and tests.
- `frontend/`: React/Vite dashboard for scans, results, and research data.
- `chrome-extension/`: optional active-tab URL scan interface.
- `dataset/raw/`: pinned email CSV and URL Parquet source snapshots.
- `dataset/processed/`: generated audits and model metrics.
- `docs/`: architecture and research notes.
- `AQUA.TXT`: detailed research-paper preparation draft.

The URL scan endpoint analyzes a submitted URL without browsing or rendering
its webpage. Some optional checks do make network requests, including DNS,
TLS, RDAP, and reputation lookups. Optional external providers may receive
the URL; consider this before submitting sensitive links.

### URL report status and coverage

`POST /api/analyze/url` and `/api/analyze/urls` return the original verdict
and risk score plus `url_components`, `category`, `confidence`, `checks`,
`limitations`, and provider-specific reports. `confidence` remains `null`:
the local URL model score is uncalibrated. Check values are `matched`,
`no_match`, `error`, `not_checked`, `unknown`, or `completed`; a `no_match`
only means that particular provider reported no match, not that the URL is
safe. Provider reports include their check/refresh timestamps where
available, and VirusTotal flagged-engine details are capped at 20.

The URL report parses URL structure and includes A, AAAA, CNAME, MX, NS,
and TXT DNS records, public IP/network metadata, TLS, RDAP and Certificate
Transparency results when available. The result explicitly says that HTTP
redirect chains are `not_checked` during the initial scan; use the existing
bounded, SSRF-protected **Expand redirects** action to check them separately.
This action uses outbound HEAD requests and revalidates each public
destination. Page content, forms, JavaScript navigation, downloads, historical
DNS changes, PhishTank data, and automated IP reputation are not part of the
initial URL scan; the separate IP reputation utility remains manual. The
registered-domain boundary is a lightweight suffix heuristic, not a full
Public Suffix List implementation. Webpage inspection requires a separately
isolated analysis service and is intentionally not represented as completed.

## Run locally on Windows

One-time setup from the project root:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
Set-Location frontend
npm install
Set-Location ..
```

The launcher expects this project-local `.venv` and starts the backend and
frontend in separate PowerShell windows. After setup, run from the project
root:

```powershell
.\start-kesihba.ps1
```

The dashboard is served at `http://localhost:5173/`; the backend API is
served at `http://127.0.0.1:8000/`. Interactive API documentation is at
`http://127.0.0.1:8000/docs`.

To start services separately:

```powershell
# Backend
Set-Location backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

In another terminal:

```powershell
# Frontend
Set-Location frontend
npm run dev
```

Create `backend/.env` for optional server-side integrations. Never commit
API keys or put them in frontend/Vite environment variables.

```dotenv
VIRUSTOTAL_API_KEY=your_virustotal_key
VIRUSTOTAL_API_KEYS=backup_key_1,backup_key_2
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_key
URLHAUS_AUTH_KEY=your_urlhaus_key
```

OpenPhish Community feed matching is used by the backend. URLhaus requires
an Auth-Key; VirusTotal can use an ordered comma-separated key list and rotates
to the next key when a key is rejected, rate-limited, or unavailable. Google
Safe Browsing v4 is a fallback
when VirusTotal is unavailable or has no URL report. Google Safe Browsing is
non-commercial only, and submitted URLs may be shared by Google. Tesseract must be installed separately
to OCR image attachments in `.eml` files. Attachment OCR can miss small,
distorted, or obfuscated text.
If the Tesseract executable is not on `PATH`, set the backend-only
`TESSERACT_CMD` variable to its full executable path.

## Train and audit the models

The source snapshots are stored under `dataset/raw/`. From `backend/`, run:

```powershell
..\.venv\Scripts\python.exe scripts\audit_datasets.py
..\.venv\Scripts\python.exe scripts\train_email_cross_corpus.py
..\.venv\Scripts\python.exe scripts\train_url_model.py
```

Training writes local model artifacts under `backend/app/models/` and
metrics/audit JSON files under `dataset/processed/`. The URL trainer streams
Parquet data in batches. Review each script and confirm the raw datasets are
present before training.

`train_email_model.py` is the small synthetic baseline experiment. It writes
`email_synthetic_baseline.joblib` and
`email_synthetic_baseline_metrics.json`; it does not replace the active email
model or its evaluation report.

### Models

- **Email:** Character TF-IDF n-grams (3–5) with logistic regression. The
  active cross-corpus training script groups exact normalized messages before
  its stratified holdout, then fits the saved model on all available messages.
- **URL:** Character hashing n-grams (3–5) with an incremental SGD
  classifier configured for logistic loss. The saved run caps training at
  300,000 dataset rows and evaluation at 60,000 test rows, and uses 12
  supplemental benign URLs.

## Datasets and saved evaluation

The project uses raw pinned source snapshots; the source files are not
manually cleaned. Details, revisions, hashes, and audit limitations are in
`dataset/README.md`, `dataset/processed/dataset_audit.json`, and the model
metrics JSON files.

| Model | Dataset | Evaluation size | Accuracy | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|
| Email | EPVME malicious + Enron ham | 6,236 | 99.90% | 99.84% | 99.97% | 99.90% |
| URL | `flwrlabs/fed-phishing-urls` | 60,000 | 90.10% | 91.86% | 89.21% | 90.51% |

These are saved model holdout results, not end-to-end or current real-world
accuracy. The email confusion matrix (benign first, malicious second) is
`[[3113, 5], [1, 3117]]`; its near-perfect score is likely affected by source,
time, language, and collection artifacts. The email corpus has a 0.16% false
positive rate and 0.03% false negative rate on this holdout only. The URL
confusion matrix is `[[25714, 2512], [3429, 28345]]`, with an 8.90% false
positive rate and 10.79% false negative rate on its sampled holdout.

Additional public email corpus references for future experiments, including
Nazario, SpamAssassin, TREC 2007, and Wooyun Email XSS, are listed in
`dataset/README.md`. These remain reference sources and are not included in
the current cross-corpus email metrics.

The URL dataset's official files contain exact normalized train/test
overlaps. The recorded training run excluded 4,733 overlapping URLs found in
its capped training region, but the full-source audit still reports 14,073
unique exact overlaps. Domain-, campaign-, and near-duplicate leakage are
not ruled out, and public URLs may be stale. The 60,000-row result is
preliminary, not an operational guarantee.

The saved metrics were generated with scikit-learn 1.9.1. The project notes
also record later verification with scikit-learn 1.8.0 and model-persistence
warnings. For publication, rerun the audit and training in one pinned
environment and report the matching code, data, model, and runtime versions.

## API overview

- `GET /health`
- `POST /api/analyze/email`
- `POST /api/analyze/url`
- `POST /api/analyze/urls` (up to 10 URLs)
- `GET /api/models`
- `GET /api/intelligence/status`
- `GET /api/scans` and `GET /api/scans/summary` (account history)
- `GET /api/tools/dns`, `/ssl`, `/domain-age`, `/ip-reputation`
- `POST /api/tools/link-expander`

Authentication, account-scoped scan history, and emailing reports are
optional application features. Report email requires backend SMTP
configuration. See the API documentation at `/docs` for request and
response schemas.

## Chrome extension

1. Start the local backend.
2. Open `chrome://extensions` and enable Developer mode.
3. Select **Load unpacked** and choose `chrome-extension/`.
4. Open an HTTP/HTTPS page and use the KESHIHBA extension popup to scan it.

The extension automatically checks the active page URL after navigation and
shows a warning badge and notification for high-risk, malicious, scam, or
brand-impersonation findings. It can also scan a pasted HTTP/HTTPS link. Local
page checks inspect visible text, page title, image labels/addresses and
site-name metadata for known brands, login cues, new-domain credential forms,
and password forms that submit to a different hostname. Only the URL and
boolean/brand indicators are sent to the local extension worker; page text and
form values are not sent to the backend. A page check is heuristic, does not
render or fetch a page from the backend, and can miss image-only or obfuscated
content. A low-risk result is labeled **No Known Threat Detected**, not safe.
URL analysis can use configured external reputation and domain lookup services.
More details are in
`chrome-extension/README.md`.

## Tests and frontend build

From `backend/`:

```powershell
..\.venv\Scripts\python.exe -m unittest discover -s tests
```

From `frontend/`:

```powershell
npm run build
```

From `chrome-extension/`, run the local page-signal regression checks with:

```powershell
node --test risk-utils.test.js
```

Passing tests or a successful build verifies only the behaviors covered by
those checks; neither establishes real-world detection performance.

The model outputs are not probability-calibrated. The displayed model score
is separate from the rule/reputation risk score, and the current score bands
have not been selected using an independent validation set. Do not interpret
either score as a measured probability of compromise.

## Research and safe-use notes

- Treat verdicts as advisory; neither a model score nor an absent feed match
  proves a URL or message safe.
- Do not visit URLs from the research datasets.
- Do not submit confidential messages or sensitive URLs unless authorized.
- Optional external reputation services may receive submitted URL data.
- Keep credentials in backend-only configuration and do not commit `.env`
  files.
- Cite dataset publishers, revisions, licenses, and external providers when
  reporting research results.
- Do not claim a novel algorithm, perfect real-world accuracy, or
  attack-prevention effectiveness from the current evidence.

For the fuller research discussion, limitations, citations, and recommended
experiments, see `AQUA.TXT` and `docs/research-notes.md`.
