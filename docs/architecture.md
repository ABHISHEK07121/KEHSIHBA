# Architecture

## Planned Components

- Chrome Extension: Captures the active page URL and displays scan results.
- FastAPI Backend: Provides REST APIs for URL, email, and health scans.
- Detection Services: Rule-based analyzers for URLs, emails, OCR text, and risk scoring.
- Threat Intelligence: Optional VirusTotal lookup using `VIRUSTOTAL_API_KEY`.
- SQLite Database: Stores safe scan metadata and detection results.
- React Dashboard: Provides scanner pages, scan results, scan history, and research notes.

## Data Safety

The system should avoid collecting passwords, cookies, browsing history, authentication tokens, or unnecessary personal information.
