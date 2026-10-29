import json
import sys
from pathlib import Path
from typing import Any

import numpy
import sklearn


PROJECT_ROOT = Path(__file__).resolve().parents[3]
EMAIL_METRICS_PATH = PROJECT_ROOT / "dataset" / "processed" / "email_model_metrics.json"
URL_METRICS_PATH = PROJECT_ROOT / "dataset" / "processed" / "url_model_metrics.json"


def _read_metrics(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {
            "available": False,
            "reason": "Metrics file has not been generated yet. Run the matching training script.",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"available": False, "reason": "Metrics file could not be read."}
    data["available"] = True
    return data


def model_metadata() -> dict[str, Any]:
    email = _read_metrics(EMAIL_METRICS_PATH)
    url = _read_metrics(URL_METRICS_PATH)
    runtime = {
        "python": sys.version.split()[0],
        "scikit_learn": sklearn.__version__,
        "numpy": numpy.__version__,
    }
    version_warnings = []
    for label, metrics in (("Email model", email), ("URL model", url)):
        trained_version = (metrics.get("runtime") or {}).get("scikit_learn")
        if trained_version and trained_version != sklearn.__version__:
            version_warnings.append(
                f"{label} metrics were generated with scikit-learn {trained_version}, but the backend is running {sklearn.__version__}."
            )
    return {
        "email_model": email,
        "url_model": url,
        "runtime": runtime,
        "version_warnings": version_warnings,
        "rule_detectors": [
            {
                "name": "Email spam detector",
                "method": "Explainable keyword rules",
                "detects": ["unsolicited marketing", "promotions", "prize claims", "free trials"],
                "dataset": "No separate spam corpus is currently trained. Rules are defined in app.services.email_analyzer.",
            },
            {
                "name": "Email scam detector",
                "method": "Explainable keyword rules",
                "detects": ["gift-card scams", "wire-transfer scams", "investment scams", "recovery-fee scams"],
                "dataset": "No separate scam corpus is currently trained. Rules are defined in app.services.email_analyzer.",
            },
            {
                "name": "Malicious URL reputation",
                "method": "Threat intelligence, Google Safe Browsing (optional), and VirusTotal (optional)",
                "detects": ["current phishing-feed matches", "recent malware URLs", "Google Safe Browsing threat matches", "VirusTotal malicious or suspicious reputation"],
                "dataset": "OpenPhish Community and URLhaus are live reputation feeds, not static training datasets.",
            },
        ],
        "notes": [
            "Training and evaluation use raw source dataset snapshots from dataset/raw; the files are not manually cleaned or cherry-picked.",
            "Email scam and spam checks use explainable keyword and sender rules.",
            "Email and URL classifier outputs are uncalibrated model scores, not measured probabilities.",
            "Operational score thresholds are heuristic and have not been selected on an independent validation set.",
            "Malicious URL detection uses URL structure rules, the local URL classifier, live threat feeds, and optional VirusTotal reputation.",
            "Google Safe Browsing v4 is a VirusTotal fallback, requires a backend API key, and is for non-commercial use; commercial deployments should use Google Web Risk. A no-match result is not proof of safety.",
            "Dataset metrics are research holdout results and should not be presented as guaranteed real-world protection.",
            *version_warnings,
        ],
    }
