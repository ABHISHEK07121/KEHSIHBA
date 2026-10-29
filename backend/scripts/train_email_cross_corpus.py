import csv
import hashlib
import io
import json
import random
import re
import sys
import zipfile
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

import joblib
import sklearn
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold

from train_email_model import _build_pipeline


PROJECT_ROOT = Path(__file__).resolve().parents[2]
EPVME_DIR = PROJECT_ROOT / "dataset" / "raw" / "epvme"
ENRON_PATH = PROJECT_ROOT / "dataset" / "raw" / "enron_spam_data.zip"
MODEL_PATH = PROJECT_ROOT / "backend" / "app" / "models" / "email_text_classifier.joblib"
METRICS_PATH = PROJECT_ROOT / "dataset" / "processed" / "email_model_metrics.json"
EPVME_REVISION = "f559178dafb015df4e6b35627c495237e6e2c560"
ENRON_REVISION = "e73c300263040f84b954e969ac06821c31cff47a"
MAX_SAMPLES_PER_CLASS = 16_000
MAX_EMAIL_BYTES = 2_000_000
MAX_BODY_CHARACTERS = 200_000
MAX_SUBJECT_CHARACTERS = 998
HTML_TAG = re.compile(r"<[^>]*>")
WHITESPACE = re.compile(r"\s+")


def _normalized_group(text: str) -> str:
    return WHITESPACE.sub(" ", text.casefold()).strip()


def _group_key(text: str) -> str:
    return hashlib.sha256(_normalized_group(text).encode("utf-8")).hexdigest()


def _combined_text(subject: str, body: str) -> str:
    return f"{subject[:MAX_SUBJECT_CHARACTERS]}\n{body[:MAX_BODY_CHARACTERS]}".strip()


def _email_text(raw: bytes) -> str:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    plain_parts: list[str] = []
    html_parts: list[str] = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type().lower()
        if not content_type.startswith("text/"):
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, ValueError):
            continue
        if not isinstance(content, str):
            continue
        if content_type == "text/html":
            html_parts.append(content)
        else:
            plain_parts.append(content)
    body = "\n".join(part for part in plain_parts if part).strip()
    if not body and html_parts:
        body = HTML_TAG.sub(" ", "\n".join(html_parts))
    subject = str(message.get("Subject") or "")
    return _combined_text(subject, body)


def _source_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.name.encode("utf-8"))
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _load_epvme() -> tuple[dict[str, str], int, int]:
    if not EPVME_DIR.is_dir():
        raise FileNotFoundError(f"Missing EPVME archive directory: {EPVME_DIR}")
    archives = sorted(EPVME_DIR.glob("EPVME_*.zip"))
    if len(archives) != 8:
        raise FileNotFoundError(f"Expected all 8 EPVME zip files in {EPVME_DIR}; found {len(archives)}")

    records: dict[str, str] = {}
    skipped = 0
    raw_samples = 0
    for archive_path in archives:
        with zipfile.ZipFile(archive_path) as archive:
            for entry in archive.infolist():
                if not entry.filename.lower().endswith(".eml"):
                    continue
                raw_samples += 1
                if entry.file_size > MAX_EMAIL_BYTES:
                    skipped += 1
                    continue
                try:
                    text = _email_text(archive.read(entry))
                except (OSError, ValueError, zipfile.BadZipFile):
                    skipped += 1
                    continue
                if text.strip():
                    records.setdefault(_group_key(text), text)
                else:
                    skipped += 1
    return records, skipped, raw_samples


def _load_enron_ham() -> tuple[dict[str, str], int]:
    if not ENRON_PATH.is_file():
        raise FileNotFoundError(f"Missing Enron Spam archive: {ENRON_PATH}")
    csv.field_size_limit(sys.maxsize)
    records: dict[str, str] = {}
    skipped = 0
    with zipfile.ZipFile(ENRON_PATH) as archive:
        csv_entries = [entry for entry in archive.infolist() if entry.filename.lower().endswith(".csv")]
        if len(csv_entries) != 1:
            raise ValueError(f"Expected one CSV in {ENRON_PATH}; found {len(csv_entries)}")
        with archive.open(csv_entries[0]) as raw_csv:
            reader = csv.DictReader(io.TextIOWrapper(raw_csv, encoding="utf-8-sig", errors="replace"))
            required_columns = {"Subject", "Message", "Spam/Ham"}
            if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
                raise ValueError(f"Enron CSV is missing required columns: {sorted(required_columns)}")
            for row in reader:
                if (row.get("Spam/Ham") or "").strip().casefold() != "ham":
                    continue
                text = _combined_text(row.get("Subject") or "", row.get("Message") or "")
                if text.strip():
                    records.setdefault(_group_key(text), text)
                else:
                    skipped += 1
    return records, skipped


def train() -> dict[str, Any]:
    epvme_records, epvme_skipped, epvme_raw_samples = _load_epvme()
    enron_records, enron_skipped = _load_enron_ham()
    conflicts = epvme_records.keys() & enron_records.keys()
    for normalized in conflicts:
        del epvme_records[normalized]
        del enron_records[normalized]

    if min(len(epvme_records), len(enron_records)) < 12_500:
        raise ValueError(
            "After exact-text deduplication, each class needs at least 12,500 unique records "
            "to support 10,000 or more training records and a held-out fold."
        )

    rng = random.Random(42)
    samples_per_class = min(MAX_SAMPLES_PER_CLASS, len(epvme_records), len(enron_records))
    phishing_texts = rng.sample(list(epvme_records.values()), samples_per_class)
    ham_texts = rng.sample(list(enron_records.values()), samples_per_class)
    texts = ham_texts + phishing_texts
    labels = [0] * len(ham_texts) + [1] * len(phishing_texts)
    groups = [_group_key(text) for text in texts]
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    train_indices, test_indices = next(splitter.split(texts, labels, groups))
    if len(train_indices) < 10_000:
        raise ValueError(f"Training split has only {len(train_indices)} records; at least 10,000 are required.")

    evaluation_model = _build_pipeline()
    evaluation_model.fit([texts[index] for index in train_indices], [labels[index] for index in train_indices])
    predictions = evaluation_model.predict([texts[index] for index in test_indices])
    matrix = confusion_matrix([labels[index] for index in test_indices], predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = (int(value) for value in matrix.ravel())

    source_archives = sorted(EPVME_DIR.glob("EPVME_*.zip")) + [ENRON_PATH]
    metrics: dict[str, Any] = {
        "dataset": "EPVME malicious emails + Enron Spam ham",
        "dataset_sources": [
            {
                "name": "sunknighteric/EPVME-Dataset",
                "revision": EPVME_REVISION,
                "license": "GPL-3.0 repository license; source data includes collected and constructed malicious emails",
                "raw_eml_samples": epvme_raw_samples,
                "unique_samples_after_deduplication": len(epvme_records),
            },
            {
                "name": "MWiechmann/enron_spam_data",
                "revision": ENRON_REVISION,
                "license": "GPL-3.0 repository license",
                "ham_samples_in_source": 16_545,
                "unique_samples_after_deduplication": len(enron_records),
            },
        ],
        "dataset_sha256": _source_digest(source_archives),
        "dataset_form": "public_research_corpora; exact normalized text duplicates removed",
        "evaluation_type": "cross_corpus_holdout",
        "accuracy_label": "Cross-corpus holdout accuracy",
        "synthetic_dataset": False,
        "samples_per_class": samples_per_class,
        "samples": len(texts),
        "train_samples": len(train_indices),
        "test_samples": len(test_indices),
        "class_distribution": {"0": len(ham_texts), "1": len(phishing_texts)},
        "label_meaning": {"0": "Enron non-spam (ham) proxy", "1": "EPVME malicious"},
        "split": {
            "folds": 5,
            "random_state": 42,
            "stratified": True,
            "grouped_by": "case-folded, whitespace-normalized exact subject and body",
        },
        "accuracy": accuracy_score([labels[index] for index in test_indices], predictions),
        "precision": precision_score([labels[index] for index in test_indices], predictions, zero_division=0),
        "recall": recall_score([labels[index] for index in test_indices], predictions, zero_division=0),
        "f1": f1_score([labels[index] for index in test_indices], predictions, zero_division=0),
        "false_positive_rate": false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0,
        "false_negative_rate": false_negative / (false_negative + true_positive) if false_negative + true_positive else 0.0,
        "confusion_matrix_labels_0_then_1": matrix.tolist(),
        "skipped_oversize_or_empty_email_files": epvme_skipped,
        "skipped_empty_enron_ham_records": enron_skipped,
        "conflicting_exact_texts_removed": len(conflicts),
        "runtime": {"python": sys.version.split()[0], "scikit_learn": sklearn.__version__},
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "limitations": (
            "This is a cross-corpus research benchmark, not current real-world accuracy. "
            "EPVME includes constructed attacks and older collected messages; Enron ham is old non-spam mail, "
            "not independently verified as phishing-free. Source, time, language, and collection differences "
            "can inflate or reduce held-out scores. This near-perfect result is likely driven by source/corpus "
            "artifacts and is not evidence of near-perfect phishing detection. Campaign-aware and time-separated "
            "evaluation on recent labeled mail is still required."
        ),
    }

    final_model = _build_pipeline().fit(texts, labels)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary_model = MODEL_PATH.with_suffix(MODEL_PATH.suffix + ".tmp")
    temporary_metrics = METRICS_PATH.with_suffix(METRICS_PATH.suffix + ".tmp")
    joblib.dump(final_model, temporary_model)
    temporary_model.replace(MODEL_PATH)
    temporary_metrics.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    temporary_metrics.replace(METRICS_PATH)
    return metrics


if __name__ == "__main__":
    print(json.dumps(train(), indent=2))
