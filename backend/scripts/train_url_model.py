import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit, urlunsplit

import joblib
import numpy as np
import pyarrow
import pyarrow.parquet as parquet
import sklearn
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_ROOT = PROJECT_ROOT / "dataset" / "raw"
TRAIN_PATH = DATASET_ROOT / "fed_phishing_urls_train.parquet"
TEST_PATH = DATASET_ROOT / "fed_phishing_urls_test.parquet"
MODEL_PATH = PROJECT_ROOT / "backend" / "app" / "models" / "url_text_classifier.joblib"
METRICS_PATH = PROJECT_ROOT / "dataset" / "processed" / "url_model_metrics.json"
DATASET_SOURCE = "flwrlabs/fed-phishing-urls"
DATASET_REVISION = "941d45362de147c316b05d6b3b00e0aefec33448"
BATCH_SIZE = 12_000
MAX_TRAIN_ROWS = int(os.getenv("URL_MODEL_MAX_TRAIN_ROWS", "300000"))
MAX_TEST_ROWS = int(os.getenv("URL_MODEL_MAX_TEST_ROWS", "60000"))
SUPPLEMENTAL_BENIGN_URLS = [
    "https://google.com/",
    "https://www.google.com/",
    "https://gmail.com/",
    "https://mail.google.com/",
    "https://microsoft.com/",
    "https://www.microsoft.com/",
    "https://apple.com/",
    "https://www.apple.com/",
    "https://github.com/",
    "https://pypi.org/",
    "https://wikipedia.org/",
    "https://example.com/",
    "https://aqua.com/",
]


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as dataset_file:
        for chunk in iter(lambda: dataset_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_batches(
    path: Path,
    excluded_urls: set[str] | None = None,
    excluded_seen: set[str] | None = None,
) -> Iterator[tuple[list[str], np.ndarray]]:
    if not path.is_file():
        raise FileNotFoundError(f"Missing dataset split: {path}")
    reader = parquet.ParquetFile(path)
    for batch in reader.iter_batches(columns=["url", "label"], batch_size=BATCH_SIZE):
        columns = batch.to_pydict()
        urls = [_normalize_training_url(url or "") for url in columns["url"]]
        labels = np.asarray(columns["label"], dtype=np.int8)
        valid = []
        for index, url in enumerate(urls):
            if not url:
                continue
            if excluded_urls is not None and url in excluded_urls:
                if excluded_seen is not None:
                    excluded_seen.add(url)
                continue
            valid.append(index)
        if valid:
            yield [urls[index] for index in valid], labels[valid]


def _normalize_training_url(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme.lower(), f"{host}{port}", parsed.path or "/", parsed.query, ""))
    except (UnicodeError, ValueError):
        return ""


def _build_vectorizer() -> HashingVectorizer:
    return HashingVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        n_features=2**20,
        alternate_sign=False,
        lowercase=True,
        norm="l2",
    )


def _build_classifier() -> SGDClassifier:
    return SGDClassifier(
        loss="log_loss",
        alpha=1e-5,
        random_state=42,
    )


def train() -> dict[str, object]:
    vectorizer = _build_vectorizer()
    classifier = _build_classifier()
    training_samples = 0
    first_batch = True
    test_urls: set[str] = set()
    for urls, _ in _read_batches(TEST_PATH):
        test_urls.update(urls)
    excluded_train_urls: set[str] = set()
    for urls, labels in _read_batches(TRAIN_PATH, test_urls, excluded_train_urls):
        remaining = MAX_TRAIN_ROWS - training_samples
        if remaining <= 0:
            break
        urls = urls[:remaining]
        labels = labels[:remaining]
        features = vectorizer.transform(urls)
        if first_batch:
            classifier.partial_fit(features, labels, classes=np.asarray([0, 1], dtype=np.int8))
            first_batch = False
        else:
            classifier.partial_fit(features, labels)
        training_samples += len(labels)

    supplemental_urls = [
        normalized
        for url in SUPPLEMENTAL_BENIGN_URLS
        if (normalized := _normalize_training_url(url)) and normalized not in test_urls
    ]
    supplemental_labels = np.zeros(len(supplemental_urls), dtype=np.int8)
    if supplemental_urls:
        classifier.partial_fit(vectorizer.transform(supplemental_urls), supplemental_labels)
        training_samples += len(supplemental_labels)

    if first_batch:
        raise ValueError("Training split contains no usable URLs")

    actual: list[int] = []
    predicted: list[int] = []
    for urls, labels in _read_batches(TEST_PATH):
        remaining = MAX_TEST_ROWS - len(actual)
        if remaining <= 0:
            break
        urls = urls[:remaining]
        labels = labels[:remaining]
        features = vectorizer.transform(urls)
        predicted.extend(classifier.predict(features).tolist())
        actual.extend(labels.tolist())

    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = (int(value) for value in matrix.ravel())
    metrics: dict[str, object] = {
        "dataset": DATASET_SOURCE,
        "dataset_revision": DATASET_REVISION,
        "license": "Apache-2.0",
        "dataset_form": "raw_source_snapshot_not_manually_cleaned",
        "train_sha256": _file_sha256(TRAIN_PATH),
        "test_sha256": _file_sha256(TEST_PATH),
        "train_samples": training_samples,
        "supplemental_benign_samples": len(SUPPLEMENTAL_BENIGN_URLS),
        "supplemental_benign_samples_used": len(supplemental_urls),
        "excluded_train_test_overlap_urls": len(excluded_train_urls),
        "test_samples": len(actual),
        "train_row_limit": MAX_TRAIN_ROWS,
        "test_row_limit": MAX_TEST_ROWS,
        "label_meaning": {"0": "benign", "1": "phishing_or_malicious"},
        "split": "official dataset train/test parquet files; exact URLs found in the full test split are excluded from fitting",
        "accuracy": accuracy_score(actual, predicted),
        "precision": precision_score(actual, predicted, zero_division=0),
        "recall": recall_score(actual, predicted, zero_division=0),
        "f1": f1_score(actual, predicted, zero_division=0),
        "false_positive_rate": false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0,
        "false_negative_rate": false_negative / (false_negative + true_positive) if false_negative + true_positive else 0.0,
        "confusion_matrix_labels_0_then_1": matrix.tolist(),
        "runtime": {
            "python": sys.version.split()[0],
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
            "pyarrow": pyarrow.__version__,
            "joblib": joblib.__version__,
        },
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "normalization": "Train and test URLs are normalized with the same scheme/host/path policy used by live scans to reduce scheme-format leakage.",
        "limitations": "Exact URLs shared with the full official test split are excluded from training. Shared domains, campaigns, redirects, and near-duplicates may remain; derived public URL datasets can contain stale or inactive URLs, so held-out scores do not establish current threat coverage. URLhaus data is malware IOC reputation data, not phishing training data.",
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    model = {"vectorizer": vectorizer, "classifier": classifier}
    temporary_model = MODEL_PATH.with_suffix(MODEL_PATH.suffix + ".tmp")
    temporary_metrics = METRICS_PATH.with_suffix(METRICS_PATH.suffix + ".tmp")
    joblib.dump(model, temporary_model)
    temporary_model.replace(MODEL_PATH)
    temporary_metrics.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    temporary_metrics.replace(METRICS_PATH)
    return metrics


if __name__ == "__main__":
    print(json.dumps(train(), indent=2))
