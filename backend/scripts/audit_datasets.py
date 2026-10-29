import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

try:
    import pyarrow
    import pyarrow.parquet as parquet
except ModuleNotFoundError as error:
    pyarrow = None
    parquet = None
    PYARROW_IMPORT_ERROR = error
else:
    PYARROW_IMPORT_ERROR = None


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DATASET_ROOT = PROJECT_ROOT / "dataset" / "raw"
EMAIL_PATH = RAW_DATASET_ROOT / "phishing_email_multilingual.csv"
URL_TRAIN_PATH = RAW_DATASET_ROOT / "fed_phishing_urls_train.parquet"
URL_TEST_PATH = RAW_DATASET_ROOT / "fed_phishing_urls_test.parquet"
REPORT_PATH = PROJECT_ROOT / "dataset" / "processed" / "dataset_audit.json"
BATCH_SIZE = 25_000


def _normalize_text(value: str) -> str:
    return " ".join((value or "").casefold().split())


def _normalize_url(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme.lower(), f"{hostname}{port}", parsed.path or "/", parsed.query, ""))
    except (UnicodeError, ValueError):
        return ""


def _read_email_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as csv_file:
        return list(csv.DictReader(csv_file))


def _label_conflicts(values: Iterable[tuple[str, str]]) -> int:
    labels_by_key: dict[str, set[str]] = defaultdict(set)
    for key, label in values:
        if key:
            labels_by_key[key].add(label)
    return sum(1 for labels in labels_by_key.values() if len(labels) > 1)


def _audit_email() -> dict[str, object]:
    rows = _read_email_rows(EMAIL_PATH)
    texts = [_normalize_text(row.get("text", "")) for row in rows]
    labels = [str(row.get("label", "")).strip() for row in rows]
    text_counts = Counter(texts)
    duplicate_groups = sum(1 for text, count in text_counts.items() if text and count > 1)
    duplicate_rows = sum(count - 1 for text, count in text_counts.items() if text and count > 1)
    return {
        "path": str(EMAIL_PATH.relative_to(PROJECT_ROOT)),
        "rows": len(rows),
        "class_distribution": dict(sorted(Counter(labels).items())),
        "empty_text_rows": sum(1 for text in texts if not text),
        "exact_duplicate_text_groups": duplicate_groups,
        "exact_duplicate_text_rows": duplicate_rows,
        "duplicate_text_label_conflicts": _label_conflicts(zip(texts, labels)),
        "notes": [
            "This checks exact normalized text duplicates only.",
            "It does not detect semantic paraphrases or near-duplicates.",
        ],
    }


def _parquet_values(path: Path, column: str) -> Iterable[str]:
    reader = parquet.ParquetFile(path)
    for batch in reader.iter_batches(columns=[column], batch_size=BATCH_SIZE):
        for value in batch.to_pydict()[column]:
            raw_value = value or ""
            yield _normalize_url(raw_value) if column == "url" else _normalize_text(raw_value)


def _parquet_label_counts(path: Path) -> tuple[int, Counter[str], int]:
    rows = 0
    empty_urls = 0
    labels: Counter[str] = Counter()
    reader = parquet.ParquetFile(path)
    for batch in reader.iter_batches(columns=["url", "label"], batch_size=BATCH_SIZE):
        columns = batch.to_pydict()
        for url, label in zip(columns["url"], columns["label"]):
            rows += 1
            labels[str(label)] += 1
            if not _normalize_text(url or ""):
                empty_urls += 1
    return rows, labels, empty_urls


def _audit_url() -> dict[str, object]:
    if parquet is None:
        return {
            "train_path": str(URL_TRAIN_PATH.relative_to(PROJECT_ROOT)),
            "test_path": str(URL_TEST_PATH.relative_to(PROJECT_ROOT)),
            "available": False,
            "reason": (
                "pyarrow is required to audit Parquet URL datasets. "
                "Install backend requirements with python -m pip install -r requirements.txt."
            ),
            "error": type(PYARROW_IMPORT_ERROR).__name__ if PYARROW_IMPORT_ERROR else None,
        }

    train_rows, train_labels, train_empty = _parquet_label_counts(URL_TRAIN_PATH)
    test_rows, test_labels, test_empty = _parquet_label_counts(URL_TEST_PATH)

    train_counts = Counter(_parquet_values(URL_TRAIN_PATH, "url"))
    test_counts = Counter(_parquet_values(URL_TEST_PATH, "url"))
    train_duplicate_groups = sum(1 for url, count in train_counts.items() if url and count > 1)
    test_duplicate_groups = sum(1 for url, count in test_counts.items() if url and count > 1)
    train_duplicate_rows = sum(count - 1 for url, count in train_counts.items() if url and count > 1)
    test_duplicate_rows = sum(count - 1 for url, count in test_counts.items() if url and count > 1)
    overlap_urls = set(train_counts).intersection(test_counts)
    overlap_urls.discard("")
    overlap_rows = sum(min(train_counts[url], test_counts[url]) for url in overlap_urls)

    return {
        "train_path": str(URL_TRAIN_PATH.relative_to(PROJECT_ROOT)),
        "test_path": str(URL_TEST_PATH.relative_to(PROJECT_ROOT)),
        "train_rows": train_rows,
        "test_rows": test_rows,
        "train_class_distribution": dict(sorted(train_labels.items())),
        "test_class_distribution": dict(sorted(test_labels.items())),
        "train_empty_url_rows": train_empty,
        "test_empty_url_rows": test_empty,
        "train_exact_duplicate_url_groups": train_duplicate_groups,
        "train_exact_duplicate_url_rows": train_duplicate_rows,
        "test_exact_duplicate_url_groups": test_duplicate_groups,
        "test_exact_duplicate_url_rows": test_duplicate_rows,
        "exact_train_test_overlap_urls": len(overlap_urls),
        "exact_train_test_overlap_rows": overlap_rows,
        "notes": [
            "URLs use the training normalization policy before exact train/test overlap is counted.",
            "It does not detect shared domains, campaigns, redirects, or near-duplicate paths.",
        ],
    }


def audit() -> dict[str, object]:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_form": "raw_source_snapshot_not_manually_cleaned",
        "runtime": {
            "python": sys.version.split()[0],
            "pyarrow": pyarrow.__version__ if pyarrow is not None else None,
        },
        "email": _audit_email(),
        "url": _audit_url(),
        "limitations": [
            "Exact duplicate checks are a first leakage screen, not proof that leakage is absent.",
            "Campaign-aware, domain-aware, source-separated, and time-based validation should be added for final research claims.",
        ],
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary_report = REPORT_PATH.with_suffix(REPORT_PATH.suffix + ".tmp")
    temporary_report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    temporary_report.replace(REPORT_PATH)
    return report


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2))
