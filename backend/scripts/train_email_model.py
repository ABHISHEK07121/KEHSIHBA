import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = PROJECT_ROOT / "dataset" / "raw" / "phishing_email_multilingual.csv"
# Keep the small synthetic experiment separate from the active cross-corpus model.
MODEL_PATH = PROJECT_ROOT / "backend" / "app" / "models" / "email_synthetic_baseline.joblib"
METRICS_PATH = PROJECT_ROOT / "dataset" / "processed" / "email_synthetic_baseline_metrics.json"
DATASET_SOURCE = "Febriyansyah/phishing-emails-multilingual"
DATASET_REVISION = "81de6750a6658efaa1c0ae5a58acfe2b183d968c"


def _load_records(dataset_path: Path) -> tuple[list[str], list[int], str]:
    digest = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    texts: list[str] = []
    labels: list[int] = []
    with dataset_path.open(encoding="utf-8-sig", newline="") as csv_file:
        for row in csv.DictReader(csv_file):
            text = row.get("text", "").strip()
            label_value = row.get("label", "").strip()
            if text and label_value in {"0", "1"}:
                texts.append(text)
                labels.append(int(label_value))
    if not texts or set(labels) != {0, 1}:
        raise ValueError("Dataset must contain non-empty text with both binary labels 0 and 1")
    return texts, labels, digest


def _build_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=100_000,
                    sublinear_tf=True,
                ),
            ),
            ("classifier", LogisticRegression(class_weight="balanced", max_iter=2_000, random_state=42)),
        ]
    )


def _normalized_group(text: str) -> str:
    return " ".join(text.casefold().split())


def _grouped_split(texts: list[str], labels: list[int]) -> tuple[list[int], list[int]]:
    groups = [_normalized_group(text) for text in texts]
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    train_indices, test_indices = next(splitter.split(texts, labels, groups))
    return train_indices.tolist(), test_indices.tolist()


def train(dataset_path: Path = DATASET_PATH, model_path: Path = MODEL_PATH, metrics_path: Path = METRICS_PATH) -> dict[str, object]:
    texts, labels, dataset_sha256 = _load_records(dataset_path)
    train_indices, test_indices = _grouped_split(texts, labels)
    train_texts = [texts[index] for index in train_indices]
    test_texts = [texts[index] for index in test_indices]
    train_labels = [labels[index] for index in train_indices]
    test_labels = [labels[index] for index in test_indices]

    evaluation_model = _build_pipeline()
    evaluation_model.fit(train_texts, train_labels)
    predictions = evaluation_model.predict(test_texts)
    matrix = confusion_matrix(test_labels, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = (int(value) for value in matrix.ravel())

    metrics: dict[str, object] = {
        "dataset": DATASET_SOURCE,
        "dataset_revision": DATASET_REVISION,
        "dataset_sha256": dataset_sha256,
        "license": "MIT",
        "dataset_form": "raw_source_snapshot_not_manually_cleaned",
        "synthetic_dataset": True,
        "samples": len(texts),
        "train_samples": len(train_texts),
        "test_samples": len(test_texts),
        "label_meaning": {"0": "benign", "1": "phishing"},
        "split": {
            "folds": 5,
            "random_state": 42,
            "stratified": True,
            "grouped_by": "case-folded, whitespace-normalized exact text",
        },
        "accuracy": accuracy_score(test_labels, predictions),
        "precision": precision_score(test_labels, predictions, zero_division=0),
        "recall": recall_score(test_labels, predictions, zero_division=0),
        "f1": f1_score(test_labels, predictions, zero_division=0),
        "false_positive_rate": false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0,
        "false_negative_rate": false_negative / (false_negative + true_positive) if false_negative + true_positive else 0.0,
        "confusion_matrix_labels_0_then_1": matrix.tolist(),
        "runtime": {
            "python": sys.version.split()[0],
            "scikit_learn": sklearn.__version__,
            "numpy": numpy.__version__,
            "joblib": joblib.__version__,
        },
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "limitations": "Synthetic bilingual research data; holdout metrics do not establish real-world performance.",
    }

    final_model = _build_pipeline().fit(texts, labels)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_model = model_path.with_suffix(model_path.suffix + ".tmp")
    temporary_metrics = metrics_path.with_suffix(metrics_path.suffix + ".tmp")
    joblib.dump(final_model, temporary_model)
    temporary_model.replace(model_path)
    temporary_metrics.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    temporary_metrics.replace(metrics_path)
    return metrics


if __name__ == "__main__":
    print(json.dumps(train(), indent=2))
