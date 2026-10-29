import logging
from pathlib import Path
from typing import Any

import joblib


logger = logging.getLogger(__name__)
MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "url_text_classifier.joblib"


class LocalURLClassifier:
    def __init__(self, model_path: Path = MODEL_PATH) -> None:
        self.model_path = model_path
        self._loaded_mtime: int | None = None
        self._model: dict[str, Any] | None = None

    def predict_phishing_probability(self, url: str) -> float | None:
        if not self.model_path.is_file():
            return None
        try:
            modified_at = self.model_path.stat().st_mtime_ns
            if modified_at != self._loaded_mtime:
                model = joblib.load(self.model_path)
                if not isinstance(model, dict) or not {"vectorizer", "classifier"}.issubset(model):
                    raise ValueError("URL model must contain vectorizer and classifier")
                if not hasattr(model["classifier"], "predict_proba"):
                    raise ValueError("URL model classifier must support probabilities")
                self._model = model
                self._loaded_mtime = modified_at
            features = self._model["vectorizer"].transform([url])
            classifier = self._model["classifier"]
            probabilities = classifier.predict_proba(features)[0]
            phishing_index = list(classifier.classes_).index(1)
            return float(probabilities[phishing_index])
        except Exception as error:
            logger.warning("URL model could not be loaded or used: %s", type(error).__name__)
            return None


url_classifier = LocalURLClassifier()