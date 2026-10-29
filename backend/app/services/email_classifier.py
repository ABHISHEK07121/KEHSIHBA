import logging
from pathlib import Path

import joblib


logger = logging.getLogger(__name__)
MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "email_text_classifier.joblib"


class LocalEmailClassifier:
    def __init__(self, model_path: Path = MODEL_PATH) -> None:
        self.model_path = model_path
        self._loaded_mtime: int | None = None
        self._pipeline = None

    def predict_phishing_probability(self, text: str) -> float | None:
        if not self.model_path.is_file():
            return None
        try:
            modified_at = self.model_path.stat().st_mtime_ns
            if modified_at != self._loaded_mtime:
                pipeline = joblib.load(self.model_path)
                if not hasattr(pipeline, "predict_proba") or 1 not in pipeline.classes_:
                    raise ValueError("Model must provide probabilities for label 1")
                self._pipeline = pipeline
                self._loaded_mtime = modified_at
            probabilities = self._pipeline.predict_proba([text])[0]
            phishing_index = list(self._pipeline.classes_).index(1)
            return float(probabilities[phishing_index])
        except Exception as error:
            logger.warning("Email model could not be loaded or used: %s", type(error).__name__)
            return None


email_classifier = LocalEmailClassifier()