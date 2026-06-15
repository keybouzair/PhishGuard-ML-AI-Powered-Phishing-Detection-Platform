"""Runtime inference engine with one-time model loading.

Load order:
1) Unified pipeline artifact (phishing_pipeline.joblib / .pkl)
2) Legacy runtime model (phishingdetection.pkl)
3) Simple classifier fallback
"""

from __future__ import annotations

import os
import pickle
from typing import Any, Optional

import joblib

from ml.feature_pipeline import build_feature_frame


class InferenceEngine:
    def __init__(self, model_dir: str = "model"):
        self.model_dir = model_dir
        self.pipeline_model: Optional[Any] = None
        self.legacy_model: Optional[Any] = None
        self.simple_predict_url = None
        self.source = "none"
        self._load_once()

    def _load_once(self) -> None:
        if self._load_pipeline_model():
            self.source = "pipeline"
            return

        if self._load_legacy_model():
            self.source = "legacy"
            return

        if self._load_simple_fallback():
            self.source = "simple"
            return

        self.source = "none"

    def _load_pipeline_model(self) -> bool:
        for name in ("phishing_pipeline.joblib", "phishing_pipeline.pkl"):
            path = os.path.join(self.model_dir, name)
            if os.path.exists(path):
                try:
                    self.pipeline_model = joblib.load(path)
                    return True
                except Exception:
                    continue
        return False

    def _load_legacy_model(self) -> bool:
        path = os.path.join(self.model_dir, "phishingdetection.pkl")
        if not os.path.exists(path):
            return False
        try:
            with open(path, "rb") as f:
                self.legacy_model = pickle.load(f)
            return True
        except Exception:
            return False

    def _load_simple_fallback(self) -> bool:
        try:
            from simple_classifier import predict_url as _simple_predict_url

            self.simple_predict_url = _simple_predict_url
            return True
        except Exception:
            return False

    def is_available(self) -> bool:
        return self.source != "none"

    def _predict_with_model(self, model: Any, url: str) -> dict:
        features = build_feature_frame(url)
        pred = int(model.predict(features)[0])

        if hasattr(model, "predict_proba"):
            proba = float(model.predict_proba(features)[0][1])
        else:
            proba = 1.0 if pred == 1 else 0.0

        return {
            "label": pred,
            "is_phishing": pred == 1,
            "probability": proba,
            "score_percent": round(proba * 100, 2),
        }

    def predict_url(self, url: str) -> dict:
        if self.pipeline_model is not None:
            out = self._predict_with_model(self.pipeline_model, url)
            out["source"] = "pipeline"
            return out

        if self.legacy_model is not None:
            out = self._predict_with_model(self.legacy_model, url)
            out["source"] = "legacy"
            return out

        if callable(self.simple_predict_url):
            r = self.simple_predict_url(url)
            pred = 1 if r.get("is_phishing") else 0
            score = float(r.get("prediction_score", 0.0))
            out = {
                "label": pred,
                "is_phishing": pred == 1,
                "probability": max(0.0, min(1.0, score / 100.0)),
                "score_percent": round(score, 2),
                "source": "simple",
            }
            return out

        raise RuntimeError("No inference model is available")
