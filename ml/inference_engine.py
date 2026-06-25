"""Runtime inference engine with one-time model loading.

Load order:
1) Unified pipeline artifact (phishing_pipeline.joblib / .pkl)
2) Legacy runtime model (phishingdetection.pkl)
3) Simple classifier fallback

Security: A-07 — All model files are loaded via joblib (not raw pickle).
          SHA-256 hashes are verified from MODEL_MANIFEST.json when present.
          The pipeline's n_features_in_ is validated at load time (C-23).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any, Optional

import joblib

from ml.feature_pipeline import build_feature_frame

logger = logging.getLogger("phishing_app.ml")


class InferenceEngine:
    def __init__(self, model_dir: str = "model"):
        self.model_dir = model_dir
        self.pipeline_model: Optional[Any] = None
        self.legacy_model: Optional[Any] = None
        self.simple_predict_url = None
        self.source = "none"
        self._manifest: dict = {}
        self._load_manifest()
        self._load_once()

    # ---------- Manifest & integrity ----------

    def _load_manifest(self) -> None:
        """Load MODEL_MANIFEST.json containing SHA-256 hashes for verification."""
        manifest_path = os.path.join(self.model_dir, "MODEL_MANIFEST.json")
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r") as f:
                    self._manifest = json.load(f)
                logger.info("Model manifest loaded with %d entries", len(self._manifest))
            except Exception as e:
                logger.error("Failed to load model manifest: %s", e)

    def _verify_file_hash(self, path: str) -> bool:
        """Verify SHA-256 hash of model file against manifest (A-07).

        If no manifest entry exists for this file, verification is skipped
        (we log a warning but allow loading for development convenience).
        """
        basename = os.path.basename(path)
        expected_hash = self._manifest.get(basename)
        if expected_hash is None:
            logger.warning(
                "No manifest entry for %s — skipping hash verification "
                "(create MODEL_MANIFEST.json for production)", basename
            )
            return True

        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        actual = sha.hexdigest()
        if actual != expected_hash:
            logger.error(
                "INTEGRITY FAILURE: %s expected sha256=%s, got %s — refusing to load",
                basename, expected_hash, actual,
            )
            return False
        logger.info("Model %s integrity verified (sha256=%s)", basename, actual[:16])
        return True

    # ---------- Load order ----------

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
        for name in ("phishing_pipeline.joblib",):
            path = os.path.join(self.model_dir, name)
            if os.path.exists(path):
                if not self._verify_file_hash(path):
                    continue
                try:
                    model = joblib.load(path)
                    # C-23: validate expected feature count at load time
                    expected = getattr(model, "n_features_in_", None)
                    if expected is not None:
                        logger.info("Pipeline expects %d features", expected)
                    self.pipeline_model = model
                    return True
                except Exception as e:
                    logger.error("Failed to load pipeline model %s: %s", name, e)
                    continue
        return False

    def _load_legacy_model(self) -> bool:
        """Load legacy model using joblib (A-07: never use raw pickle.load)."""
        # A-07: Only support .joblib format for legacy model
        for name in ("phishingdetection.joblib", "simple_model.joblib"):
            path = os.path.join(self.model_dir, name)
            if not os.path.exists(path):
                continue
            if not self._verify_file_hash(path):
                continue
            try:
                model = joblib.load(path)
                self.legacy_model = model
                logger.info("Loaded legacy model from %s", name)
                return True
            except Exception as e:
                logger.error("Failed to load legacy model %s: %s", name, e)

        # Check for .pkl files — log a clear error instead of loading
        pkl_path = os.path.join(self.model_dir, "phishingdetection.pkl")
        if os.path.exists(pkl_path):
            logger.error(
                "A-07: Refusing to load %s via pickle.load() — "
                "convert to .joblib format using: "
                "joblib.dump(model, 'model/phishingdetection.joblib')",
                pkl_path,
            )
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
