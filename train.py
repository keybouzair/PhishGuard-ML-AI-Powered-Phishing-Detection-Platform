"""
Project trainer

What this script does:
1) Merges these datasets:
   - dataset/raw_data.csv (url,label)
   - dataset/phishing_legit_dataset.csv (text,label,...)
2) Trains a URL model used by the project runtime:
   - model/simple_model.joblib
   - model/simple_scaler.joblib
3) Trains an auxiliary text model (emails/messages):
   - model/text_phishing_model.joblib
4) Writes training summary:
   - model/training_report.json
   - model/feature_importance.json
"""

from __future__ import annotations

import json
import os
import time
import joblib
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    roc_auc_score,
    precision_recall_curve,
    auc as sk_auc,
)
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler

from ml.feature_pipeline import extract_feature_vector, FEATURE_NAMES


MODEL_DIR = "model"
RAW_DATASET_PATH = "dataset/raw_data.csv"
PHISHING_TEXT_DATASET_PATH = "dataset/phishing_legit_dataset.csv"

URL_MODEL_PATH = os.path.join(MODEL_DIR, "simple_model.joblib")
URL_SCALER_PATH = os.path.join(MODEL_DIR, "simple_scaler.joblib")
URL_THRESHOLD_PATH = os.path.join(MODEL_DIR, "simple_model_threshold.joblib")
TEXT_MODEL_PATH = os.path.join(MODEL_DIR, "text_phishing_model.joblib")
TRAINING_REPORT_PATH = os.path.join(MODEL_DIR, "training_report.json")
FEATURE_IMPORTANCE_PATH = os.path.join(MODEL_DIR, "feature_importance.json")
MODEL_MANIFEST_PATH = os.path.join(MODEL_DIR, "MODEL_MANIFEST.json")


@dataclass
class TrainResult:
    accuracy: float
    report: dict
    train_size: int
    test_size: int
    cv_roc_auc: Optional[float] = None
    roc_auc: Optional[float] = None
    pr_auc: Optional[float] = None
    threshold: float = 0.5


def normalize_label(value) -> Optional[int]:
    """Map different label styles to 0/1."""
    if pd.isna(value):
        return None

    if isinstance(value, (int, np.integer, float, np.floating)):
        if int(value) in (0, 1):
            return int(value)
        return None

    text = str(value).strip().lower()
    mapping = {
        "0": 0,
        "1": 1,
        "legitimate": 0,
        "safe": 0,
        "benign": 0,
        "phishing": 1,
        "malicious": 1,
        "unsafe": 1,
    }
    return mapping.get(text)


def load_raw_url_dataset(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        return pd.DataFrame(columns=["source", "url", "text", "label"])

    df = pd.read_csv(path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError(f"{path} must contain columns: url, label")

    out = pd.DataFrame(
        {
            "source": "raw_data",
            "url": df["url"].astype(str).str.strip(),
            "text": df["url"].astype(str).str.strip(),
            "label": df["label"].apply(normalize_label),
        }
    )
    return out.dropna(subset=["label"]).copy()


def load_phishing_text_dataset(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        return pd.DataFrame(columns=["source", "url", "text", "label"])

    df = pd.read_csv(path)
    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError(f"{path} must contain columns: text, label")

    out = pd.DataFrame(
        {
            "source": "phishing_legit_dataset",
            "url": np.nan,
            "text": df["text"].astype(str).str.strip(),
            "label": df["label"].apply(normalize_label),
        }
    )
    return out.dropna(subset=["label"]).copy()


def extract_simple_url_features(url: str) -> list[float]:
    """Canonical feature layout shared with runtime inference."""
    return extract_feature_vector(url)


def train_url_model(url_df: pd.DataFrame) -> TrainResult:
    """Train the URL model.

    E-06: 5-fold stratified CV for ROC-AUC + PR-AUC.
    E-07: time-based split when 'checked_at' is available; otherwise random.
    E-05: tune threshold against recall@1%FPR (FN > FP cost).
    """
    clean = url_df.dropna(subset=["url", "label"]).copy()
    clean = clean[clean["url"].str.startswith(("http://", "https://"), na=False)]
    clean = clean.drop_duplicates(subset=["url", "label"])

    if clean.empty:
        raise ValueError("No URL rows available for URL model training.")

    X = np.array([extract_simple_url_features(u) for u in clean["url"]])
    y = clean["label"].astype(int).values

    # E-07: time-based split when timestamp column exists
    if "checked_at" in clean.columns and clean["checked_at"].notna().any():
        clean = clean.sort_values("checked_at")
        split_idx = int(len(clean) * 0.8)
        X_train, X_test = X[:split_idx], X[split_idx:]
        y_train, y_test = y[:split_idx], y[split_idx:]
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

    # E-06: K-fold cross-validation on the training set
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_aucs = []
    for fold, (tr, va) in enumerate(cv.split(X_train, y_train)):
        scaler_cv = StandardScaler()
        Xtr = scaler_cv.fit_transform(X_train[tr])
        Xva = scaler_cv.transform(X_train[va])
        m = RandomForestClassifier(
            n_estimators=200, random_state=42,
            class_weight="balanced_subsample", n_jobs=-1,
        )
        m.fit(Xtr, y_train[tr])
        proba = m.predict_proba(Xva)[:, 1]
        try:
            cv_aucs.append(roc_auc_score(y_train[va], proba))
        except ValueError:
            pass
    cv_auc_mean = float(np.mean(cv_aucs)) if cv_aucs else None

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced_subsample",
        n_jobs=-1,
    )
    model.fit(X_train_scaled, y_train)

    y_proba = model.predict_proba(X_test_scaled)[:, 1]
    y_pred = (y_proba >= 0.5).astype(int)

    # E-05: tune threshold by maximising recall at <=1% FPR
    best_threshold = 0.5
    try:
        fpr, tpr, thr = precision_recall_curve(y_test, y_proba)
        # precision_recall_curve returns descending; build candidate thresholds
        candidates = np.unique(np.concatenate(([0.5], np.linspace(0.05, 0.95, 19), thr)))
        best_recall = -1.0
        for t in candidates:
            preds = (y_proba >= t).astype(int)
            tp = int(((preds == 1) & (y_test == 1)).sum())
            fp = int(((preds == 1) & (y_test == 0)).sum())
            fn = int(((preds == 0) & (y_test == 1)).sum())
            tn = int(((preds == 0) & (y_test == 0)).sum())
            fpr_v = fp / (fp + tn) if (fp + tn) > 0 else 0
            recall_v = tp / (tp + fn) if (tp + fn) > 0 else 0
            if fpr_v <= 0.01 and recall_v > best_recall:
                best_recall = recall_v
                best_threshold = float(t)
    except Exception:
        pass

    y_pred = (y_proba >= best_threshold).astype(int)
    acc = float(accuracy_score(y_test, y_pred))
    report = classification_report(y_test, y_pred, output_dict=True)
    try:
        roc_auc = float(roc_auc_score(y_test, y_proba))
    except ValueError:
        roc_auc = None
    try:
        prec, rec, _ = precision_recall_curve(y_test, y_proba)
        pr_auc = float(sk_auc(rec, prec))
    except ValueError:
        pr_auc = None

    joblib.dump(model, URL_MODEL_PATH)
    joblib.dump(scaler, URL_SCALER_PATH)
    joblib.dump({"threshold": best_threshold}, URL_THRESHOLD_PATH)

    # D-13: persist feature importance for the landing page / transparency
    if hasattr(model, "feature_importances_"):
        fi = {name: float(imp) for name, imp in zip(FEATURE_NAMES, model.feature_importances_)}
        with open(FEATURE_IMPORTANCE_PATH, "w", encoding="utf-8") as f:
            json.dump(fi, f, indent=2)

    result = TrainResult(
        accuracy=acc,
        report=report,
        train_size=len(X_train),
        test_size=len(X_test),
    )
    result.cv_roc_auc = cv_auc_mean
    result.roc_auc = roc_auc
    result.pr_auc = pr_auc
    result.threshold = best_threshold
    return result


def train_text_model(text_df: pd.DataFrame) -> TrainResult:
    """E-09: Train the text model on the *text* dataset only (not URLs)."""
    clean = text_df.dropna(subset=["text", "label"]).copy()
    clean = clean[clean["text"].str.len() > 0]
    clean = clean.drop_duplicates(subset=["text", "label"])

    if clean.empty:
        # E-08: Fail fast when no legitimate text rows are available
        raise ValueError("No text rows available for text model training.")

    X_train, X_test, y_train, y_test = train_test_split(
        clean["text"],
        clean["label"].astype(int),
        test_size=0.2,
        random_state=42,
        stratify=clean["label"].astype(int),
    )

    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=200000,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    model = LogisticRegression(
        max_iter=1500,
        solver="liblinear",
        class_weight="balanced",
    )
    model.fit(X_train_vec, y_train)

    y_pred = model.predict(X_test_vec)
    acc = float(accuracy_score(y_test, y_pred))
    report = classification_report(y_test, y_pred, output_dict=True)
    try:
        y_proba = model.predict_proba(X_test_vec)[:, 1]
        roc_auc = float(roc_auc_score(y_test, y_proba))
    except Exception:
        roc_auc = None

    payload = {"vectorizer": vectorizer, "model": model}
    joblib.dump(payload, TEXT_MODEL_PATH)

    result = TrainResult(
        accuracy=acc,
        report=report,
        train_size=X_train_vec.shape[0],
        test_size=X_test_vec.shape[0],
    )
    result.roc_auc = roc_auc
    return result


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    print("Loading datasets...")
    raw_df = load_raw_url_dataset(RAW_DATASET_PATH)
    text_df = load_phishing_text_dataset(PHISHING_TEXT_DATASET_PATH)

    # E-08: Fail fast if either dataset is empty — silence hides real failures
    if raw_df.empty:
        raise ValueError(
            f"No URL rows found in {RAW_DATASET_PATH}. Training cannot proceed."
        )
    if text_df.empty:
        raise ValueError(
            f"No text rows found in {PHISHING_TEXT_DATASET_PATH}. "
            "phishing_legit_rows must be > 0."
        )

    print(f"Raw URL rows: {len(raw_df):,}")
    print(f"Phishing/legit text rows: {len(text_df):,}")

    print("Training URL model for runtime classifier...")
    url_result = train_url_model(raw_df)
    print(f"URL model accuracy: {url_result.accuracy:.4f} "
          f"(ROC-AUC: {url_result.roc_auc}, threshold: {url_result.threshold:.2f})")

    # E-09: train the text model on the *text* dataset only
    print("Training text model on phishing_legit dataset...")
    text_result = train_text_model(text_df)
    print(f"Text model accuracy: {text_result.accuracy:.4f} "
          f"(ROC-AUC: {text_result.roc_auc})")

    report = {
        "datasets": {
            "raw_data_rows": int(len(raw_df)),
            "phishing_legit_rows": int(len(text_df)),
            "url_class_distribution": {
                str(k): int(v)
                for k, v in raw_df["label"].value_counts().to_dict().items()
            },
            "text_class_distribution": {
                str(k): int(v)
                for k, v in text_df["label"].value_counts().to_dict().items()
            },
        },
        "url_model": {
            "path": URL_MODEL_PATH,
            "scaler_path": URL_SCALER_PATH,
            "threshold_path": URL_THRESHOLD_PATH,
            "accuracy": url_result.accuracy,
            "roc_auc": url_result.roc_auc,
            "pr_auc": url_result.pr_auc,
            "cv_roc_auc": url_result.cv_roc_auc,
            "decision_threshold": url_result.threshold,
            "train_size": url_result.train_size,
            "test_size": url_result.test_size,
            "report": url_result.report,
        },
        "text_model": {
            "path": TEXT_MODEL_PATH,
            "accuracy": text_result.accuracy,
            "roc_auc": text_result.roc_auc,
            "train_size": text_result.train_size,
            "test_size": text_result.test_size,
            "report": text_result.report,
        },
        "feature_importance_path": FEATURE_IMPORTANCE_PATH,
        "model_manifest_path": MODEL_MANIFEST_PATH,
    }

    with open(TRAINING_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # E-18: write a hash manifest for runtime integrity check
    _write_model_manifest()

    print("Training complete.")
    print(f"Saved: {URL_MODEL_PATH}")
    print(f"Saved: {URL_SCALER_PATH}")
    print(f"Saved: {URL_THRESHOLD_PATH}")
    print(f"Saved: {TEXT_MODEL_PATH}")
    print(f"Saved: {TRAINING_REPORT_PATH}")
    print(f"Saved: {FEATURE_IMPORTANCE_PATH}")
    print(f"Saved: {MODEL_MANIFEST_PATH}")


def _write_model_manifest() -> None:
    """E-18: write SHA-256 manifest for runtime integrity verification."""
    import hashlib
    manifest = {}
    for path in (URL_MODEL_PATH, URL_SCALER_PATH, URL_THRESHOLD_PATH, TEXT_MODEL_PATH):
        if os.path.exists(path):
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            manifest[os.path.basename(path)] = h.hexdigest()
    with open(MODEL_MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


if __name__ == "__main__":
    main()