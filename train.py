"""
Project trainer

What this script does:
1) Merges these datasets:
   - dataset/raw_data.csv (url,label)
   - dataset/phishing_legit_dataset.csv (text,label,...)
2) Trains a URL model used by the project runtime:
   - model/simple_model.pkl
   - model/simple_scaler.pkl
3) Trains an auxiliary text model (emails/messages):
   - model/text_phishing_model.pkl
4) Writes training summary:
   - model/training_report.json
"""

from __future__ import annotations

import json
import os
import pickle
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from ml.feature_pipeline import extract_feature_vector


MODEL_DIR = "model"
RAW_DATASET_PATH = "dataset/raw_data.csv"
PHISHING_TEXT_DATASET_PATH = "dataset/phishing_legit_dataset.csv"

URL_MODEL_PATH = os.path.join(MODEL_DIR, "simple_model.pkl")
URL_SCALER_PATH = os.path.join(MODEL_DIR, "simple_scaler.pkl")
TEXT_MODEL_PATH = os.path.join(MODEL_DIR, "text_phishing_model.pkl")
TRAINING_REPORT_PATH = os.path.join(MODEL_DIR, "training_report.json")


@dataclass
class TrainResult:
    accuracy: float
    report: dict
    train_size: int
    test_size: int


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
    clean = url_df.dropna(subset=["url", "label"]).copy()
    clean = clean[clean["url"].str.startswith(("http://", "https://"), na=False)]
    clean = clean.drop_duplicates(subset=["url", "label"])

    if clean.empty:
        raise ValueError("No URL rows available for URL model training.")

    X = np.array([extract_simple_url_features(u) for u in clean["url"]])
    y = clean["label"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

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

    y_pred = model.predict(X_test_scaled)
    acc = float(accuracy_score(y_test, y_pred))
    report = classification_report(y_test, y_pred, output_dict=True)

    with open(URL_MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(URL_SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)

    return TrainResult(
        accuracy=acc,
        report=report,
        train_size=len(X_train),
        test_size=len(X_test),
    )


def train_text_model(merged_df: pd.DataFrame) -> TrainResult:
    clean = merged_df.dropna(subset=["text", "label"]).copy()
    clean = clean[clean["text"].str.len() > 0]
    clean = clean.drop_duplicates(subset=["text", "label"])

    if clean.empty:
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

    payload = {"vectorizer": vectorizer, "model": model}
    with open(TEXT_MODEL_PATH, "wb") as f:
        pickle.dump(payload, f)

    return TrainResult(
        accuracy=acc,
        report=report,
        train_size=X_train_vec.shape[0],
        test_size=X_test_vec.shape[0],
    )


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    print("Loading datasets...")
    raw_df = load_raw_url_dataset(RAW_DATASET_PATH)
    text_df = load_phishing_text_dataset(PHISHING_TEXT_DATASET_PATH)

    merged = pd.concat([raw_df, text_df], ignore_index=True)
    merged = merged.dropna(subset=["label"]).copy()

    if merged.empty:
        raise ValueError("No training rows found after merging datasets.")

    print(f"Merged rows: {len(merged):,}")
    print(f"- raw_data rows: {len(raw_df):,}")
    print(f"- phishing_legit rows: {len(text_df):,}")

    print("Training URL model for runtime classifier...")
    url_result = train_url_model(raw_df)
    print(f"URL model accuracy: {url_result.accuracy:.4f}")

    print("Training text model on merged data...")
    text_result = train_text_model(merged)
    print(f"Text model accuracy: {text_result.accuracy:.4f}")

    report = {
        "datasets": {
            "raw_data_rows": int(len(raw_df)),
            "phishing_legit_rows": int(len(text_df)),
            "merged_rows": int(len(merged)),
            "merged_class_distribution": {
                str(k): int(v) for k, v in merged["label"].value_counts().to_dict().items()
            },
        },
        "url_model": {
            "path": URL_MODEL_PATH,
            "scaler_path": URL_SCALER_PATH,
            "accuracy": url_result.accuracy,
            "train_size": url_result.train_size,
            "test_size": url_result.test_size,
            "report": url_result.report,
        },
        "text_model": {
            "path": TEXT_MODEL_PATH,
            "accuracy": text_result.accuracy,
            "train_size": text_result.train_size,
            "test_size": text_result.test_size,
            "report": text_result.report,
        },
    }

    with open(TRAINING_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("Training complete.")
    print(f"Saved: {URL_MODEL_PATH}")
    print(f"Saved: {URL_SCALER_PATH}")
    print(f"Saved: {TEXT_MODEL_PATH}")
    print(f"Saved: {TRAINING_REPORT_PATH}")


if __name__ == "__main__":
    main()