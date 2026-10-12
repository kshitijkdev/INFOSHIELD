"""
InfoShield AI - ML Exposure Risk Model Training Script (Phase 4A)
Trains an explainable Scikit-Learn RandomForestClassifier to estimate
exposure risk for detected PII entities based on purpose context,
sensitivity, necessity, and document characteristics.

Saves trained model and preprocessing pipeline to:
ml_models/pii_risk_model.joblib
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "backend"))
DATA_PATH = os.path.join(BASE_DIR, "data", "risk_training.csv")
MODEL_DIR = os.path.join(BASE_DIR, "ml_models")
MODEL_PATH = os.path.join(MODEL_DIR, "pii_risk_model.joblib")
META_PATH = os.path.join(MODEL_DIR, "model_metadata.json")

os.makedirs(MODEL_DIR, exist_ok=True)

CATEGORICAL_FEATURES = [
    "pii_type",
    "document_type",
    "purpose_necessity",
    "purpose_domain",
    "purpose_task",
    "identity_binding_requirement",
    "exposure_level"
]

NUMERIC_FEATURES = [
    "pii_sensitivity",
    "ocr_confidence",
    "pii_confidence",
    "context_risk"
]

TARGET_COL = "risk_class"
CLASSES = ["LOW", "MEDIUM", "HIGH"]


def train_model():
    print("=" * 65)
    print("INFOSHIELD ML EXPOSURE RISK MODEL TRAINING")
    print("=" * 65)

    # 1. Load dataset
    if not os.path.isfile(DATA_PATH):
        raise FileNotFoundError(f"Training dataset not found: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)
    print(f"Loaded {len(df)} samples from: {DATA_PATH}")

    # Validate columns
    required_cols = CATEGORICAL_FEATURES + NUMERIC_FEATURES + [TARGET_COL]
    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset missing required columns: {missing}")

    # Class balance check
    print("\nTarget Class Distribution:")
    for cls_name, count in df[TARGET_COL].value_counts().items():
        print(f"  • {cls_name:<8}: {count} ({count/len(df)*100:.1f}%)")

    # 2. Features and Target
    X = df[CATEGORICAL_FEATURES + NUMERIC_FEATURES]
    y = df[TARGET_COL]

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 3. Preprocessing pipeline
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                CATEGORICAL_FEATURES
            ),
            (
                "num",
                StandardScaler(),
                NUMERIC_FEATURES
            )
        ]
    )

    # 4. Model specification: explainable RandomForest
    rf_clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=7,
        min_samples_split=3,
        random_state=42
    )

    pipeline = Pipeline(steps=[
        ("preprocessor", preprocessor),
        ("classifier", rf_clf)
    ])

    print("\nTraining RandomForestClassifier pipeline...")
    pipeline.fit(X_train, y_train)

    # 5. Evaluation
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec_macro = precision_score(y_test, y_pred, average="macro", zero_division=0)
    rec_macro = recall_score(y_test, y_pred, average="macro", zero_division=0)
    f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)
    prec_weight = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec_weight = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1_weight = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    print("\n" + "-" * 65)
    print("EVALUATION METRICS (Test Set):")
    print("-" * 65)
    print(f"Accuracy  : {acc * 100:.2f}%")
    print(f"Precision : {prec_macro * 100:.2f}% (Macro) | {prec_weight * 100:.2f}% (Weighted)")
    print(f"Recall    : {rec_macro * 100:.2f}% (Macro) | {rec_weight * 100:.2f}% (Weighted)")
    print(f"F1-Score  : {f1_macro * 100:.2f}% (Macro) | {f1_weight * 100:.2f}% (Weighted)")

    cm = confusion_matrix(y_test, y_pred, labels=CLASSES)
    print("\nConfusion Matrix (Rows: True, Cols: Pred [LOW, MEDIUM, HIGH]):")
    print(cm)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, labels=CLASSES, zero_division=0))

    # 6. Save model to disk
    joblib.dump(pipeline, MODEL_PATH)
    print(f"✓ Trained model artifact saved to: {MODEL_PATH}")

    metadata = {
        "model_name": "RandomForestClassifier",
        "model_version": "prototype-1",
        "library": "scikit-learn",
        "categorical_features": CATEGORICAL_FEATURES,
        "numeric_features": NUMERIC_FEATURES,
        "classes": CLASSES,
        "metrics": {
            "test_accuracy": round(float(acc), 4),
            "macro_precision": round(float(prec_macro), 4),
            "macro_recall": round(float(rec_macro), 4),
            "macro_f1": round(float(f1_macro), 4),
            "weighted_f1": round(float(f1_weight), 4)
        },
        "training_samples": len(df),
        "test_samples": len(X_test),
        "disclaimer": "PROTOTYPE MODEL: Trained on synthetic/curated risk dataset for demonstration purposes. Production deployment requires training against real organizational governance policy datasets."
    }

    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"✓ Model metadata saved to: {META_PATH}")
    print("\n" + "=" * 65)
    print("MODEL TRAINING COMPLETE!")
    print("=" * 65)


if __name__ == "__main__":
    train_model()
