"""
InfoShield AI - Model Information Inspection Utility (Phase 4A)
Displays technical architectural metadata for the Purpose AI NLP engine
and Scikit-Learn ML Exposure Risk model for faculty demonstration.
"""

import os
import sys
import json

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from purpose_ai import get_purpose_ai, PURPOSE_KNOWLEDGE_BASE
from risk_model import get_risk_model, META_PATH, MODEL_PATH


def display_model_info():
    print("=" * 68)
    print("              INFOSHIELD AI & ML MODEL SPECIFICATION")
    print("=" * 68)

    # 1. Purpose AI Section
    purpose_ai = get_purpose_ai()
    domains = sorted(list(set(item["domain"] for item in PURPOSE_KNOWLEDGE_BASE)))
    intents = [item["id"] for item in PURPOSE_KNOWLEDGE_BASE]

    print("\n[1] PURPOSE UNDERSTANDING (NLP / SEMANTIC AI)")
    print("-" * 68)
    print(f"Model Name           : {purpose_ai.model_name}")
    print(f"Model Architecture   : {purpose_ai.model_type}")
    print(f"Operational Mode     : {'Fallback Active (scikit-learn vector space)' if purpose_ai.is_fallback else 'Primary (sentence-transformers)'}")
    if purpose_ai.is_fallback:
        print(f"Reason for Fallback  : {purpose_ai.fallback_reason}")
    print(f"Knowledge Base Size  : {len(PURPOSE_KNOWLEDGE_BASE)} curated intent classes ({len(purpose_ai.corpus_texts)} example sentences)")
    print(f"Supported Domains ({len(domains)}) : {', '.join(domains)}")
    print("Supported Intents    :")
    for d in domains:
        d_tasks = [item["task"] for item in PURPOSE_KNOWLEDGE_BASE if item["domain"] == d]
        print(f"  • {d.upper():<14} : {', '.join(sorted(list(set(d_tasks))))}")

    # 2. Risk ML Model Section
    risk_model = get_risk_model()
    meta = risk_model.metadata

    print("\n[2] PII EXPOSURE RISK PREDICTOR (SCIKIT-LEARN ML)")
    print("-" * 68)
    print(f"Model Algorithm      : {meta.get('model_name', 'RandomForestClassifier')}")
    print(f"Model Version        : {meta.get('model_version', 'prototype-1')}")
    print(f"Library              : {meta.get('library', 'scikit-learn')}")
    print(f"Model Artifact Path  : {MODEL_PATH}")
    print(f"Training Samples     : {meta.get('training_samples', 'N/A')}")
    print(f"Test Samples         : {meta.get('test_samples', 'N/A')}")
    print(f"Risk Target Classes  : {', '.join(meta.get('classes', ['LOW', 'MEDIUM', 'HIGH']))}")

    cat_feats = meta.get("categorical_features", [])
    num_feats = meta.get("numeric_features", [])
    print(f"\nFeature Schema ({len(cat_feats) + len(num_feats)} total):")
    print(f"  • Categorical ({len(cat_feats)}) : {', '.join(cat_feats)}")
    print(f"  • Numeric ({len(num_feats)})     : {', '.join(num_feats)}")

    metrics = meta.get("metrics", {})
    print("\nEvaluation Metrics (Test Set):")
    print(f"  • Test Accuracy    : {metrics.get('test_accuracy', 0.0) * 100:.2f}%")
    print(f"  • Macro Precision  : {metrics.get('macro_precision', 0.0) * 100:.2f}%")
    print(f"  • Macro Recall     : {metrics.get('macro_recall', 0.0) * 100:.2f}%")
    print(f"  • Macro F1-Score   : {metrics.get('macro_f1', 0.0) * 100:.2f}%")
    print(f"  • Weighted F1-Score: {metrics.get('weighted_f1', 0.0) * 100:.2f}%")

    print("\nDisclaimer:")
    print(f"  {meta.get('disclaimer', 'Prototype demonstration model.')}")

    print("\n" + "=" * 68)


if __name__ == "__main__":
    display_model_info()
