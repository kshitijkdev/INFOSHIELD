"""
InfoShield AI - ML Exposure Risk Model Inference Engine (Phase 4A)
Loads the trained Scikit-Learn RandomForest pipeline from ml_models/pii_risk_model.joblib
and performs explainable exposure-risk inference for detected PII entities.

Architecture:
1. Loads trained model once at startup (errors out if model artifact missing).
2. Computes multi-factor risk features for detected PII (sensitivity, necessity, domain context, OCR quality).
3. Produces risk_class (LOW, MEDIUM, HIGH) and risk_probability.
4. Integrates with the Policy Layer to synthesize explainable final protection decisions.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from typing import Dict, Any, Optional, Tuple

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

_env_model_dir = os.getenv("RISK_MODEL_DIR")
if not _env_model_dir:
    MODEL_DIR = os.path.join(BASE_DIR, "ml_models")
elif not os.path.isabs(_env_model_dir):
    MODEL_DIR = os.path.join(BASE_DIR, _env_model_dir)
else:
    MODEL_DIR = _env_model_dir

_env_model_path = os.getenv("RISK_MODEL_PATH")
if not _env_model_path:
    MODEL_PATH = os.path.join(MODEL_DIR, "pii_risk_model.joblib")
elif not os.path.isabs(_env_model_path):
    MODEL_PATH = os.path.join(BASE_DIR, _env_model_path)
else:
    MODEL_PATH = _env_model_path

_env_meta_path = os.getenv("RISK_MODEL_META_PATH")
if not _env_meta_path:
    META_PATH = os.path.join(MODEL_DIR, "model_metadata.json")
elif not os.path.isabs(_env_meta_path):
    META_PATH = os.path.join(BASE_DIR, _env_meta_path)
else:
    META_PATH = _env_meta_path

_env_sens_path = os.getenv("PII_SENSITIVITY_PATH")
if not _env_sens_path:
    SENSITIVITY_PATH = os.path.join(BASE_DIR, "data", "pii_sensitivity.json")
elif not os.path.isabs(_env_sens_path):
    SENSITIVITY_PATH = os.path.join(BASE_DIR, _env_sens_path)
else:
    SENSITIVITY_PATH = _env_sens_path

# Default baseline domain context risks
DOMAIN_CONTEXT_RISKS = {
    "education": 0.45,
    "employment": 0.60,
    "banking": 0.85,
    "government": 0.70,
    "travel": 0.65,
    "healthcare": 0.75,
    "legal": 0.80,
    "general": 0.50
}

# Identity binding requirement heuristics
IDENTITY_BINDING = {
    "person_name": "HIGH",
    "date_of_birth": "MEDIUM",
    "aadhaar_number": "HIGH",
    "pan_number": "HIGH",
    "vid": "LOW",
    "mobile_number": "LOW",
    "address": "MEDIUM",
    "gender": "LOW",
    "qr_code": "LOW",
    "bank_account_number": "HIGH",
    "ifsc_code": "LOW",
    "email_address": "LOW",
    "pin_code": "LOW",
    "photograph": "HIGH",
    "licence_number": "HIGH",
    "validity_date": "LOW",
    "blood_group": "LOW",
    "authorized_classes": "LOW",
    "passport_number": "HIGH",
    "mrz": "HIGH",
    "salary_income": "MEDIUM",
    "employee_id": "MEDIUM",
    "roll_number": "LOW",
    "marks_cgpa": "LOW",
    "passing_year": "LOW",
    "nationality": "LOW",
    "designation": "LOW",
    "statement_period": "LOW"
}


class PIIRiskModel:
    """
    ML Exposure Risk Model wrapper for production inference.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or MODEL_PATH
        if not os.path.isfile(self.model_path):
            raise FileNotFoundError(
                f"Trained risk model artifact '{self.model_path}' not found. "
                f"Please execute 'python train_risk_model.py' to generate the ML model."
            )

        # Load pipeline once
        self.pipeline = joblib.load(self.model_path)

        # Load metadata if present
        self.metadata = {}
        if os.path.isfile(META_PATH):
            try:
                with open(META_PATH, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            except Exception:
                pass

        # Load centralized sensitivities
        self.sensitivities = {}
        if os.path.isfile(SENSITIVITY_PATH):
            try:
                with open(SENSITIVITY_PATH, "r", encoding="utf-8") as f:
                    self.sensitivities = json.load(f)
            except Exception:
                pass

    def get_pii_sensitivity(self, pii_type: str) -> float:
        """Returns centralized PII sensitivity weight (0.0 to 1.0)."""
        clean_key = pii_type.lower().replace(" ", "_")
        return float(self.sensitivities.get(clean_key, 0.50))

    def predict_risk(
        self,
        pii_type: str,
        document_type: str,
        purpose_necessity: str,
        purpose_domain: str,
        purpose_task: str,
        ocr_confidence: float = 0.90,
        pii_confidence: float = 0.90,
        context_risk: Optional[float] = None,
        exposure_level: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Runs ML inference to predict PII exposure risk class and probability.

        Returns:
            {
                "class": "LOW" | "MEDIUM" | "HIGH",
                "probability": float (0.0 to 1.0),
                "model": "RandomForestClassifier",
                "version": "prototype-1"
            }
        """
        clean_pii = pii_type.lower().replace(" ", "_")
        clean_doc = document_type or "Identity Document"
        clean_nec = purpose_necessity.upper() if purpose_necessity else "UNNECESSARY"
        clean_dom = purpose_domain.lower() if purpose_domain else "general"
        clean_task = purpose_task.lower() if purpose_task else "unknown"

        # Lookup sensitivity and contextual defaults
        sens = self.get_pii_sensitivity(clean_pii)
        c_risk = context_risk if context_risk is not None else DOMAIN_CONTEXT_RISKS.get(clean_dom, 0.50)
        binding = IDENTITY_BINDING.get(clean_pii, "MEDIUM")

        if exposure_level:
            exp_lvl = exposure_level
        elif clean_nec == "UNNECESSARY" and sens >= 0.70:
            exp_lvl = "HIGH"
        elif clean_nec == "CONDITIONAL":
            exp_lvl = "MEDIUM" if sens >= 0.60 else "LOW"
        else:
            exp_lvl = "LOW"

        row = {
            "pii_type": clean_pii,
            "document_type": clean_doc,
            "purpose_necessity": clean_nec,
            "purpose_domain": clean_dom,
            "purpose_task": clean_task,
            "identity_binding_requirement": binding,
            "exposure_level": exp_lvl,
            "pii_sensitivity": float(sens),
            "ocr_confidence": float(ocr_confidence),
            "pii_confidence": float(pii_confidence),
            "context_risk": float(c_risk)
        }

        row_df = pd.DataFrame([row])

        # Predict class and calibrated probabilities
        pred_class = str(self.pipeline.predict(row_df)[0])
        probas = self.pipeline.predict_proba(row_df)[0]
        classes = list(self.pipeline.classes_)

        # Extract probability for the predicted class
        class_idx = classes.index(pred_class) if pred_class in classes else 0
        pred_prob = float(probas[class_idx])

        return {
            "class": pred_class,
            "probability": round(pred_prob, 2),
            "model": self.metadata.get("model_name", "RandomForestClassifier"),
            "version": self.metadata.get("model_version", "prototype-1")
        }

    @staticmethod
    def synthesize_decision(
        necessity: str,
        risk_class: str,
        pii_type: str,
        purpose_task: str = ""
    ) -> Tuple[str, str, str]:
        """
        Synthesizes the final explainable decision and redaction action
        by combining the Policy Layer necessity with ML Exposure Risk.

        Architecture:
          AI (Purpose Understanding)
          ↓
          POLICY (Necessity Determination)
          ↓
          ML (Exposure Risk Estimation)
          ↓
          DECISION ENGINE (Final Protection Action)

        Returns:
            (decision, action, reason)
            - decision: "REQUIRED" | "CONDITIONAL" | "UNNECESSARY"
            - action: "PRESERVED" | "PARTIALLY_REDACTED" | "FULLY_REDACTED"
            - reason: human-readable explainable rationale
        """
        clean_nec = necessity.upper()
        clean_pii = pii_type.lower().replace(" ", "_")

        # Global photo-preservation rule: Never mask, blur, pixelate, or redact photograph
        if clean_pii == "photograph":
            return (
                "REQUIRED",
                "PRESERVED",
                "Visual face photograph is globally preserved to ensure human identity verification."
            )

        if clean_nec == "REQUIRED":
            decision = "REQUIRED"
            action = "PRESERVED"
            reason = f"{pii_type.replace('_', ' ').title()} is strictly necessary to satisfy the verified purpose requirements."

        elif clean_nec == "CONDITIONAL":
            decision = "CONDITIONAL"
            if clean_pii == "aadhaar_number":
                action = "PARTIAL_MASK"
                reason = "Identity verification may require the document, but full Aadhaar exposure is not assumed necessary. Masking first 8 digits."
            elif clean_pii == "mobile_number":
                action = "PARTIAL_MASK"
                reason = "Contact verification permits partial identification. Masking first 6 digits to prevent exposure."
            elif clean_pii == "address":
                action = "PARTIAL_MASK"
                reason = "Regional jurisdiction is verified while specific street and door details are redacted for privacy."
            elif clean_pii in ["date_of_birth", "gender"]:
                if risk_class == "LOW":
                    action = "PRESERVED"
                    reason = f"{pii_type.replace('_', ' ').title()} verified as low exposure risk for conditional requirement."
                else:
                    action = "PARTIAL_MASK"
                    reason = f"{pii_type.replace('_', ' ').title()} exhibits {risk_class} risk; conditional redaction applied."
            elif clean_pii in ["licence_number", "driving_licence_number"]:
                action = "PARTIAL_MASK"
                reason = "Regional RTO prefix and serial suffix preserved; internal serial minimized."
            elif clean_pii in ["passport_number", "passport"]:
                action = "PARTIAL_MASK"
                reason = "Passport number preserved with middle digits masked to protect international identifier."
            elif clean_pii in ["bank_account_number", "account_number"]:
                action = "PARTIAL_MASK"
                reason = "Bank account identifier masked (retaining last 4 digits) to minimize transaction routing exposure."
            elif clean_pii in ["mrz", "machine_readable_zone"]:
                action = "FULL_MASK" if risk_class == "HIGH" else "PARTIAL_MASK"
                reason = "Machine Readable Zone minimized to prevent automated scanning of travel biometric codes."
            elif clean_pii in ["salary_income", "salary", "income", "net_pay", "gross_salary"]:
                action = "PRESERVED" if ("loan" in purpose_task.lower() or "financial" in purpose_task.lower() or "income" in purpose_task.lower() or risk_class == "LOW") else "FULL_MASK"
                reason = "Compensation figures evaluated under loan/financial eligibility requirements."
            elif clean_pii in ["employee_id", "emp_id", "staff_id"]:
                action = "PARTIAL_MASK" if risk_class in ["HIGH", "MEDIUM"] else "PRESERVED"
                reason = "Employee ID serial digits minimized to avoid internal credential enumeration."
            elif clean_pii in ["roll_number", "registration_number"]:
                action = "PRESERVED" if ("admission" in purpose_task.lower() or "exam" in purpose_task.lower() or "qualification" in purpose_task.lower() or risk_class == "LOW") else "PARTIAL_MASK"
                reason = "Academic registration identifier preserved to verify institutional records."
            elif clean_pii in ["marks_cgpa", "marks", "cgpa", "grade", "percentage"]:
                action = "PRESERVED"
                reason = "Educational achievement metrics preserved for academic and eligibility evaluation."
            elif clean_pii in ["passing_year", "nationality", "designation", "statement_period"]:
                action = "PRESERVED"
                reason = f"{pii_type.replace('_', ' ').title()} preserved for contextual verification."
            elif clean_pii in ["validity_date", "validity"]:
                action = "PRESERVED"
                reason = "Validity date preserved to confirm credential remains active."
            elif clean_pii in ["vid", "qr_code"]:
                action = "FULL_MASK"
                reason = f"{pii_type.replace('_', ' ').title()} carries high privacy sensitivity and is not needed for this transaction."
            else:
                action = "PARTIAL_MASK" if risk_class in ["HIGH", "MEDIUM"] else "PRESERVED"
                reason = f"Conditional requirement evaluated under {risk_class} exposure risk."

        else: # UNNECESSARY
            decision = "UNNECESSARY"
            action = "FULL_MASK"
            reason = f"{pii_type.replace('_', ' ').title()} is not recognized as necessary for the stated purpose. Fully masked under zero-trust minimization."

        return decision, action, reason


# Global singleton instance for efficient, single-load inference
_GLOBAL_RISK_MODEL: Optional[PIIRiskModel] = None


def get_risk_model() -> PIIRiskModel:
    """Singleton getter ensuring ML model is loaded only once at application startup."""
    global _GLOBAL_RISK_MODEL
    if _GLOBAL_RISK_MODEL is None:
        _GLOBAL_RISK_MODEL = PIIRiskModel()
    return _GLOBAL_RISK_MODEL
