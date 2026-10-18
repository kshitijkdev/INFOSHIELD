"""
Pytest Suite for InfoShield Phase 4A AI and ML Engines
Validates:
1. College admission intent classification
2. College admission + financial aid compound intent classification
3. Job application intent classification
4. Bank KYC intent classification
5. Government service intent classification
6. Visa application intent classification
7. Unknown/general purpose fallback (<0.15 similarity threshold)
8. Semantic invariance (multiple distinct phrasings mapping to the same intent)
9. ML risk prediction (class and probability calculation)
10. End-to-end /api/protect integration with intelligence payload
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from purpose_ai import classify_purpose, get_purpose_ai
from risk_model import get_risk_model, PIIRiskModel
from purpose_engine import analyze_purpose
from api import app

client = TestClient(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if not os.path.isdir(os.path.join(BASE_DIR, "test_images")):
    BASE_DIR = os.path.dirname(BASE_DIR)
TEST_DOC_PATH = os.path.join(BASE_DIR, "test_images", "test_document.png")


# ==============================================================================
# 1. COLLEGE ADMISSION INTENT
# ==============================================================================

def test_college_admission_intent():
    purpose = "I am submitting my identity document to my university for admission enrollment."
    res = classify_purpose(purpose)
    
    assert res["domain"] == "education"
    assert res["task"] == "college_admission"
    assert res["intent_confidence"] >= 0.50
    assert "ai_model" in res
    assert "reasoning_signals" in res


# ==============================================================================
# 2. COLLEGE ADMISSION + FINANCIAL AID COMPOUND INTENT
# ==============================================================================

def test_college_admission_financial_aid_intent():
    purpose = "I need to submit my Aadhaar to my college for admission and financial aid."
    res = classify_purpose(purpose)
    
    assert res["domain"] == "education"
    assert res["task"] == "college_admission"
    assert res["sub_purpose"] == "financial_aid"
    assert res["intent_confidence"] >= 0.60


# ==============================================================================
# 3. JOB APPLICATION INTENT
# ==============================================================================

def test_job_application_intent():
    purpose = "Submitting identity proof and resume for employment background verification at new company."
    res = classify_purpose(purpose)
    
    assert res["domain"] == "employment"
    assert res["task"] in ["job_application", "job_onboarding", "onboarding", "background_verification"]
    assert res["intent_confidence"] >= 0.50


# ==============================================================================
# 4. BANK KYC INTENT
# ==============================================================================

def test_bank_kyc_intent():
    purpose = "Opening a new savings bank account and completing customer KYC verification."
    res = classify_purpose(purpose)
    
    assert res["domain"] == "banking"
    assert res["task"] in ["bank_kyc", "bank_account_opening"]
    assert res["intent_confidence"] >= 0.50


# ==============================================================================
# 5. GOVERNMENT SERVICE INTENT
# ==============================================================================

def test_government_service_intent():
    purpose = "Applying for government welfare subsidy scheme at district administrative office."
    res = classify_purpose(purpose)
    
    assert res["domain"] == "government"
    assert res["task"] in ["subsidy", "welfare_subsidy", "government_service", "ration_card"]
    assert res["intent_confidence"] >= 0.50


# ==============================================================================
# 6. VISA APPLICATION INTENT
# ==============================================================================

def test_visa_application_intent():
    purpose = "Applying for travel visa and passport verification at embassy consular section."
    res = classify_purpose(purpose)
    
    assert res["domain"] == "travel"
    assert res["task"] in ["visa_application", "flight_booking"]
    assert res["intent_confidence"] >= 0.50


# ==============================================================================
# 7. UNKNOWN / GENERAL PURPOSE FALLBACK
# ==============================================================================

def test_unknown_general_purpose_fallback():
    # Irrelevant sentence with no semantic overlap with purpose database
    purpose = "The quick brown fox jumps over the lazy dog in the sunny afternoon."
    res = classify_purpose(purpose)
    
    assert res["domain"] == "general"
    assert res["task"] == "unknown"
    assert res["intent_confidence"] <= 0.40


# ==============================================================================
# 8. SEMANTIC INVARIANCE
# ==============================================================================

def test_semantic_invariance():
    # Multiple distinct formulations of college admission
    phrasings = [
        "Submitting academic paperwork for university degree enrollment",
        "Registering for admission to higher education institute",
        "Document upload for college seat allotment and enrollment"
    ]
    for text in phrasings:
        res = classify_purpose(text)
        assert res["domain"] == "education", f"Failed domain for phrasing: '{text}'"
        assert res["task"] == "college_admission", f"Failed task for phrasing: '{text}'"
        assert res["intent_confidence"] >= 0.50


# ==============================================================================
# 9. ML RISK PREDICTION
# ==============================================================================

def test_ml_risk_prediction():
    model = get_risk_model()
    
    # 1. High risk scenario: Aadhaar number marked unnecessary in banking context
    high_pred = model.predict_risk(
        pii_type="aadhaar_number",
        document_type="Aadhaar Card",
        purpose_necessity="UNNECESSARY",
        purpose_domain="banking",
        purpose_task="bank_account_opening",
        ocr_confidence=0.95,
        pii_confidence=0.98
    )
    assert high_pred["class"] == "HIGH"
    assert high_pred["probability"] >= 0.50
    assert "model" in high_pred

    # 2. Low risk scenario: Person name required in education context
    low_pred = model.predict_risk(
        pii_type="person_name",
        document_type="Aadhaar Card",
        purpose_necessity="REQUIRED",
        purpose_domain="education",
        purpose_task="college_admission",
        ocr_confidence=0.92,
        pii_confidence=0.95
    )
    assert low_pred["class"] == "LOW"
    assert low_pred["probability"] >= 0.50


# ==============================================================================
# 10. POST /api/protect END-TO-END INTEGRATION WITH INTELLIGENCE BLOCK
# ==============================================================================

def test_api_protect_intelligence_block():
    assert os.path.isfile(TEST_DOC_PATH), f"Test document not found: {TEST_DOC_PATH}"
    
    purpose_text = (
        "I need to submit my Aadhaar to my college for admission and financial aid. "
        "The college needs it to verify my identity and process my financial assistance application."
    )
    
    from conftest import get_test_auth_headers

    with open(TEST_DOC_PATH, "rb") as f:
        response = client.post(
            "/api/protect",
            files={"file": ("test_document.png", f, "image/png")},
            data={"purpose": purpose_text},
            headers=get_test_auth_headers()
        )
    
    assert response.status_code == 200, f"Protect request failed: {response.text}"
    data = response.json()
    
    # Verify top-level structure
    assert data["success"] is True
    assert "intelligence" in data
    
    # Verify AI Purpose Intelligence block
    intel = data["intelligence"]
    assert "purpose_ai" in intel
    assert intel["purpose_ai"]["domain"] == "education"
    assert intel["purpose_ai"]["task"] == "college_admission"
    assert intel["purpose_ai"]["sub_purpose"] == "financial_aid"
    assert intel["purpose_ai"]["confidence"] >= 0.50
    
    # Verify ML Risk Model block
    assert "risk_model" in intel
    assert intel["risk_model"]["model"] == "RandomForestClassifier"
    
    # Verify requirements with ML risk and bboxes
    assert len(data["requirements"]) > 0
    for req in data["requirements"]:
        assert "decision" in req
        assert "action" in req
        assert "risk" in req
        assert req["risk"]["class"] in ["LOW", "MEDIUM", "HIGH"]
        assert 0.0 <= req["risk"]["probability"] <= 1.0
        assert "bbox" in req
        
    # Verify output file exists
    protected_filename = data["document"]["protected_filename"]
    output_dir = os.path.join(BASE_DIR, "outputs")
    output_path = os.path.join(output_dir, protected_filename)
    assert os.path.isfile(output_path), f"Protected image not found at {output_path}"
    assert os.path.getsize(output_path) > 1000
