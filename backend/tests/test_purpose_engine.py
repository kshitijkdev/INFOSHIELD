"""
Pytest Suite for InfoShield Purpose Analysis Engine
Phase 2 Validation:
1. Scenario 1: Aadhaar + college admission + financial aid
2. Scenario 2: Aadhaar + bank KYC
3. Scenario 3: PAN + job onboarding
4. Scenario 4: Passport + visa application
5. Scenario 5: Unknown/general purpose
6. API endpoint integration: POST /api/analyze-purpose
7. End-to-End Pipeline test: POST /api/scan -> POST /api/analyze-purpose
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

from purpose_engine import (
    classify_domain,
    classify_task,
    classify_submission_context,
    classify_sub_purpose,
    interpret_purpose,
    analyze_purpose,
)
from api import app

client = TestClient(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if not os.path.isdir(os.path.join(BASE_DIR, "test_images")):
    BASE_DIR = os.path.dirname(BASE_DIR)
TEST_DOC_PATH = os.path.join(BASE_DIR, "test_images", "test_document.png")


# ==============================================================================
# 1. SCENARIO 1: AADHAAR + COLLEGE ADMISSION + FINANCIAL AID
# ==============================================================================

def test_scenario_1_college_admission_financial_aid():
    purpose = "I need to submit my Aadhaar to my college for admission and financial aid."
    pii = [
        {"type": "person_name", "value": "Tapan Sarma"},
        {"type": "date_of_birth", "value": "11/09/2002"},
        {"type": "gender", "value": "MALE"},
        {"type": "mobile_number", "value": "9954018168"},
        {"type": "aadhaar_number", "value": "8141 5978 8449"},
        {"type": "vid", "value": "9186083758430970"},
        {"type": "address", "value": "C/O: Kabindra Nath Sarma..."},
    ]

    result = analyze_purpose("Aadhaar Card", purpose, pii)

    assert result["success"] is True

    # Purpose interpretation assertions
    pa = result["purpose_analysis"]
    assert pa["domain"] == "education"
    assert pa["task"] == "college admission"
    assert pa["sub_purpose"] == "financial aid"
    assert pa["submission_context"] == "college"

    # Map decisions by PII type
    decisions = {r["type"]: r for r in result["requirements"]}

    assert decisions["person_name"]["decision"] == "REQUIRED"
    assert "identify the applicant" in decisions["person_name"]["reason"]

    assert decisions["date_of_birth"]["decision"] == "CONDITIONAL"
    assert "eligibility" in decisions["date_of_birth"]["reason"].lower()

    assert decisions["gender"]["decision"] == "CONDITIONAL"

    assert decisions["mobile_number"]["decision"] == "UNNECESSARY"
    assert "not required" in decisions["mobile_number"]["reason"].lower()

    assert decisions["aadhaar_number"]["decision"] == "CONDITIONAL"
    assert "not be assumed necessary" in decisions["aadhaar_number"]["reason"]

    assert decisions["vid"]["decision"] == "UNNECESSARY"

    assert decisions["address"]["decision"] == "CONDITIONAL"

    # Summary verification
    summary = result["summary"]
    assert summary["required"] == 1
    assert summary["conditional"] == 4
    assert summary["unnecessary"] == 2


# ==============================================================================
# 2. SCENARIO 2: AADHAAR + BANK KYC
# ==============================================================================

def test_scenario_2_bank_kyc():
    purpose = "Submitting Aadhaar to HDFC Bank for KYC verification and account reactivation."
    pii = [
        {"type": "person_name", "value": "Aarav Sharma"},
        {"type": "date_of_birth", "value": "14/05/1998"},
        {"type": "gender", "value": "MALE"},
        {"type": "mobile_number", "value": "9876543210"},
        {"type": "aadhaar_number", "value": "9823 4567 9012"},
        {"type": "vid", "value": "9123456789012345"},
        {"type": "address", "value": "Flat 402, Green Meadows, Andheri East, Mumbai - 400069"},
    ]

    result = analyze_purpose("Aadhaar Card", purpose, pii)

    pa = result["purpose_analysis"]
    assert pa["domain"] == "banking"
    assert pa["task"] == "KYC"
    assert pa["submission_context"] == "bank"

    decisions = {r["type"]: r["decision"] for r in result["requirements"]}

    # Under Banking KYC: Name, DOB, and Address are REQUIRED (statutory KYC compliance)
    assert decisions["person_name"] == "REQUIRED"
    assert decisions["date_of_birth"] == "REQUIRED"
    assert decisions["address"] == "REQUIRED"
    assert decisions["aadhaar_number"] == "CONDITIONAL"  # Masked digits required per RBI
    assert decisions["mobile_number"] == "CONDITIONAL"
    assert decisions["vid"] == "CONDITIONAL"


# ==============================================================================
# 3. SCENARIO 3: PAN + JOB ONBOARDING
# ==============================================================================

def test_scenario_3_pan_job_onboarding():
    purpose = "Submitting PAN card to employer for job onboarding and payroll tax deduction."
    pii = [
        {"type": "person_name", "value": "Rohan Verma"},
        {"type": "date_of_birth", "value": "22/11/1995"},
        {"type": "pan_number", "value": "ABCDE1234F"},
        {"type": "bank_account_number", "value": "0100492817291"},
        {"type": "ifsc_code", "value": "HDFC0001234"},
        {"type": "aadhaar_number", "value": "9823 4567 9012"},
        {"type": "mobile_number", "value": "9876543210"},
    ]

    result = analyze_purpose("PAN Card", purpose, pii)

    pa = result["purpose_analysis"]
    assert pa["domain"] == "employment"
    assert pa["task"] == "job onboarding"
    assert pa["submission_context"] == "employer"

    decisions = {r["type"]: r["decision"] for r in result["requirements"]}

    # For job onboarding: Name, DOB, PAN, Bank Account, and IFSC are REQUIRED for payroll/TDS
    assert decisions["person_name"] == "REQUIRED"
    assert decisions["date_of_birth"] == "REQUIRED"
    assert decisions["pan_number"] == "REQUIRED"
    assert decisions["bank_account_number"] == "REQUIRED"
    assert decisions["ifsc_code"] == "REQUIRED"
    assert decisions["aadhaar_number"] == "CONDITIONAL"
    assert decisions["mobile_number"] == "UNNECESSARY"


# ==============================================================================
# 4. SCENARIO 4: PASSPORT + VISA APPLICATION
# ==============================================================================

def test_scenario_4_passport_visa_application():
    purpose = "Applying for a tourist visa at the German Embassy for foreign travel."
    pii = [
        {"type": "person_name", "value": "Priya Patel"},
        {"type": "date_of_birth", "value": "05/03/1992"},
        {"type": "gender", "value": "FEMALE"},
        {"type": "address", "value": "12 Park Street, Kolkata - 700016"},
        {"type": "aadhaar_number", "value": "9823 4567 9012"},
        {"type": "vid", "value": "9123456789012345"},
    ]

    result = analyze_purpose("Passport", purpose, pii)

    pa = result["purpose_analysis"]
    assert pa["domain"] == "travel"
    assert pa["task"] == "visa application"
    assert pa["submission_context"] == "embassy"

    decisions = {r["type"]: r["decision"] for r in result["requirements"]}

    # Consular Visa Application: Name, DOB, Gender, and Address are REQUIRED per ICAO standards
    assert decisions["person_name"] == "REQUIRED"
    assert decisions["date_of_birth"] == "REQUIRED"
    assert decisions["gender"] == "REQUIRED"
    assert decisions["address"] == "REQUIRED"
    # Domestic identity numbers are UNNECESSARY for sovereign foreign visas
    assert decisions["aadhaar_number"] == "UNNECESSARY"
    assert decisions["vid"] == "UNNECESSARY"


# ==============================================================================
# 5. SCENARIO 5: UNKNOWN / GENERAL PURPOSE (ZERO-TRUST FALLBACK)
# ==============================================================================

def test_scenario_5_general_purpose():
    purpose = "I am uploading this document for general casual storage."
    pii = [
        {"type": "person_name", "value": "Tapan Sarma"},
        {"type": "date_of_birth", "value": "11/09/2002"},
        {"type": "gender", "value": "MALE"},
        {"type": "mobile_number", "value": "9954018168"},
        {"type": "aadhaar_number", "value": "8141 5978 8449"},
        {"type": "vid", "value": "9186083758430970"},
        {"type": "address", "value": "Guwahati, Assam - 781001"},
    ]

    result = analyze_purpose("Identity Document", purpose, pii)

    pa = result["purpose_analysis"]
    assert pa["domain"] == "general"
    assert pa["task"] == "general identity verification"
    assert pa["submission_context"] == "general verifier"

    decisions = {r["type"]: r["decision"] for r in result["requirements"]}

    # Zero-Trust Minimization: Only person_name is retained; all high-risk identifiers are shielded
    assert decisions["person_name"] == "REQUIRED"
    assert decisions["gender"] == "UNNECESSARY"
    assert decisions["aadhaar_number"] == "UNNECESSARY"
    assert decisions["vid"] == "UNNECESSARY"
    assert decisions["mobile_number"] == "UNNECESSARY"
    assert decisions["address"] == "UNNECESSARY"


# ==============================================================================
# 6. API INTEGRATION TEST: POST /api/analyze-purpose
# ==============================================================================

def test_api_analyze_purpose_endpoint():
    payload = {
        "document_type": "Aadhaar Card",
        "purpose": "I need to submit my Aadhaar to my college for admission and financial aid.",
        "pii": [
            {"type": "person_name", "value": "Tapan Sarma"},
            {"type": "date_of_birth", "value": "11/09/2002"},
            {"type": "gender", "value": "MALE"},
            {"type": "mobile_number", "value": "9954018168"},
            {"type": "aadhaar_number", "value": "8141 5978 8449"},
            {"type": "vid", "value": "9186083758430970"},
            {"type": "address", "value": "C/O: Kabindra Nath Sarma..."}
        ]
    }

    response = client.post("/api/analyze-purpose", json=payload)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

    data = response.json()
    assert data["success"] is True
    assert "purpose_analysis" in data
    assert "requirements" in data
    assert "summary" in data

    pa = data["purpose_analysis"]
    assert pa["domain"] == "education"
    assert pa["task"] == "college admission"
    assert pa["sub_purpose"] == "financial aid"
    assert pa["submission_context"] == "college"

    reqs = {r["type"]: r["decision"] for r in data["requirements"]}
    assert reqs["person_name"] == "REQUIRED"
    assert reqs["date_of_birth"] == "CONDITIONAL"
    assert reqs["mobile_number"] == "UNNECESSARY"
    assert reqs["aadhaar_number"] == "CONDITIONAL"
    assert reqs["vid"] == "UNNECESSARY"

    assert data["summary"]["required"] == 1
    assert data["summary"]["conditional"] == 4
    assert data["summary"]["unnecessary"] == 2


def test_api_analyze_purpose_empty_purpose_400():
    payload = {
        "document_type": "Aadhaar Card",
        "purpose": "",
        "pii": [{"type": "person_name", "value": "Test"}]
    }
    response = client.post("/api/analyze-purpose", json=payload)
    assert response.status_code == 400


# ==============================================================================
# 7. REAL END-TO-END PIPELINE: OCR -> PII -> PURPOSE -> REQUIREMENTS
# ==============================================================================

def test_full_pipeline_ocr_to_purpose():
    """
    Executes the genuine end-to-end InfoShield pipeline:
      Step 1: POST /api/scan with real document image -> Real OCR + Extracted PII
      Step 2: POST /api/analyze-purpose with extracted PII + user purpose -> Data Minimization Requirements
    """
    assert os.path.exists(TEST_DOC_PATH), f"Test image not found at {TEST_DOC_PATH}"

    # Step 1: Real pixel OCR scan
    with open(TEST_DOC_PATH, "rb") as f:
        scan_resp = client.post(
            "/api/scan",
            files={"file": ("test_document.png", f, "image/png")}
        )

    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["success"] is True
    extracted_pii = scan_data["pii"]
    assert len(extracted_pii) >= 6, "Expected at least 6 PII fields from test document"

    # Verify real extracted values exist
    pii_types = [p["type"] for p in extracted_pii]
    assert "person_name" in pii_types
    assert "aadhaar_number" in pii_types

    # Step 2: Feed real extracted PII directly into Purpose Analysis Engine
    purpose_payload = {
        "document_type": scan_data["document"]["type"],
        "purpose": "I need to submit my Aadhaar to my college for admission and financial aid.",
        "pii": extracted_pii
    }

    purpose_resp = client.post("/api/analyze-purpose", json=purpose_payload)
    assert purpose_resp.status_code == 200
    purpose_data = purpose_resp.json()

    assert purpose_data["success"] is True
    assert purpose_data["purpose_analysis"]["domain"] == "education"
    assert purpose_data["purpose_analysis"]["task"] == "college admission"

    # Check requirement decisions generated for real extracted items
    req_map = {r["type"]: r for r in purpose_data["requirements"]}
    assert req_map["person_name"]["decision"] == "REQUIRED"
    assert req_map["aadhaar_number"]["decision"] == "CONDITIONAL"
    assert req_map["mobile_number"]["decision"] == "UNNECESSARY"
    assert req_map["vid"]["decision"] == "UNNECESSARY"

    print("\n✓ Full Pipeline (OCR -> PII -> Purpose -> Requirements) Verified Successfully!")
