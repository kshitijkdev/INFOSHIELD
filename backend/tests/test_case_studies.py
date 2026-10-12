"""
InfoShield AI - Academic Prototype Case Studies Test Suite
Covers 12+ real-world purpose-based minimization scenarios across:
1. Education (admission, financial aid, student ID, marksheet verification)
2. Banking (KYC, account opening, education loan, income verification)
3. Identity & Travel (DL identity, DL address, Passport visa)
4. Employment (HR verification, salary verification)
5. Zero-Trust Fallback (Unknown document, vague purpose, review_required flag)
6. Physical Pixel Redaction Integrity & Document Immutability
"""

import os
import shutil
import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient

from api import app, classify_document_type, detect_document_type
from purpose_engine import analyze_purpose, interpret_purpose
from redaction_engine import RedactionEngine
from pii_detector import PIIDetector

client = TestClient(app)

TEST_IMAGES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_images")


# ==============================================================================
# 1. EDUCATION DOMAIN CASE STUDIES
# ==============================================================================

def test_case_study_1_college_admission():
    """
    Case Study 1: College Admission
    Recipient: College Admissions Office
    Purpose: College admission verification
    Expectation: Name & marks/CGPA required; address/Aadhaar conditional or unnecessary; QR unnecessary.
    """
    pii = [
        {"type": "person_name", "value": "Aarav Sharma", "confidence": 0.95},
        {"type": "marks_cgpa", "value": "9.4 CGPA", "confidence": 0.95},
        {"type": "passing_year", "value": "2024", "confidence": 0.95},
        {"type": "roll_number", "value": "6624912", "confidence": 0.90},
        {"type": "aadhaar_number", "value": "9823 4567 9012", "confidence": 0.90},
        {"type": "address", "value": "Flat 402, Mumbai", "confidence": 0.85},
        {"type": "qr_code", "value": "SECURE_QR_DATA", "confidence": 0.95},
    ]
    res = analyze_purpose("Marksheet", "College admission at Mumbai University", pii)
    assert res["success"] is True
    assert res["domain"] == "education"
    assert "admission" in res["task"].lower() or "education" in res["domain"].lower()

    req_map = {r["type"]: r["decision"] for r in res["requirements"]}
    assert req_map["person_name"] == "REQUIRED"
    assert req_map["marks_cgpa"] == "REQUIRED"
    assert req_map["passing_year"] == "REQUIRED"
    assert req_map["qr_code"] == "UNNECESSARY"
    assert req_map["address"] in ["CONDITIONAL", "UNNECESSARY"]


def test_case_study_2_financial_aid_scholarship():
    """
    Case Study 2: Financial Aid / Scholarship
    Recipient: University Financial Aid Cell
    Purpose: Financial aid and scholarship fee waiver
    Expectation: Name & marks required; bank details conditional/required for disbursement; QR unnecessary.
    """
    pii = [
        {"type": "person_name", "value": "Aarav Sharma", "confidence": 0.95},
        {"type": "marks_cgpa", "value": "9.4 CGPA", "confidence": 0.95},
        {"type": "bank_account_number", "value": "501004928192", "confidence": 0.92},
        {"type": "ifsc_code", "value": "HDFC0000128", "confidence": 0.90},
        {"type": "address", "value": "Mumbai, Maharashtra", "confidence": 0.85},
        {"type": "qr_code", "value": "QR_PAYLOAD", "confidence": 0.95},
    ]
    res = analyze_purpose("Marksheet", "Application for financial aid and scholarship grant", pii)
    assert res["success"] is True
    req_map = {r["type"]: r["decision"] for r in res["requirements"]}
    assert req_map["person_name"] == "REQUIRED"
    assert req_map["marks_cgpa"] == "REQUIRED"
    assert req_map["bank_account_number"] in ["REQUIRED", "CONDITIONAL"]
    assert req_map["ifsc_code"] in ["REQUIRED", "CONDITIONAL"]
    assert req_map["qr_code"] == "UNNECESSARY"


def test_case_study_3_student_verification():
    """
    Case Study 3: Student Campus Verification
    Recipient: Campus Security / Registrar
    Purpose: Student enrollment identity verification
    Expectation: Name & photo required; roll number required; home address minimized.
    """
    pii = [
        {"type": "person_name", "value": "Aarav Sharma", "confidence": 0.95},
        {"type": "photograph", "value": "[FACE]", "confidence": 0.98},
        {"type": "roll_number", "value": "2024-CS-042", "confidence": 0.95},
        {"type": "address", "value": "Flat 402, Mumbai", "confidence": 0.85},
        {"type": "aadhaar_number", "value": "9823 4567 9012", "confidence": 0.90},
    ]
    res = analyze_purpose("College ID", "Student verification for library and lab access", pii)
    assert res["success"] is True
    req_map = {r["type"]: r["decision"] for r in res["requirements"]}
    assert req_map["person_name"] == "REQUIRED"
    assert req_map["photograph"] == "REQUIRED"
    assert req_map["roll_number"] == "REQUIRED"
    assert req_map["address"] == "UNNECESSARY"


def test_case_study_4_marksheet_score_verification():
    """
    Case Study 4: Academic Marksheet Verification
    Recipient: Academic Board / Higher Studies Verifier
    Purpose: Marksheet verification for qualifying examination
    Expectation: Candidate name, roll number, marks/CGPA, passing year required; address & UID unnecessary.
    """
    pii = [
        {"type": "person_name", "value": "Aarav Sharma", "confidence": 0.95},
        {"type": "roll_number", "value": "6624912", "confidence": 0.95},
        {"type": "marks_cgpa", "value": "472 / 500 (94.4%)", "confidence": 0.95},
        {"type": "passing_year", "value": "2024", "confidence": 0.92},
        {"type": "address", "value": "Mumbai 400069", "confidence": 0.80},
        {"type": "aadhaar_number", "value": "9823 4567 9012", "confidence": 0.90},
    ]
    res = analyze_purpose("Marksheet", "Marksheet verification for post-graduate admission", pii)
    assert res["success"] is True
    req_map = {r["type"]: r["decision"] for r in res["requirements"]}
    assert req_map["person_name"] == "REQUIRED"
    assert req_map["roll_number"] == "REQUIRED"
    assert req_map["marks_cgpa"] == "REQUIRED"
    assert req_map["passing_year"] == "REQUIRED"
    assert req_map["address"] == "UNNECESSARY"
    assert req_map["aadhaar_number"] == "UNNECESSARY"


# ==============================================================================
# 2. BANKING DOMAIN CASE STUDIES
# ==============================================================================

def test_case_study_5_banking_kyc():
    """
    Case Study 5: Banking KYC
    Recipient: Bank Compliance Department
    Purpose: Bank KYC compliance verification
    Expectation: Name, DOB, address, PAN required; Aadhaar CONDITIONAL (masked first 8 digits).
    """
    pii = [
        {"type": "person_name", "value": "Aarav Sharma", "confidence": 0.95},
        {"type": "date_of_birth", "value": "15/08/2000", "confidence": 0.95},
        {"type": "address", "value": "Flat 402, Mumbai", "confidence": 0.90},
        {"type": "pan_number", "value": "ABCDE1234F", "confidence": 0.95},
        {"type": "aadhaar_number", "value": "9823 4567 9012", "confidence": 0.95},
        {"type": "mobile_number", "value": "9876543210", "confidence": 0.90},
    ]
    res = analyze_purpose("Aadhaar Card", "Bank account KYC verification", pii)
    assert res["success"] is True
    assert res["domain"] == "banking"
    req_map = {r["type"]: r["decision"] for r in res["requirements"]}
    assert req_map["person_name"] == "REQUIRED"
    assert req_map["date_of_birth"] == "REQUIRED"
    assert req_map["address"] == "REQUIRED"
    assert req_map["pan_number"] == "REQUIRED"
    assert req_map["aadhaar_number"] == "CONDITIONAL"


def test_case_study_6_banking_account_opening():
    """
    Case Study 6: Bank Account Opening
    Recipient: Retail Bank Branch
    Purpose: Open new savings account
    Expectation: Name, DOB, PAN, photo, address required; Aadhaar conditional.
    """
    pii = [
        {"type": "person_name", "value": "Aarav Sharma", "confidence": 0.95},
        {"type": "date_of_birth", "value": "15/08/2000", "confidence": 0.95},
        {"type": "pan_number", "value": "ABCDE1234F", "confidence": 0.95},
        {"type": "address", "value": "Flat 402, Mumbai", "confidence": 0.90},
        {"type": "photograph", "value": "[FACE]", "confidence": 0.98},
        {"type": "aadhaar_number", "value": "9823 4567 9012", "confidence": 0.90},
    ]
    res = analyze_purpose("Aadhaar Card", "Open a new bank savings account", pii)
    assert res["success"] is True
    req_map = {r["type"]: r["decision"] for r in res["requirements"]}
    assert req_map["person_name"] == "REQUIRED"
    assert req_map["pan_number"] == "REQUIRED"
    assert req_map["address"] == "REQUIRED"
    assert req_map["photograph"] == "REQUIRED"
    assert req_map["aadhaar_number"] == "CONDITIONAL"


def test_case_study_7_banking_education_loan():
    """
    Case Study 7: Education Loan
    Recipient: Bank Loan Underwriting Department
    Purpose: Education loan application
    Expectation: Name, Bank account, IFSC, salary/income, statement period, marks required; QR unnecessary.
    """
    pii = [
        {"type": "person_name", "value": "Aarav Sharma", "confidence": 0.95},
        {"type": "bank_account_number", "value": "501004928192", "confidence": 0.95},
        {"type": "ifsc_code", "value": "HDFC0000128", "confidence": 0.95},
        {"type": "salary_income", "value": "85000", "confidence": 0.92},
        {"type": "statement_period", "value": "JAN 2026 - JUN 2026", "confidence": 0.90},
        {"type": "marks_cgpa", "value": "9.4 CGPA", "confidence": 0.95},
        {"type": "pan_number", "value": "ABCDE1234F", "confidence": 0.95},
        {"type": "qr_code", "value": "QR_PAYLOAD", "confidence": 0.95},
    ]
    res = analyze_purpose("Bank Statement", "Education loan application for university tuition fees", pii)
    assert res["success"] is True
    req_map = {r["type"]: r["decision"] for r in res["requirements"]}
    assert req_map["person_name"] == "REQUIRED"
    assert req_map["bank_account_number"] == "REQUIRED"
    assert req_map["ifsc_code"] == "REQUIRED"
    assert req_map["salary_income"] == "REQUIRED"
    assert req_map["statement_period"] == "REQUIRED"
    assert req_map["marks_cgpa"] == "REQUIRED"
    assert req_map["qr_code"] == "UNNECESSARY"


def test_case_study_8_banking_income_verification():
    """
    Case Study 8: Income Verification
    Recipient: Financial Verification Agency
    Purpose: Income verification from bank statement
    Expectation: Salary/income & statement period required; bank account CONDITIONAL (masked); DOB unnecessary.
    """
    pii = [
        {"type": "person_name", "value": "Aarav Sharma", "confidence": 0.95},
        {"type": "salary_income", "value": "Closing Balance: 245000", "confidence": 0.95},
        {"type": "statement_period", "value": "01/01/2026 to 31/03/2026", "confidence": 0.92},
        {"type": "bank_account_number", "value": "50100492819234", "confidence": 0.90},
        {"type": "date_of_birth", "value": "15/08/2000", "confidence": 0.85},
        {"type": "qr_code", "value": "QR_DATA", "confidence": 0.95},
    ]
    res = analyze_purpose("Bank Statement", "Income verification for financial appraisal", pii)
    assert res["success"] is True
    req_map = {r["type"]: r["decision"] for r in res["requirements"]}
    assert req_map["person_name"] == "REQUIRED"
    assert req_map["salary_income"] == "REQUIRED"
    assert req_map["statement_period"] == "REQUIRED"
    assert req_map["bank_account_number"] == "CONDITIONAL"
    assert req_map["date_of_birth"] == "UNNECESSARY"
    assert req_map["qr_code"] == "UNNECESSARY"


# ==============================================================================
# 3. IDENTITY & TRAVEL DOMAIN CASE STUDIES
# ==============================================================================

def test_case_study_9_dl_identity_verification():
    """
    Case Study 9: DL Identity Verification
    Recipient: Security Desk / Visitor Registry
    Purpose: General identity verification
    Expectation: Photo & Name REQUIRED; address UNNECESSARY; licence number CONDITIONAL.
    """
    pii = [
        {"type": "photograph", "value": "[FACE]", "confidence": 0.98},
        {"type": "person_name", "value": "Aarav Sharma", "confidence": 0.95},
        {"type": "licence_number", "value": "MH02 20180012345", "confidence": 0.90},
        {"type": "address", "value": "Flat 402, Mumbai", "confidence": 0.90},
        {"type": "blood_group", "value": "O+", "confidence": 0.85},
    ]
    res = analyze_purpose("Driving Licence", "Identity verification at visitor security gate", pii)
    assert res["success"] is True
    req_map = {r["type"]: r["decision"] for r in res["requirements"]}
    assert req_map["photograph"] == "REQUIRED"
    assert req_map["person_name"] == "REQUIRED"
    assert req_map["address"] == "UNNECESSARY"
    assert req_map["blood_group"] == "UNNECESSARY"
    assert req_map["licence_number"] == "CONDITIONAL"


def test_case_study_10_dl_address_verification():
    """
    Case Study 10: DL Address Verification
    Recipient: Broadband / Telecom Provider
    Purpose: Address verification for utility setup
    Expectation: Address, Name, and Photograph REQUIRED; licence number CONDITIONAL; blood group UNNECESSARY.
    """
    pii = [
        {"type": "address", "value": "Flat 402, Mumbai 400069", "confidence": 0.95},
        {"type": "person_name", "value": "Aarav Sharma", "confidence": 0.95},
        {"type": "photograph", "value": "[FACE]", "confidence": 0.98},
        {"type": "licence_number", "value": "MH02 20180012345", "confidence": 0.90},
        {"type": "blood_group", "value": "O+", "confidence": 0.85},
    ]
    res = analyze_purpose("Driving Licence", "Address verification for home broadband connection", pii)
    assert res["success"] is True
    req_map = {r["type"]: r["decision"] for r in res["requirements"]}
    assert req_map["address"] == "REQUIRED"
    assert req_map["person_name"] == "REQUIRED"
    assert req_map["photograph"] == "REQUIRED"
    assert req_map["blood_group"] == "UNNECESSARY"
    assert req_map["licence_number"] == "CONDITIONAL"


def test_case_study_11_passport_visa_application():
    """
    Case Study 11: Passport Visa Application
    Recipient: Consular Embassy / Border Control
    Purpose: Tourist visa application
    Expectation: Passport number, nationality, MRZ, photo, validity date REQUIRED; domestic Aadhaar unnecessary.
    """
    pii = [
        {"type": "person_name", "value": "Aarav Sharma", "confidence": 0.98},
        {"type": "passport_number", "value": "Z8923412", "confidence": 0.98},
        {"type": "nationality", "value": "INDIAN", "confidence": 0.95},
        {"type": "mrz", "value": "P<INDSHARMA<<AARAV<<<<<<<<<<<<<<<<<<<\nZ8923412<2IND0008154M3001018<<<<<<<<<<<0", "confidence": 0.98},
        {"type": "photograph", "value": "[FACE]", "confidence": 0.98},
        {"type": "validity_date", "value": "15/01/2034", "confidence": 0.95},
        {"type": "aadhaar_number", "value": "9823 4567 9012", "confidence": 0.90},
        {"type": "qr_code", "value": "DOMESTIC_QR", "confidence": 0.95},
    ]
    res = analyze_purpose("Passport", "Tourist visa application for international travel", pii)
    assert res["success"] is True
    assert res["domain"] == "travel"
    req_map = {r["type"]: r["decision"] for r in res["requirements"]}
    assert req_map["person_name"] == "REQUIRED"
    assert req_map["passport_number"] == "REQUIRED"
    assert req_map["nationality"] == "REQUIRED"
    assert req_map["mrz"] == "REQUIRED"
    assert req_map["photograph"] == "REQUIRED"
    assert req_map["validity_date"] == "REQUIRED"
    assert req_map["aadhaar_number"] == "UNNECESSARY"
    assert req_map["qr_code"] == "UNNECESSARY"


# ==============================================================================
# 4. EMPLOYMENT DOMAIN CASE STUDIES
# ==============================================================================

def test_case_study_12_hr_verification():
    """
    Case Study 12: HR Verification
    Recipient: Corporate HR Operations
    Purpose: HR employee identity verification
    Expectation: Employee ID, Name, Designation, Photo REQUIRED; Salary & bank details UNNECESSARY.
    """
    pii = [
        {"type": "person_name", "value": "Aarav Sharma", "confidence": 0.98},
        {"type": "employee_id", "value": "EMP-88219", "confidence": 0.95},
        {"type": "designation", "value": "Lead Security Engineer", "confidence": 0.95},
        {"type": "photograph", "value": "[FACE]", "confidence": 0.98},
        {"type": "salary_income", "value": "Net Pay: 125000", "confidence": 0.92},
        {"type": "bank_account_number", "value": "501004928192", "confidence": 0.90},
        {"type": "qr_code", "value": "QR_PAYLOAD", "confidence": 0.95},
    ]
    res = analyze_purpose("Employment Document", "HR verification for employee staff directory", pii)
    assert res["success"] is True
    req_map = {r["type"]: r["decision"] for r in res["requirements"]}
    assert req_map["person_name"] == "REQUIRED"
    assert req_map["employee_id"] == "REQUIRED"
    assert req_map["designation"] == "REQUIRED"
    assert req_map["photograph"] == "REQUIRED"
    assert req_map["salary_income"] == "UNNECESSARY"
    assert req_map["bank_account_number"] == "UNNECESSARY"
    assert req_map["qr_code"] == "UNNECESSARY"


def test_case_study_13_salary_income_verification():
    """
    Case Study 13: Employment Payslip Income Verification
    Recipient: Underwriter / Landlord
    Purpose: Employment income verification from salary slip
    Expectation: Salary, Employee ID, Statement period REQUIRED; DOB & address UNNECESSARY.
    """
    pii = [
        {"type": "person_name", "value": "Aarav Sharma", "confidence": 0.98},
        {"type": "employee_id", "value": "EMP-88219", "confidence": 0.95},
        {"type": "salary_income", "value": "Net Salary: 125000", "confidence": 0.98},
        {"type": "statement_period", "value": "Pay Period: March 2026", "confidence": 0.95},
        {"type": "date_of_birth", "value": "15/08/2000", "confidence": 0.85},
        {"type": "address", "value": "Flat 402, Mumbai", "confidence": 0.85},
        {"type": "aadhaar_number", "value": "9823 4567 9012", "confidence": 0.90},
    ]
    res = analyze_purpose("Employment Document", "Proof of income verification from salary slip", pii)
    assert res["success"] is True
    req_map = {r["type"]: r["decision"] for r in res["requirements"]}
    assert req_map["person_name"] == "REQUIRED"
    assert req_map["salary_income"] == "REQUIRED"
    assert req_map["employee_id"] == "REQUIRED"
    assert req_map["statement_period"] == "REQUIRED"
    assert req_map["date_of_birth"] == "UNNECESSARY"
    assert req_map["address"] == "UNNECESSARY"
    assert req_map["aadhaar_number"] == "UNNECESSARY"


# ==============================================================================
# 5. ZERO-TRUST FALLBACK & REVIEW REQUIRED
# ==============================================================================

def test_case_study_14_unknown_document_vague_purpose():
    """
    Case Study 14: Unknown Document & Vague Purpose
    Expectation: Document classified as 'Unknown Document' with low confidence (< 0.60),
    warnings generated, review_required flag is True, zero-trust default UNNECESSARY applied.
    """
    doc_type, conf, warnings = classify_document_type("Some random unrelated syllabus text without markers", {})
    assert doc_type == "Unknown Document"
    assert conf < 0.60
    assert len(warnings) > 0

    pii = [{"type": "person_name", "value": "Unknown Person", "confidence": 0.80}]
    res = analyze_purpose("Unknown Document", "stuff", pii)
    assert res["review_required"] is True
    assert res["requirements"][0]["decision"] == "UNNECESSARY"


# ==============================================================================
# 6. PHYSICAL PIXEL REDACTION & IMMUTABILITY
# ==============================================================================

def test_physical_redaction_and_immutability():
    """
    Verifies that physical OpenCV redaction alters the output file pixels
    while leaving the original uploaded image completely immutable.
    """
    engine = RedactionEngine()
    test_img = os.path.join(TEST_IMAGES_DIR, "pan_sample.png")
    assert os.path.isfile(test_img), f"Test image missing: {test_img}"

    # Read original image bytes before redaction
    with open(test_img, "rb") as f:
        orig_bytes = f.read()

    fields_dict = {
        "Person Name": {"value": "AARAV SHARMA", "bbox": {"x": 50, "y": 80, "width": 200, "height": 30}},
        "PAN Number": {"value": "ABCDE1234F", "bbox": {"x": 50, "y": 140, "width": 180, "height": 30}}
    }
    requirements = [
        {"field": "Person Name", "decision": "REQUIRED", "action": "PRESERVED"},
        {"field": "PAN Number", "decision": "UNNECESSARY", "action": "FULLY_MASKED"}
    ]

    out_name = "test_redacted_immutability_output.png"
    out_path = os.path.join(engine.output_dir, out_name)

    result = engine.redact_document(
        image_path=test_img,
        fields_dict=fields_dict,
        requirements=requirements,
        output_path=out_path
    )

    assert result["success"] is True
    assert os.path.isfile(out_path)

    # 1. Verify original file is 100% UNCHANGED
    with open(test_img, "rb") as f:
        current_bytes = f.read()
    assert current_bytes == orig_bytes, "Original document file was modified!"

    # 2. Verify PRESERVED field has zero pixel difference
    img_orig = cv2.imread(test_img)
    img_redacted = cv2.imread(out_path)

    # Person Name box should be EXACT match
    box_p = fields_dict["Person Name"]["bbox"]
    orig_crop_name = img_orig[box_p["y"]:box_p["y"]+box_p["height"], box_p["x"]:box_p["x"]+box_p["width"]]
    redacted_crop_name = img_redacted[box_p["y"]:box_p["y"]+box_p["height"], box_p["x"]:box_p["x"]+box_p["width"]]
    diff_name = cv2.absdiff(orig_crop_name, redacted_crop_name)
    assert np.count_nonzero(diff_name) == 0, "PRESERVED field pixels were altered!"

    # 3. Verify UNNECESSARY field has physical pixel redaction
    box_pan = fields_dict["PAN Number"]["bbox"]
    orig_crop_pan = img_orig[box_pan["y"]:box_pan["y"]+box_pan["height"], box_pan["x"]:box_pan["x"]+box_pan["width"]]
    redacted_crop_pan = img_redacted[box_pan["y"]:box_pan["y"]+box_pan["height"], box_pan["x"]:box_pan["x"]+box_pan["width"]]
    diff_pan = cv2.absdiff(orig_crop_pan, redacted_crop_pan)
    assert np.count_nonzero(diff_pan) > 0, "UNNECESSARY field was not physically redacted on pixels!"

    # Cleanup temp output
    if os.path.isfile(out_path):
        os.remove(out_path)
