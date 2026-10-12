"""
InfoShield AI - Risk Model Training Dataset Generator
Generates curated, realistic synthetic training dataset in data/risk_training.csv.
Clearly documented as curated prototype data for educational & demonstration purposes.
"""

import os
import sys
import csv
import json
import random

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "backend"))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# Load centralized PII sensitivities
with open(os.path.join(DATA_DIR, "pii_sensitivity.json"), "r") as f:
    SENSITIVITIES = json.load(f)

# Domain context risk baselines
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
    "pin_code": "LOW"
}

def determine_risk_class(sensitivity, necessity, context_risk, exposure_level):
    """
    Realistic multi-factor policy risk classifier:
    Considers PII sensitivity, purpose necessity, domain context, and exposure level.
    """
    # Sensitivity + Necessity interaction score
    necessity_weight = {"UNNECESSARY": 0.85, "CONDITIONAL": 0.50, "REQUIRED": 0.15}[necessity]
    exposure_weight = {"HIGH": 0.9, "MEDIUM": 0.5, "LOW": 0.2}[exposure_level]
    
    composite_risk = (
        (sensitivity * 0.40) +
        (necessity_weight * 0.30) +
        (context_risk * 0.15) +
        (exposure_weight * 0.15)
    )

    if composite_risk >= 0.63:
        return "HIGH"
    elif composite_risk >= 0.42:
        return "MEDIUM"
    else:
        return "LOW"


def generate_dataset(num_samples: int = 320, output_file: str = "data/risk_training.csv"):
    random.seed(42)

    pii_types = [
        "aadhaar_number", "vid", "pan_number", "bank_account_number",
        "mobile_number", "date_of_birth", "address", "person_name",
        "gender", "qr_code", "email_address", "pin_code", "ifsc_code"
    ]

    doc_types = [
        "Aadhaar Card", "PAN Card", "Passport", "Driving Licence",
        "College ID", "Marksheet", "Bank Statement", "Identity Document"
    ]

    domain_tasks = [
        ("education", "college_admission"),
        ("education", "scholarship"),
        ("education", "financial_aid"),
        ("education", "examination"),
        ("employment", "job_application"),
        ("employment", "onboarding"),
        ("employment", "background_verification"),
        ("employment", "payroll"),
        ("banking", "bank_account_opening"),
        ("banking", "kyc"),
        ("banking", "loan_application"),
        ("banking", "credit_verification"),
        ("government", "government_service"),
        ("government", "subsidy"),
        ("travel", "visa_application"),
        ("travel", "passport_application"),
        ("healthcare", "hospital_registration"),
        ("healthcare", "insurance_claim"),
        ("legal", "legal_verification"),
        ("general", "identity_verification"),
        ("general", "unknown")
    ]

    necessities = ["REQUIRED", "CONDITIONAL", "UNNECESSARY"]
    exposure_levels = ["HIGH", "MEDIUM", "LOW"]

    rows = []

    # Curated policy templates to ensure core canonical scenarios are guaranteed
    canonical_templates = [
        # College admission + financial aid
        ("person_name", "Aadhaar Card", "REQUIRED", "education", "college_admission", "LOW", "LOW"),
        ("date_of_birth", "Aadhaar Card", "CONDITIONAL", "education", "college_admission", "MEDIUM", "MEDIUM"),
        ("gender", "Aadhaar Card", "CONDITIONAL", "education", "college_admission", "LOW", "LOW"),
        ("mobile_number", "Aadhaar Card", "UNNECESSARY", "education", "college_admission", "HIGH", "HIGH"),
        ("aadhaar_number", "Aadhaar Card", "CONDITIONAL", "education", "college_admission", "HIGH", "HIGH"),
        ("vid", "Aadhaar Card", "UNNECESSARY", "education", "college_admission", "HIGH", "HIGH"),
        ("address", "Aadhaar Card", "CONDITIONAL", "education", "college_admission", "MEDIUM", "MEDIUM"),
        ("qr_code", "Aadhaar Card", "UNNECESSARY", "education", "college_admission", "HIGH", "HIGH"),
        
        # Bank KYC
        ("person_name", "Aadhaar Card", "REQUIRED", "banking", "kyc", "LOW", "LOW"),
        ("aadhaar_number", "Aadhaar Card", "REQUIRED", "banking", "kyc", "HIGH", "HIGH"),
        ("pan_number", "PAN Card", "REQUIRED", "banking", "kyc", "HIGH", "HIGH"),
        ("date_of_birth", "Aadhaar Card", "REQUIRED", "banking", "kyc", "MEDIUM", "MEDIUM"),
        ("address", "Aadhaar Card", "REQUIRED", "banking", "kyc", "MEDIUM", "MEDIUM"),
        ("mobile_number", "Aadhaar Card", "CONDITIONAL", "banking", "kyc", "MEDIUM", "MEDIUM"),
        ("qr_code", "Aadhaar Card", "UNNECESSARY", "banking", "kyc", "HIGH", "HIGH"),

        # Job Onboarding
        ("person_name", "Identity Document", "REQUIRED", "employment", "onboarding", "LOW", "LOW"),
        ("pan_number", "PAN Card", "REQUIRED", "employment", "onboarding", "HIGH", "HIGH"),
        ("bank_account_number", "Bank Statement", "REQUIRED", "employment", "onboarding", "HIGH", "HIGH"),
        ("aadhaar_number", "Aadhaar Card", "CONDITIONAL", "employment", "onboarding", "HIGH", "HIGH"),
        ("mobile_number", "Aadhaar Card", "REQUIRED", "employment", "onboarding", "MEDIUM", "LOW"),
        ("address", "Aadhaar Card", "CONDITIONAL", "employment", "onboarding", "MEDIUM", "MEDIUM"),
        ("vid", "Aadhaar Card", "UNNECESSARY", "employment", "onboarding", "HIGH", "HIGH"),

        # Visa Application
        ("person_name", "Passport", "REQUIRED", "travel", "visa_application", "LOW", "LOW"),
        ("date_of_birth", "Passport", "REQUIRED", "travel", "visa_application", "MEDIUM", "LOW"),
        ("address", "Passport", "CONDITIONAL", "travel", "visa_application", "MEDIUM", "MEDIUM"),
        ("aadhaar_number", "Aadhaar Card", "UNNECESSARY", "travel", "visa_application", "HIGH", "HIGH"),
        ("bank_account_number", "Bank Statement", "REQUIRED", "travel", "visa_application", "HIGH", "HIGH")
    ]

    for p_type, d_type, nec, dom, task, exp_lvl, risk_cls in canonical_templates:
        sens = SENSITIVITIES.get(p_type, 0.50)
        c_risk = DOMAIN_CONTEXT_RISKS.get(dom, 0.50)
        binding = IDENTITY_BINDING.get(p_type, "MEDIUM")
        for _ in range(4): # duplicate variations with slight jitter
            ocr_c = round(random.uniform(0.85, 0.99), 2)
            pii_c = round(random.uniform(0.85, 0.99), 2)
            rows.append({
                "pii_type": p_type,
                "document_type": d_type,
                "pii_sensitivity": sens,
                "purpose_necessity": nec,
                "purpose_domain": dom,
                "purpose_task": task,
                "ocr_confidence": ocr_c,
                "pii_confidence": pii_c,
                "context_risk": c_risk,
                "identity_binding_requirement": binding,
                "exposure_level": exp_lvl,
                "risk_class": risk_cls
            })

    # Generate additional diverse synthetic samples across full space
    while len(rows) < num_samples:
        p_type = random.choice(pii_types)
        d_type = random.choice(doc_types)
        dom, task = random.choice(domain_tasks)
        sens = SENSITIVITIES.get(p_type, 0.50)
        c_risk = DOMAIN_CONTEXT_RISKS.get(dom, 0.50)
        binding = IDENTITY_BINDING.get(p_type, "MEDIUM")
        
        # Realistic necessity correlation with sensitivity
        if p_type == "person_name":
            nec = random.choices(["REQUIRED", "CONDITIONAL"], weights=[0.85, 0.15])[0]
        elif p_type in ["vid", "qr_code"]:
            nec = random.choices(["UNNECESSARY", "CONDITIONAL"], weights=[0.85, 0.15])[0]
        elif sens >= 0.90:
            nec = random.choices(["CONDITIONAL", "UNNECESSARY", "REQUIRED"], weights=[0.45, 0.35, 0.20])[0]
        else:
            nec = random.choice(necessities)

        exp_lvl = "HIGH" if nec == "UNNECESSARY" and sens >= 0.70 else random.choice(exposure_levels)
        ocr_c = round(random.uniform(0.60, 0.99), 2)
        pii_c = round(random.uniform(0.65, 0.99), 2)

        risk_cls = determine_risk_class(sens, nec, c_risk, exp_lvl)

        rows.append({
            "pii_type": p_type,
            "document_type": d_type,
            "pii_sensitivity": sens,
            "purpose_necessity": nec,
            "purpose_domain": dom,
            "purpose_task": task,
            "ocr_confidence": ocr_c,
            "pii_confidence": pii_c,
            "context_risk": c_risk,
            "identity_binding_requirement": binding,
            "exposure_level": exp_lvl,
            "risk_class": risk_cls
        })

    # Write to CSV
    target_path = os.path.join(BASE_DIR, output_file)
    with open(target_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"✓ Generated {len(rows)} training samples in: {target_path}")


if __name__ == "__main__":
    generate_dataset()
