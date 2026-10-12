"""
InfoShield AI - Purpose Analysis & Policy Decision Engine
Phase 2: Purpose-Based PII Minimization Engine

A deterministic rule-based policy engine that interprets natural-language submission purposes
and evaluates detected PII fields against data minimization rules (Zero-Trust Privacy).

Architecture:
  1. Purpose Interpretation:
     - Domain classification (education, banking, employment, travel, government, etc.)
     - Task classification (college admission, KYC, job onboarding, visa application, etc.)
     - Submission context identification (college, bank, employer, embassy, etc.)
     - Sub-purpose extraction (financial aid, loan, domicile verification, etc.)

  2. Policy Decision Engine:
     - Evaluates each PII field: REQUIRED, CONDITIONAL, UNNECESSARY
     - Provides clear privacy rationale and confidence score
     - Applies sub-purpose dynamic modifiers (e.g., financial aid permitting disbursement data)
     - Fallback zero-trust minimization for unclassified/general purposes

Modular & extensible: Designed so an LLM or NLP classifier can replace or augment
the rule engine in future phases without breaking API contracts.
"""

from typing import Dict, Any, List, Optional
import re
from purpose_ai import classify_purpose
from risk_model import get_risk_model, PIIRiskModel


# ==============================================================================
# 1. SEMANTIC DICTIONARIES & TAXONOMY
# ==============================================================================

DOMAIN_KEYWORDS: Dict[str, List[str]] = {
    "education": [
        "college", "university", "school", "institute", "admission", "admissions",
        "student", "academic", "matriculation", "enrollment", "enrolment", "tuition",
        "course", "degree", "diploma", "semester", "hostel", "scholarship",
        "financial aid", "fee waiver", "exam", "examination", "marksheet"
    ],
    "banking": [
        "bank", "banking", "kyc", "account", "savings", "branch", "deposit",
        "fixed deposit", "loan", "mortgage", "credit card", "debit card",
        "ifsc", "rbi", "re-kyc", "current account", "overdraft", "netbanking",
        "financial institution", "financial", "income", "funds"
    ],
    "employment": [
        "job", "employment", "onboarding", "hire", "hiring", "employer",
        "hr", "company", "joining", "payroll", "salary", "background check",
        "bgv", "offer letter", "work", "staff", "corporation", "epfo", "provident fund"
    ],
    "travel": [
        "visa", "embassy", "consulate", "immigration", "travel", "flight",
        "airline", "foreign", "tourist", "schengen", "vfs", "border",
        "international", "hotel", "check-in", "booking"
    ],
    "government": [
        "government", "govt", "portal", "subsidy", "scheme", "ration",
        "pension", "dbt", "rto", "driving licence renewal", "voter",
        "municipal", "tehsil", "panchayat", "aadhaar update", "civic"
    ],
    "healthcare": [
        "hospital", "clinic", "doctor", "medical", "patient", "treatment",
        "admission to hospital", "health record", "prescription", "diagnostic", "pharmacy"
    ],
    "insurance": [
        "insurance", "claim", "policy", "premium", "coverage", "underwriting",
        "mediclaim", "tpa", "settlement"
    ],
    "legal": [
        "court", "legal", "lawyer", "affidavit", "notary", "agreement",
        "rental agreement", "lease", "deed", "litigation"
    ],
}

TASK_RULES: Dict[str, List[tuple]] = {
    "education": [
        (["marksheet", "qualification", "transcript", "marks", "grade", "score", "cbse"], "marksheet verification"),
        (["student identity", "student id", "student verification", "campus verification"], "student verification"),
        (["financial aid", "scholarship", "fee waiver", "grant", "stipend"], "college admission"),
        (["exam", "examination", "hall ticket", "admit card"], "exam registration"),
        (["hostel", "dormitory", "accommodation"], "hostel allocation"),
        (["admission", "apply", "enroll", "enrollment", "registration", "admitted", "matriculation"], "college admission"),
    ],
    "banking": [
        (["education loan", "student loan"], "education loan"),
        (["bank statement", "statement verification", "income verification", "salary verification", "proof of funds"], "income verification"),
        (["re-kyc", "update kyc", "kyc update"], "KYC"),
        (["kyc", "verification", "verify identity", "compliance", "customer verification"], "KYC"),
        (["loan", "mortgage", "credit card", "borrowing", "lending"], "loan application"),
        (["open account", "new account", "savings account", "current account", "opening"], "account opening"),
    ],
    "employment": [
        (["hr verification", "hr identity", "staff verification", "employee verification"], "hr verification"),
        (["salary slip", "payslip", "income verification", "salary verification", "proof of income"], "employment income verification"),
        (["onboarding", "joining", "hired", "offer", "new job", "employment verification", "joining formalities"], "job onboarding"),
        (["background check", "bgv", "police verification", "screening"], "background verification"),
        (["payroll", "salary account", "direct deposit", "epf", "epfo", "pf"], "payroll setup"),
    ],
    "travel": [
        (["hotel", "checkin", "check-in", "resort", "lodging"], "hotel check-in"),
        (["flight", "airline", "boarding", "ticket"], "flight check-in"),
        (["visa", "embassy", "consulate", "schengen", "tourist visa", "work permit"], "visa application"),
    ],
    "government": [
        (["subsidy", "scheme", "dbt", "ration", "pension"], "scheme enrollment"),
        (["licence renewal", "license renewal", "rto", "permit"], "licence renewal"),
        (["portal", "registration", "civic service", "certificate"], "civic services"),
    ],
    "healthcare": [
        (["insurance claim", "cashless", "tpa"], "medical insurance claim"),
        (["admission", "inpatient", "emergency"], "hospital admission"),
        (["consultation", "appointment", "outpatient", "clinic"], "outpatient consultation"),
    ],
    "insurance": [
        (["claim", "settlement", "reimbursement"], "insurance claim"),
        (["policy purchase", "new policy", "underwriting"], "policy issuance"),
    ],
    "legal": [
        (["rent agreement", "lease agreement", "tenant", "rental"], "rental agreement"),
        (["affidavit", "notary", "power of attorney"], "affidavit verification"),
    ],
    "general": [
        (["address proof", "proof of residence", "address verification", "address", "residence", "utility", "broadband"], "address verification"),
        (["identity", "id proof", "identify", "verification", "photo id", "kyc", "identification"], "general identity verification"),
    ],
}

SUB_PURPOSE_RULES: List[tuple] = [
    (["education loan", "student loan", "study loan"], "education loan"),
    (["income verification", "salary verification", "proof of income", "income proof", "salary proof"], "income verification"),
    (["hr verification", "employee verification", "staff check"], "hr verification"),
    (["financial aid", "fee waiver", "scholarship", "grant", "stipend"], "financial aid"),
    (["loan", "mortgage", "credit line", "emi"], "loan"),
    (["domicile", "quota", "reservation", "state quota"], "domicile verification"),
    (["background check", "bgv", "security clearance"], "background check"),
    (["tax deduction", "tds", "tax filing"], "tax compliance"),
    (["address proof", "proof of residence", "address verification", "proof of address"], "address proof"),
    (["age verification", "proof of age", "minor verification"], "age verification"),
]

CONTEXT_KEYWORDS: Dict[str, List[str]] = {
    "college": ["college", "campus", "institute", "faculty"],
    "university": ["university"],
    "school": ["school"],
    "bank": ["bank", "branch", "credit union", "lender", "nbfc"],
    "employer": ["employer", "company", "firm", "workplace", "hr", "office", "corporation"],
    "embassy": ["embassy", "consulate", "visa center", "vfs"],
    "government portal": ["government portal", "govt portal", "portal", "ministry", "rto", "tehsil"],
    "hospital": ["hospital", "clinic", "health center", "medical center"],
    "insurance company": ["insurance company", "insurer", "tpa"],
    "court": ["court", "notary", "advocate", "registrar office"],
}

DEFAULT_CONTEXTS: Dict[str, str] = {
    "education": "college",
    "banking": "bank",
    "employment": "employer",
    "travel": "embassy",
    "government": "government portal",
    "healthcare": "hospital",
    "insurance": "insurance company",
    "legal": "court",
    "general": "general verifier",
}

DEFAULT_TASKS: Dict[str, str] = {
    "education": "college admission",
    "banking": "KYC",
    "employment": "job onboarding",
    "travel": "visa application",
    "government": "civic services",
    "healthcare": "patient registration",
    "insurance": "insurance claim",
    "legal": "legal verification",
    "general": "general identity verification",
}


# ==============================================================================
# 2. POLICY RULES MATRIX (Data Minimization Standards)
# ==============================================================================

POLICIES: Dict[str, Dict[str, Dict[str, tuple]]] = {
    "education": {
        "college admission": {
            "person_name": ("REQUIRED", "Needed to identify the applicant for admission records.", 0.95),
            "date_of_birth": ("CONDITIONAL", "May be required for age and eligibility verification.", 0.82),
            "gender": ("CONDITIONAL", "May be relevant for certain eligibility criteria.", 0.70),
            "marks_cgpa": ("REQUIRED", "Academic marks and CGPA required to confirm admission qualification.", 0.98),
            "roll_number": ("CONDITIONAL", "Academic roll number acts as secondary credential reference.", 0.85),
            "passing_year": ("REQUIRED", "Year of passing confirms eligibility for admission cycle.", 0.92),
            "photograph": ("REQUIRED", "Student photograph required for academic identification records.", 0.95),
            "mobile_number": ("UNNECESSARY", "Not required for the stated submission purpose.", 0.91),
            "aadhaar_number": ("CONDITIONAL", "The institution may require identity verification, but full exposure should not be assumed necessary.", 0.84),
            "vid": ("UNNECESSARY", "Not required for the stated purpose.", 0.93),
            "address": ("CONDITIONAL", "Location may be relevant for eligibility or domicile verification.", 0.78),
            "qr_code": ("UNNECESSARY", "Biometric and cryptographic payload is unnecessary for academic admission.", 0.95),
            "email_address": ("UNNECESSARY", "Contact details on document are unnecessary; communication occurs via admissions portal.", 0.90),
            "pan_number": ("UNNECESSARY", "Tax identification is not relevant for academic admission proof.", 0.94),
            "bank_account_number": ("UNNECESSARY", "Banking details are not required for general admission identity proof.", 0.92),
            "ifsc_code": ("UNNECESSARY", "Banking routing codes are not required for general admission.", 0.92),
        },
        "marksheet verification": {
            "person_name": ("REQUIRED", "Mandatory to verify student candidate identity against academic record.", 0.99),
            "roll_number": ("REQUIRED", "Mandatory educational roll number required to verify marks with examination board.", 0.99),
            "marks_cgpa": ("REQUIRED", "Core academic marks and CGPA required to confirm qualification criteria.", 0.99),
            "passing_year": ("REQUIRED", "Required to establish academic graduation session and validity.", 0.96),
            "date_of_birth": ("CONDITIONAL", "May verify student birth date if recorded on certificate.", 0.85),
            "address": ("UNNECESSARY", "Residential address is not relevant for academic score verification.", 0.92),
            "aadhaar_number": ("UNNECESSARY", "National identity number is not required for qualification checks.", 0.95),
            "qr_code": ("UNNECESSARY", "Biometric matrix is not required for marksheet review.", 0.95),
        },
        "student verification": {
            "person_name": ("REQUIRED", "Mandatory to verify student enrolled status.", 0.98),
            "photograph": ("REQUIRED", "Visual photograph required for student campus identity matching.", 0.98),
            "roll_number": ("REQUIRED", "Enrolled student roll or registration number required.", 0.96),
            "date_of_birth": ("CONDITIONAL", "May confirm student age record.", 0.85),
            "address": ("UNNECESSARY", "Personal home address minimized for general campus verification.", 0.90),
            "aadhaar_number": ("CONDITIONAL", "Masked student identity proof.", 0.88),
            "qr_code": ("UNNECESSARY", "Biometric QR minimized.", 0.95),
        },
        "exam registration": {
            "person_name": ("REQUIRED", "Mandatory to verify examinee registration.", 0.98),
            "date_of_birth": ("REQUIRED", "Needed to verify examinee identity against examination roster.", 0.90),
            "gender": ("CONDITIONAL", "May be needed for exam center gender allocation.", 0.75),
            "aadhaar_number": ("CONDITIONAL", "Masked identifier is sufficient for exam hall entry.", 0.88),
            "address": ("UNNECESSARY", "Residential address is not needed at examination center.", 0.90),
            "mobile_number": ("UNNECESSARY", "Contact number on identity proof is not needed during examination.", 0.92),
            "vid": ("UNNECESSARY", "Virtual ID is unnecessary for exam hall admission.", 0.94),
            "qr_code": ("UNNECESSARY", "Biometric payload is not scanned for general exam seating.", 0.95),
        }
    },

    "banking": {
        "KYC": {
            "person_name": ("REQUIRED", "Mandatory to verify the legal account holder identity.", 0.98),
            "date_of_birth": ("REQUIRED", "Required by banking regulations to establish legal age and compliance.", 0.95),
            "aadhaar_number": ("CONDITIONAL", "Required for KYC verification, but first 8 digits should be masked per RBI/UIDAI guidelines.", 0.90),
            "pan_number": ("REQUIRED", "Mandatory for financial accounts and tax compliance under KYC norms.", 0.97),
            "address": ("REQUIRED", "Mandatory for residential and communication address verification under KYC rules.", 0.92),
            "mobile_number": ("CONDITIONAL", "May be needed to confirm registered mobile number for two-factor authentication.", 0.85),
            "gender": ("CONDITIONAL", "Demographic record used for account profile completion.", 0.75),
            "vid": ("CONDITIONAL", "Virtual ID may be accepted as a privacy-preserving alternative to Aadhaar.", 0.82),
            "qr_code": ("CONDITIONAL", "Used for secure offline XML verification by accredited banking representatives.", 0.85),
            "email_address": ("CONDITIONAL", "May be needed for electronic bank statements and notifications.", 0.80),
            "bank_account_number": ("CONDITIONAL", "Account identifier relevant if linking existing accounts.", 0.85),
            "ifsc_code": ("CONDITIONAL", "Branch code relevant for routing transactions.", 0.85),
        },
        "account opening": {
            "person_name": ("REQUIRED", "Mandatory to establish the account holder's legal identity.", 0.98),
            "date_of_birth": ("REQUIRED", "Mandatory to verify legal age of majority for banking services.", 0.96),
            "pan_number": ("REQUIRED", "Legally required for opening bank accounts under financial regulations.", 0.98),
            "aadhaar_number": ("CONDITIONAL", "Identity proof accepted, with masking required under privacy guidelines.", 0.90),
            "address": ("REQUIRED", "Required for mandatory proof of residence under banking compliance.", 0.94),
            "photograph": ("REQUIRED", "Visual portrait photograph required for account holder identification.", 0.98),
            "mobile_number": ("CONDITIONAL", "Required to bind SMS alerts and transaction authorization.", 0.88),
            "gender": ("CONDITIONAL", "Demographic record for customer registration.", 0.75),
            "vid": ("CONDITIONAL", "Privacy-preserving alternative to Aadhaar for account opening.", 0.80),
            "qr_code": ("CONDITIONAL", "Used for official offline verification by bank personnel.", 0.85),
        },
        "education loan": {
            "person_name": ("REQUIRED", "Essential for applicant legal identity verification.", 0.99),
            "bank_account_number": ("REQUIRED", "Mandatory bank account number for loan assessment and disbursement.", 0.98),
            "ifsc_code": ("REQUIRED", "Required alongside bank account for electronic disbursement routing.", 0.96),
            "salary_income": ("REQUIRED", "Statement balance or family income verified for debt capacity.", 0.98),
            "statement_period": ("REQUIRED", "Statement period verified to establish active financial standing.", 0.95),
            "marks_cgpa": ("REQUIRED", "Academic merit marks verified for education loan eligibility.", 0.96),
            "roll_number": ("CONDITIONAL", "Academic identifier supporting admission standing.", 0.88),
            "pan_number": ("REQUIRED", "Mandatory for credit score checking and income verification.", 0.98),
            "address": ("REQUIRED", "Mandatory residential verification under lending compliance.", 0.93),
            "date_of_birth": ("REQUIRED", "Required to verify legal credit eligibility and borrower age.", 0.96),
            "aadhaar_number": ("CONDITIONAL", "Identity verification permitted with masked UID.", 0.88),
            "photograph": ("REQUIRED", "Visual face photograph is globally preserved to ensure human identity verification.", 0.99),
            "qr_code": ("UNNECESSARY", "Biometric QR not scanned by loan underwriting.", 0.95),
        },
        "loan application": {
            "person_name": ("REQUIRED", "Essential for borrower legal identity verification.", 0.99),
            "date_of_birth": ("REQUIRED", "Required to verify legal credit eligibility and borrower age.", 0.96),
            "pan_number": ("REQUIRED", "Mandatory for credit score checking and income verification.", 0.98),
            "bank_account_number": ("REQUIRED", "Essential for assessing repayment history and loan disbursement.", 0.95),
            "ifsc_code": ("REQUIRED", "Required for automated loan disbursement and EMI mandate routing.", 0.95),
            "salary_income": ("REQUIRED", "Statement balance or verified income required for loan underwriting.", 0.98),
            "statement_period": ("REQUIRED", "Statement period verifies active account status.", 0.95),
            "address": ("REQUIRED", "Mandatory for property and physical residence verification.", 0.93),
            "aadhaar_number": ("CONDITIONAL", "Identity verification permitted with masked UID.", 0.88),
            "mobile_number": ("CONDITIONAL", "Primary contact for loan verification and dispatch.", 0.85),
            "gender": ("CONDITIONAL", "Demographic parameter for loan documentation.", 0.70),
            "vid": ("UNNECESSARY", "Virtual ID is unnecessary when primary credentials are provided.", 0.90),
        },
        "income verification": {
            "person_name": ("REQUIRED", "Mandatory to bind financial statement to individual.", 0.98),
            "salary_income": ("REQUIRED", "Compensation figures and closing balance verified as proof of funds.", 0.99),
            "employee_id": ("REQUIRED", "Employee ID code verifies corporate payroll earnings.", 0.98),
            "statement_period": ("REQUIRED", "Confirms active period of earnings and banking transactions.", 0.95),
            "ifsc_code": ("REQUIRED", "Confirms verified financial branch routing.", 0.95),
            "bank_account_number": ("CONDITIONAL", "Account number acts as identifier; middle digits masked to limit exposure.", 0.90),
            "pan_number": ("CONDITIONAL", "Tax reference for income verification.", 0.90),
            "address": ("CONDITIONAL", "Residential location verified at regional level.", 0.85),
            "date_of_birth": ("UNNECESSARY", "Date of birth not strictly required for statement verification.", 0.88),
            "qr_code": ("UNNECESSARY", "Biometric QR unnecessary.", 0.95),
        }
    },

    "employment": {
        "job onboarding": {
            "person_name": ("REQUIRED", "Essential to verify the employee's legal identity.", 0.98),
            "date_of_birth": ("REQUIRED", "Required for statutory employment compliance and retirement records.", 0.94),
            "pan_number": ("REQUIRED", "Mandatory for payroll tax deduction (TDS) and income tax reporting.", 0.97),
            "bank_account_number": ("REQUIRED", "Essential for salary disbursement and direct payroll deposit.", 0.96),
            "ifsc_code": ("REQUIRED", "Required alongside bank account for electronic salary transfer routing.", 0.96),
            "aadhaar_number": ("CONDITIONAL", "Identity proof accepted, but full 12 digits should be masked per statutory guidelines.", 0.88),
            "address": ("CONDITIONAL", "Broad residential jurisdiction needed for records; exact street details can be minimized.", 0.80),
            "mobile_number": ("UNNECESSARY", "Contact information is collected via the employee record form, not document exposure.", 0.89),
            "email_address": ("UNNECESSARY", "Corporate communication is conducted via official employer email.", 0.90),
            "gender": ("CONDITIONAL", "Demographic data collected for statutory diversity reporting.", 0.72),
            "vid": ("UNNECESSARY", "Virtual ID is superfluous when PAN and masked identity are provided.", 0.92),
            "qr_code": ("UNNECESSARY", "Biometric QR payload is unnecessary for corporate employment verification.", 0.94),
        },
        "background verification": {
            "person_name": ("REQUIRED", "Mandatory for background check candidate identification.", 0.99),
            "date_of_birth": ("REQUIRED", "Required to differentiate candidate records in public/academic registries.", 0.95),
            "address": ("REQUIRED", "Mandatory for address verification and local jurisdiction checks.", 0.95),
            "aadhaar_number": ("CONDITIONAL", "Identity proof accepted with masked digits.", 0.85),
            "pan_number": ("CONDITIONAL", "May be used to verify past employment tax history.", 0.85),
            "mobile_number": ("UNNECESSARY", "Verifier contacts candidate directly, document contact not exposed.", 0.88),
            "vid": ("UNNECESSARY", "Virtual ID unnecessary for background verification.", 0.93),
            "qr_code": ("UNNECESSARY", "Biometric payload not needed for background vetting.", 0.95),
        },
        "hr verification": {
            "person_name": ("REQUIRED", "Legal full name required for HR employee identification.", 0.99),
            "employee_id": ("REQUIRED", "Employee ID code required for internal HR record matching.", 0.99),
            "designation": ("REQUIRED", "Designation/title confirms employee organizational role.", 0.96),
            "photograph": ("REQUIRED", "Employee photograph required for visual staff directory match.", 0.98),
            "date_of_birth": ("CONDITIONAL", "Secondary verification against HR records.", 0.85),
            "pan_number": ("CONDITIONAL", "Tax identifier reference for HR files.", 0.85),
            "salary_income": ("UNNECESSARY", "Compensation figures not required for basic HR identity verification.", 0.95),
            "bank_account_number": ("UNNECESSARY", "Direct bank details not required for HR identity card review.", 0.95),
            "address": ("CONDITIONAL", "Residential jurisdiction for HR record.", 0.80),
            "mobile_number": ("UNNECESSARY", "Personal contact collected via employee portal.", 0.90),
            "aadhaar_number": ("CONDITIONAL", "Masked national identity proof.", 0.88),
            "qr_code": ("UNNECESSARY", "Biometric QR unnecessary.", 0.95),
        },
        "employment income verification": {
            "person_name": ("REQUIRED", "Legal full name verifies ownership of compensation record.", 0.99),
            "employee_id": ("REQUIRED", "Employee ID code verifies corporate affiliation.", 0.98),
            "salary_income": ("REQUIRED", "Gross and net earnings figures are primary proof of income.", 0.99),
            "statement_period": ("REQUIRED", "Pay period confirms current valid earnings cycle.", 0.96),
            "designation": ("CONDITIONAL", "Designation provides corporate role context.", 0.88),
            "pan_number": ("CONDITIONAL", "Tax PAN verifies salary compliance.", 0.90),
            "bank_account_number": ("CONDITIONAL", "Salary credit account identifier; middle digits masked.", 0.90),
            "date_of_birth": ("UNNECESSARY", "Date of birth not required for salary verification.", 0.90),
            "address": ("UNNECESSARY", "Residential address not required for salary verification.", 0.92),
            "aadhaar_number": ("UNNECESSARY", "National identity number not required for income verification.", 0.95),
            "qr_code": ("UNNECESSARY", "Biometric QR unnecessary.", 0.95),
        }
    },

    "travel": {
        "visa application": {
            "person_name": ("REQUIRED", "Must match international travel records and visa application exactly.", 0.99),
            "passport_number": ("REQUIRED", "Mandatory international travel credential required for visa processing.", 0.99),
            "nationality": ("REQUIRED", "Mandatory nationality declaration for international visa issuance.", 0.98),
            "mrz": ("REQUIRED", "Machine Readable Zone required for consular border and visa validation.", 0.99),
            "date_of_birth": ("REQUIRED", "Mandatory biographical data for international security and visa issuance.", 0.98),
            "validity_date": ("REQUIRED", "Passport validity date required to satisfy minimum travel validity rules.", 0.98),
            "photograph": ("REQUIRED", "Consular facial biometric comparison required for visa issuance.", 0.98),
            "gender": ("REQUIRED", "Required by international consular and aviation standards (ICAO Doc 9303).", 0.95),
            "address": ("REQUIRED", "Required for consular jurisdiction and residence verification in home country.", 0.90),
            "mobile_number": ("CONDITIONAL", "Emergency contact information for consular notifications.", 0.80),
            "email_address": ("CONDITIONAL", "Electronic correspondence regarding visa application status.", 0.82),
            "aadhaar_number": ("UNNECESSARY", "Domestic national identity number is not recognized for foreign sovereign visa issuance.", 0.92),
            "vid": ("UNNECESSARY", "Domestic UID payload is irrelevant for foreign immigration authorities.", 0.95),
            "pan_number": ("UNNECESSARY", "National tax identifier is irrelevant for visa biographical records.", 0.90),
            "bank_account_number": ("CONDITIONAL", "If submitting financial proof, aggregate balance summary suffices over unmasked account number.", 0.85),
            "ifsc_code": ("UNNECESSARY", "Domestic clearing code is irrelevant for foreign visa review.", 0.92),
            "qr_code": ("UNNECESSARY", "Domestic QR matrix is incompatible with foreign consular border systems.", 0.96),
        },
        "hotel check-in": {
            "person_name": ("REQUIRED", "Required for guest registration record.", 0.95),
            "date_of_birth": ("CONDITIONAL", "Proof of majority may be needed for room booking.", 0.80),
            "gender": ("UNNECESSARY", "Not required for general accommodation check-in.", 0.88),
            "address": ("CONDITIONAL", "General city or region of origin is sufficient for guest registry.", 0.82),
            "aadhaar_number": ("CONDITIONAL", "Masked identity proof suffices for domestic hotel compliance.", 0.85),
            "mobile_number": ("UNNECESSARY", "Contact info collected via reservation system, not on document.", 0.90),
            "vid": ("UNNECESSARY", "Virtual ID unnecessary for hotel check-in.", 0.95),
            "qr_code": ("UNNECESSARY", "Hotel front desks should not scan unverified biometric QR codes.", 0.96),
            "pan_number": ("UNNECESSARY", "Tax identifier is irrelevant for lodging identification.", 0.94),
        }
    },

    "government": {
        "scheme enrollment": {
            "person_name": ("REQUIRED", "Mandatory to verify beneficiary entitlement.", 0.98),
            "date_of_birth": ("REQUIRED", "Required for age-bracketed welfare eligibility.", 0.95),
            "aadhaar_number": ("CONDITIONAL", "Identity proof accepted; masking recommended unless Direct Benefit Transfer mandates UID.", 0.88),
            "address": ("REQUIRED", "Mandatory to verify state/district territorial jurisdiction.", 0.94),
            "gender": ("CONDITIONAL", "Required if the welfare scheme is gender-specific.", 0.80),
            "bank_account_number": ("CONDITIONAL", "Required if financial subsidy is disbursed directly to beneficiary.", 0.88),
            "ifsc_code": ("CONDITIONAL", "Required for direct electronic treasury transfer.", 0.88),
            "mobile_number": ("CONDITIONAL", "Required for scheme enrollment SMS alerts.", 0.82),
            "vid": ("CONDITIONAL", "Valid alternative to Aadhaar for welfare scheme access.", 0.85),
            "qr_code": ("CONDITIONAL", "May be scanned by authorized civic enrollment centers.", 0.82),
        }
    },

    "general": {
        "general identity verification": {
            "photograph": ("REQUIRED", "Visual face photograph is required to match and confirm the identity of the document holder.", 0.98),
            "person_name": ("REQUIRED", "Legal full name is necessary for individual identity verification.", 0.95),
            "licence_number": ("CONDITIONAL", "Licence identifier confirms document authenticity; sequential numbers can be masked.", 0.85),
            "date_of_birth": ("CONDITIONAL", "Expose only birth year if age verification is required; otherwise minimize.", 0.75),
            "validity_date": ("CONDITIONAL", "Validity date verifies that the credential has not expired and remains legally active.", 0.85),
            "gender": ("UNNECESSARY", "Gender is not strictly necessary for identity verification and is minimized under zero-trust.", 0.85),
            "address": ("UNNECESSARY", "Residential address is not required for general identity verification under zero-trust minimization.", 0.90),
            "blood_group": ("UNNECESSARY", "Private medical health information is not relevant for identity verification.", 0.96),
            "authorized_classes": ("UNNECESSARY", "Vehicle driving class is not relevant for personal identity verification.", 0.90),
            "aadhaar_number": ("UNNECESSARY", "High-risk national identifier should not be exposed without a verified statutory requirement.", 0.92),
            "vid": ("UNNECESSARY", "High-risk credential shielded under zero-trust default.", 0.95),
            "mobile_number": ("UNNECESSARY", "Personal contact information shielded from untrusted third parties.", 0.90),
            "pan_number": ("UNNECESSARY", "Financial tax identifier shielded from generic verification.", 0.95),
            "bank_account_number": ("UNNECESSARY", "High-risk banking identifier shielded from generic exposure.", 0.98),
            "ifsc_code": ("UNNECESSARY", "Banking routing details shielded from generic verification.", 0.95),
            "email_address": ("UNNECESSARY", "Personal email shielded from generic third-party sharing.", 0.90),
            "qr_code": ("UNNECESSARY", "Cryptographic biometric payload shielded from third-party harvesting.", 0.97),
        },
        "address verification": {
            "address": ("REQUIRED", "Full residential address is the mandatory primary field for proof of residence verification.", 0.99),
            "person_name": ("REQUIRED", "Full legal name is required to bind the residential address to the applicant.", 0.98),
            "photograph": ("REQUIRED", "Visual face photograph is globally preserved to ensure human identity verification.", 0.99),
            "licence_number": ("CONDITIONAL", "Licence number acts as auxiliary document reference; sequential digits masked to prevent unnecessary exposure.", 0.85),
            "validity_date": ("CONDITIONAL", "Validity date verifies document has not expired as a valid proof of residence.", 0.85),
            "date_of_birth": ("UNNECESSARY", "Date of birth is not required for address-only verification.", 0.90),
            "gender": ("UNNECESSARY", "Gender is not necessary for address verification.", 0.90),
            "blood_group": ("UNNECESSARY", "Private medical health information is irrelevant for address verification.", 0.98),
            "authorized_classes": ("UNNECESSARY", "Vehicle driving class is irrelevant for residential address verification.", 0.95),
            "aadhaar_number": ("CONDITIONAL", "Aadhaar may serve as address proof but requires masked UID.", 0.88),
            "mobile_number": ("UNNECESSARY", "Phone number is not required for address verification.", 0.90),
            "qr_code": ("UNNECESSARY", "Biometric QR payload is unnecessary for address verification.", 0.96),
        }
    }
}

# Sub-purpose dynamic overrides
SUB_PURPOSE_MODIFIERS: Dict[str, Dict[str, tuple]] = {
    "financial aid": {
        "bank_account_number": ("CONDITIONAL", "May be required for disbursement of financial aid or scholarship funds.", 0.85),
        "ifsc_code": ("CONDITIONAL", "Required alongside bank account for electronic financial aid deposit.", 0.85),
        "address": ("CONDITIONAL", "Location may be relevant for eligibility or domicile verification.", 0.78),
    },
    "domicile verification": {
        "address": ("REQUIRED", "Full residential state and district is mandatory for domicile verification.", 0.94),
    },
    "address proof": {
        "address": ("REQUIRED", "Full residential address is mandatory for proof of residence.", 0.99),
        "photograph": ("REQUIRED", "Visual face photograph is globally preserved to ensure human identity verification.", 0.99),
        "blood_group": ("UNNECESSARY", "Medical health data is not required for address proof.", 0.98),
        "date_of_birth": ("UNNECESSARY", "Date of birth is not required for address-only proof.", 0.90),
    },
    "loan": {
        "bank_account_number": ("REQUIRED", "Mandatory for assessing financial capacity and disbursement.", 0.95),
        "pan_number": ("REQUIRED", "Mandatory for credit score checking and income verification.", 0.97),
    },
    "education loan": {
        "bank_account_number": ("REQUIRED", "Mandatory for assessing financial capacity and disbursement.", 0.98),
        "ifsc_code": ("REQUIRED", "Required alongside bank account for electronic financial disbursement.", 0.96),
        "salary_income": ("REQUIRED", "Income/balance verified for education loan underwriting.", 0.98),
        "statement_period": ("REQUIRED", "Statement period verified for account active standing.", 0.95),
        "marks_cgpa": ("REQUIRED", "Academic merit marks verified for education loan eligibility.", 0.96),
        "pan_number": ("REQUIRED", "Mandatory for credit score checking and borrower identity.", 0.98),
    },
    "income verification": {
        "salary_income": ("REQUIRED", "Earnings figures verified as primary proof of income.", 0.99),
        "employee_id": ("REQUIRED", "Employee identification code verifies proof of corporate earnings.", 0.98),
        "statement_period": ("REQUIRED", "Pay period / statement period confirms active earnings cycle.", 0.96),
        "bank_account_number": ("CONDITIONAL", "Account identifier; middle digits masked to limit exposure.", 0.90),
        "pan_number": ("CONDITIONAL", "Tax reference for income verification.", 0.90),
        "date_of_birth": ("UNNECESSARY", "Date of birth not required for income verification.", 0.90),
        "address": ("UNNECESSARY", "Residential address not required for income verification.", 0.92),
    },
    "hr verification": {
        "employee_id": ("REQUIRED", "Employee ID code required for internal HR record matching.", 0.99),
        "designation": ("REQUIRED", "Designation/title confirms employee organizational role.", 0.96),
        "photograph": ("REQUIRED", "Employee photograph required for visual staff directory match.", 0.98),
        "salary_income": ("UNNECESSARY", "Compensation figures not required for basic HR identity verification.", 0.95),
    },
    "tax compliance": {
        "pan_number": ("REQUIRED", "Mandatory for income tax deduction and statutory compliance.", 0.98),
    }
}


# ==============================================================================
# 3. INTERPRETATION & CLASSIFICATION LOGIC
# ==============================================================================

def classify_domain(purpose: str) -> str:
    """
    Classifies the primary domain from the natural language purpose text.
    Returns standard domain key (e.g. 'education', 'banking', 'employment', 'travel', etc.).
    """
    cleaned = purpose.lower()
    scores: Dict[str, int] = {domain: 0 for domain in DOMAIN_KEYWORDS}

    for domain, keywords in DOMAIN_KEYWORDS.items():
        for kw in keywords:
            # Word boundary matching where possible, substring fallback
            pattern = r"\b" + re.escape(kw) + r"\b"
            if re.search(pattern, cleaned):
                scores[domain] += 2
            elif kw in cleaned:
                scores[domain] += 1

    best_domain = max(scores, key=lambda d: scores[d])
    return best_domain if scores[best_domain] > 0 else "general"


def classify_task(purpose: str, domain: str) -> str:
    """
    Determines the specific operational task within the identified domain.
    """
    cleaned = purpose.lower()
    domain_rules = TASK_RULES.get(domain, [])

    for keywords, task_name in domain_rules:
        for kw in keywords:
            pattern = r"\b" + re.escape(kw) + r"\b"
            if re.search(pattern, cleaned) or kw in cleaned:
                return task_name

    return DEFAULT_TASKS.get(domain, "general identity verification")


def classify_submission_context(purpose: str, domain: str) -> str:
    """
    Identifies the target institution or recipient context (e.g., college, bank, employer).
    """
    cleaned = purpose.lower()

    for context_name, keywords in CONTEXT_KEYWORDS.items():
        for kw in keywords:
            pattern = r"\b" + re.escape(kw) + r"\b"
            if re.search(pattern, cleaned) or kw in cleaned:
                return context_name

    return DEFAULT_CONTEXTS.get(domain, "general verifier")


def classify_sub_purpose(purpose: str, domain: str, task: str) -> Optional[str]:
    """
    Extracts secondary intent such as 'financial aid', 'loan', 'domicile verification'.
    """
    cleaned = purpose.lower()

    for keywords, sub_name in SUB_PURPOSE_RULES:
        for kw in keywords:
            pattern = r"\b" + re.escape(kw) + r"\b"
            if re.search(pattern, cleaned) or kw in cleaned:
                return sub_name

    return None


def interpret_purpose(purpose: str) -> Dict[str, Any]:
    """
    Full natural-language purpose semantic interpretation.
    Combines rule-based taxonomy with semantic embedding AI classifier.
    """
    domain = classify_domain(purpose)
    task = classify_task(purpose, domain)
    submission_context = classify_submission_context(purpose, domain)
    sub_purpose = classify_sub_purpose(purpose, domain, task)

    # If rule-based taxonomy returned generic fallback, augment via Semantic AI
    ai_res = classify_purpose(purpose)
    if domain == "general" and ai_res["domain"] != "general":
        domain = ai_res["domain"]
        submission_context = ai_res["submission_context"]
        ai_t = ai_res["task"]
        if domain == "education":
            task = "college admission" if "college" in ai_t else "examination" if "exam" in ai_t else "school admission" if "school" in ai_t else "scholarship" if "scholarship" in ai_t else DEFAULT_TASKS["education"]
        elif domain == "employment":
            task = "job onboarding" if ai_t in ["onboarding", "payroll"] else "background verification" if "background" in ai_t else "job application"
        elif domain == "banking":
            task = "kyc verification" if "kyc" in ai_t else "account opening" if "account" in ai_t else "loan application"
        elif domain == "travel":
            task = "visa application" if "visa" in ai_t else "passport application"
        elif domain == "government":
            task = "scheme enrollment"
        else:
            task = DEFAULT_TASKS.get(domain, "general identity verification")

    if not sub_purpose and ai_res["sub_purpose"] not in ["unknown", "general", None]:
        if "financial" in ai_res["sub_purpose"]:
            sub_purpose = "financial aid"
        elif "domicile" in ai_res["sub_purpose"]:
            sub_purpose = "domicile verification"
        elif "address" in ai_res["sub_purpose"]:
            sub_purpose = "address proof"
            if domain == "general":
                task = "address verification"
        elif "loan" in ai_res["sub_purpose"]:
            sub_purpose = "loan"

    if domain == "general" and "address" in purpose.lower() and task != "address verification":
        task = "address verification"
        sub_purpose = "address proof"

    return {
        "domain": domain,
        "task": task,
        "sub_purpose": sub_purpose,
        "submission_context": submission_context
    }


# ==============================================================================
# 4. POLICY DECISION & DATA MINIMIZATION
# ==============================================================================

def determine_requirement(
    pii_type: str,
    domain: str,
    task: str,
    sub_purpose: Optional[str] = None,
    document_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates a single PII field type against domain/task policies and sub-purpose modifiers.
    Probes persistent Supabase database policy rules first, falling back to local rules.
    Returns:
      {
        "type": pii_type,
        "decision": "REQUIRED" | "CONDITIONAL" | "UNNECESSARY",
        "reason": str,
        "confidence": float
      }
    """
    clean_type = pii_type.lower().strip()

    # Global photo-preservation rule: Never mask, blur, pixelate, or redact photograph
    if clean_type == "photograph":
        return {
            "type": pii_type,
            "decision": "REQUIRED",
            "reason": "Visual face photograph is globally preserved to ensure human identity verification across all submission workflows.",
            "confidence": 1.0
        }

    # 0. Zero-trust enforcement for Unknown Document
    if document_type == "Unknown Document":
        return {
            "type": pii_type,
            "decision": "UNNECESSARY",
            "reason": "Document type is unverified; zero-trust default minimization applied.",
            "confidence": 0.85
        }

    # 0. Check Database-backed policy rules if database is active
    if document_type:
        try:
            from supabase_service import get_db_service
            db = get_db_service()
            if db.is_connected():
                db_rule = db.get_policy_rule(
                    document_type=document_type,
                    purpose_domain=domain,
                    purpose_task=task,
                    pii_type=clean_type
                )
                if db_rule:
                    return {
                        "type": pii_type,
                        "decision": db_rule["decision"],
                        "reason": db_rule["reason"],
                        "confidence": 0.95
                    }
        except Exception:
            pass

    # 1. Check Sub-Purpose Modifiers first (specialized purpose exceptions)
    if sub_purpose and sub_purpose in SUB_PURPOSE_MODIFIERS:
        if clean_type in SUB_PURPOSE_MODIFIERS[sub_purpose]:
            decision, reason, conf = SUB_PURPOSE_MODIFIERS[sub_purpose][clean_type]
            return {
                "type": pii_type,
                "decision": decision,
                "reason": reason,
                "confidence": round(conf, 2)
            }

    # 2. Check Specific Domain -> Task Policy
    domain_policies = POLICIES.get(domain, {})
    task_policy = domain_policies.get(task, None)

    # Fallback to first available task policy in domain if specific task not found
    if not task_policy and domain_policies:
        task_policy = next(iter(domain_policies.values()))

    if task_policy and clean_type in task_policy:
        decision, reason, conf = task_policy[clean_type]
        return {
            "type": pii_type,
            "decision": decision,
            "reason": reason,
            "confidence": round(conf, 2)
        }

    # 3. Check General Policy Fallback
    if document_type != "Unknown Document":
        general_policy = POLICIES["general"]["general identity verification"]
        if clean_type in general_policy:
            decision, reason, conf = general_policy[clean_type]
            return {
                "type": pii_type,
                "decision": decision,
                "reason": reason,
                "confidence": round(conf, 2)
            }

    # 4. Default Zero-Trust Rule for uncataloged fields or unknown documents
    return {
        "type": pii_type,
        "decision": "UNNECESSARY",
        "reason": "Not recognized as necessary for the stated purpose under zero-trust minimization.",
        "confidence": 0.85
    }


def analyze_purpose(
    document_type: str,
    purpose: str,
    pii: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Core entrypoint for Purpose Analysis Engine (Phase 4A Intelligence).
    Combines:
    1. AI Semantic Purpose Intent Understanding
    2. Policy Layer Data Minimization Determination
    3. ML Exposure Risk Estimation (RandomForestClassifier)
    4. Decision Synthesis for Explainable Protection
    """
    # 1. AI semantic classification
    ai_intent = classify_purpose(purpose)

    # 2. Rule & policy interpretation
    interpretation = interpret_purpose(purpose)
    domain = interpretation["domain"]
    task = interpretation["task"]
    sub_purpose = interpretation["sub_purpose"]

    # 3. Evaluate requirements for every detected PII entity with ML risk scoring
    requirements = []
    counts = {"required": 0, "conditional": 0, "unnecessary": 0}

    risk_model = get_risk_model()

    for item in pii:
        pii_type = item.get("type", "").strip()
        if not pii_type:
            continue

        req = determine_requirement(
            pii_type=pii_type,
            domain=domain,
            task=task,
            sub_purpose=sub_purpose,
            document_type=document_type
        )

        # ML Risk Inference
        ocr_val = item.get("ocr_confidence")
        ocr_c = float(ocr_val) if ocr_val is not None else 0.90
        pii_val = item.get("confidence")
        pii_c = float(pii_val) if pii_val is not None else 0.90

        risk_pred = risk_model.predict_risk(
            pii_type=pii_type,
            document_type=document_type,
            purpose_necessity=req["decision"],
            purpose_domain=domain,
            purpose_task=task,
            ocr_confidence=ocr_c,
            pii_confidence=pii_c
        )

        decision, action, synth_reason = PIIRiskModel.synthesize_decision(
            necessity=req["decision"],
            risk_class=risk_pred["class"],
            pii_type=pii_type,
            purpose_task=task
        )

        req["decision"] = decision
        req["action"] = action
        if "reason" not in req or not req["reason"]:
            req["reason"] = synth_reason
        req["risk"] = {
            "class": risk_pred["class"],
            "probability": risk_pred["probability"]
        }
        req["risk_class"] = risk_pred["class"]
        req["risk_probability"] = risk_pred["probability"]

        requirements.append(req)

        dec_key = decision.lower()
        if dec_key in counts:
            counts[dec_key] += 1

    intent_conf = float(ai_intent.get("intent_confidence", 1.0) or 1.0)
    review_required = (
        intent_conf < 0.60
        or (domain in ["unknown", "general"] and len(purpose.strip().split()) <= 2)
        or len(ai_intent.get("alternative_intents", [])) >= 3
    )

    return {
        "success": True,
        "domain": ai_intent["domain"],
        "task": ai_intent["task"],
        "sub_purpose": ai_intent["sub_purpose"],
        "submission_context": ai_intent["submission_context"],
        "intent_confidence": ai_intent["intent_confidence"],
        "ai_model": ai_intent["ai_model"],
        "alternative_intents": ai_intent["alternative_intents"],
        "reasoning_signals": ai_intent["reasoning_signals"],
        "purpose_analysis": interpretation,
        "review_required": review_required,
        "requirements": requirements,
        "summary": counts
    }

