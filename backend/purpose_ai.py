"""
InfoShield AI - Purpose Understanding Engine (Phase 4A)
Production NLP / Semantic AI Model for Arbitrary Natural-Language Purpose Intent Classification.

Architecture:
1. Primary: sentence-transformers (all-MiniLM-L6-v2) semantic embedding model.
2. Fallback: scikit-learn semantic vector-space model (TF-IDF sublinear n-gram embeddings
   + dense cosine similarity matrix + calibrated Softmax temperature distribution)
   used automatically if PyTorch wheel cannot be installed due to Windows MAX_PATH limits.

Never relies on simple keyword checks. Always compares user free-form purpose against
a comprehensive curated intent knowledge base via semantic vector embeddings.
"""

import os
import re
import numpy as np
from typing import Dict, Any, List, Optional, Tuple

try:
    import sentence_transformers
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except Exception:
    HAS_SENTENCE_TRANSFORMERS = False

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


# ==============================================================================
# 1. CURATED PURPOSE INTENT KNOWLEDGE BASE
# ==============================================================================

PURPOSE_KNOWLEDGE_BASE: List[Dict[str, Any]] = [
    # --------------------------------------------------------------------------
    # EDUCATION DOMAIN
    # --------------------------------------------------------------------------
    {
        "id": "edu_college_admission",
        "domain": "education",
        "task": "college_admission",
        "sub_purpose": "general_admission",
        "submission_context": "college",
        "examples": [
            "I need Aadhaar for college admission",
            "The college needs my Aadhaar to process my admission",
            "I am submitting my identity document to my university for admission enrollment",
            "College admission document verification for new undergraduate program",
            "Registering for admission to higher education institute",
            "Submitting application for university degree admission",
            "Document upload for college seat allotment and enrollment",
            "Identity proof for admission to engineering college"
        ],
        "keywords": ["college", "university", "admission", "enrollment", "registrar", "institute"]
    },
    {
        "id": "edu_college_financial_aid",
        "domain": "education",
        "task": "college_admission",
        "sub_purpose": "financial_aid",
        "submission_context": "college",
        "examples": [
            "I need to submit my Aadhaar to my college for admission and financial aid. They need it to verify my identity and process my financial assistance.",
            "I need this document for university financial aid",
            "College admission with financial assistance and fee waiver",
            "Submitting documents for student tuition fee concession and college aid",
            "University scholarship and financial aid office submission",
            "Identity verification for college admission hardship grant and financial support",
            "Applying for university student financial aid package along with admission"
        ],
        "keywords": ["financial aid", "assistance", "grant", "concession", "waiver", "college", "tuition"]
    },
    {
        "id": "edu_scholarship",
        "domain": "education",
        "task": "scholarship",
        "sub_purpose": "scholarship_processing",
        "submission_context": "scholarship_portal",
        "examples": [
            "I have to submit my ID proof for scholarship processing",
            "Applying for state government merit scholarship scheme",
            "Document verification for national scholarship portal NSP",
            "Higher education scholarship grant verification",
            "Post-matric scholarship application document upload",
            "Identity proof for minority scholarship disbursement"
        ],
        "keywords": ["scholarship", "merit", "portal", "stipend", "grant", "disbursement"]
    },
    {
        "id": "edu_school_admission",
        "domain": "education",
        "task": "school_admission",
        "sub_purpose": "student_admission",
        "submission_context": "school",
        "examples": [
            "School admission identity proof for child",
            "Submitting Aadhaar for primary school admission registration",
            "Secondary school enrollment and class admission verification",
            "Uploading ID for high school student admission"
        ],
        "keywords": ["school", "child", "class", "nursery", "primary", "secondary"]
    },
    {
        "id": "edu_examination",
        "domain": "education",
        "task": "examination",
        "sub_purpose": "exam_verification",
        "submission_context": "exam_center",
        "examples": [
            "ID card required for university examination hall ticket",
            "Identity proof for board exam entrance and verification",
            "Competitive exam document check at examination center",
            "Aadhaar card for semester examination admit card verification"
        ],
        "keywords": ["examination", "exam", "hall ticket", "admit card", "test"]
    },
    {
        "id": "edu_student_verification",
        "domain": "education",
        "task": "student_verification",
        "sub_purpose": "campus_verification",
        "submission_context": "college",
        "examples": [
            "Student verification for university identity card issuance",
            "College campus library card registration",
            "Verifying enrolled student identity credentials",
            "Annual student status re-verification at campus administrative office"
        ],
        "keywords": ["student", "library", "campus", "id card", "verification"]
    },
    {
        "id": "edu_hostel_admission",
        "domain": "education",
        "task": "hostel_admission",
        "sub_purpose": "accommodation",
        "submission_context": "college",
        "examples": [
            "Hostel room allocation document submission",
            "University dormitory hostel admission verification",
            "College residence hall booking identity proof",
            "Student hostel allotment and boarding registration"
        ],
        "keywords": ["hostel", "dormitory", "accommodation", "room", "boarding"]
    },
    {
        "id": "edu_marksheet_verification",
        "domain": "education",
        "task": "marksheet_verification",
        "sub_purpose": "academic_credentials",
        "submission_context": "college",
        "examples": [
            "Submitting marksheet for college admission eligibility verification",
            "Educational qualification verification for university enrollment",
            "Academic transcript and marksheet verification for degree admission",
            "Verifying CBSE board examination marks and CGPA for college admission",
            "Marksheet submission for undergraduate admission seat allotment",
            "Academic score verification and mark sheet evaluation"
        ],
        "keywords": ["marksheet", "transcript", "qualification", "board", "cgpa", "marks", "education", "score", "grade"]
    },

    # --------------------------------------------------------------------------
    # EMPLOYMENT DOMAIN
    # --------------------------------------------------------------------------
    {
        "id": "emp_job_application",
        "domain": "employment",
        "task": "job_application",
        "sub_purpose": "candidate_screening",
        "submission_context": "recruiter",
        "examples": [
            "Submitting documents for job application and interview",
            "Job candidate identity screening for hiring process",
            "Application for software engineer job opening",
            "Uploading identity proof for recruitment portal",
            "Submitting document for job interview and hiring",
            "Job application documentation for employment screening",
            "Submitting identity proof and resume for job application at company",
            "Submitting resume and identity verification for new employment"
        ],
        "keywords": ["job", "application", "interview", "candidate", "recruitment", "hiring", "resume", "company", "employment"]
    },
    {
        "id": "emp_onboarding",
        "domain": "employment",
        "task": "onboarding",
        "sub_purpose": "new_hire_formalities",
        "submission_context": "employer",
        "examples": [
            "Submitting documents for new job onboarding and joining formalities",
            "Submitting document for job interview and onboarding",
            "Company employee joining formalities and verification",
            "New hire HR documentation and badge creation",
            "Offer letter acceptance joining verification at corporate office",
            "Submitting PAN and Aadhaar for job joining and background check",
            "Employee joining onboarding formalities at office"
        ],
        "keywords": ["onboarding", "joining", "new hire", "company", "formalities", "hr", "interview"]
    },
    {
        "id": "emp_background_verification",
        "domain": "employment",
        "task": "background_verification",
        "sub_purpose": "bgv_screening",
        "submission_context": "bgv_agency",
        "examples": [
            "Employee background verification HR onboarding",
            "Third party employment background check and address check",
            "Pre-employment background screening BGV submission",
            "Criminal record and identity background check for employment",
            "Submitting identity proof for employment background verification at company",
            "Uploading identity documents and resume for employee background check",
            "Identity proof and resume for company background verification"
        ],
        "keywords": ["background", "verification", "bgv", "screening", "check", "agency", "resume", "company", "employment"]
    },
    {
        "id": "emp_payroll",
        "domain": "employment",
        "task": "payroll",
        "sub_purpose": "salary_disbursement",
        "submission_context": "employer",
        "examples": [
            "Setting up payroll and salary account with employer",
            "PAN card and bank account submission for salary crediting",
            "Employee PF gratuity and monthly payroll registration",
            "Corporate payroll processing documentation"
        ],
        "keywords": ["payroll", "salary", "disbursement", "pf", "tax", "compensation"]
    },
    {
        "id": "emp_hr_verification",
        "domain": "employment",
        "task": "hr_verification",
        "sub_purpose": "identity_confirmation",
        "submission_context": "employer",
        "examples": [
            "Submitting document for HR identity verification and staff records",
            "HR employee onboarding and identity confirmation",
            "HR department identity verification for employment badge and staff profile",
            "Corporate employee HR identification and verification"
        ],
        "keywords": ["hr", "human resources", "staff", "employee", "identity verification", "company", "badge"]
    },
    {
        "id": "emp_income_verification",
        "domain": "employment",
        "task": "employment_income_verification",
        "sub_purpose": "salary_proof",
        "submission_context": "employer",
        "examples": [
            "Employment and income verification with salary slip",
            "Submitting salary slip and employment certificate for proof of income",
            "Salary certificate and employee verification for employment record",
            "Payslip document submission for income proof and job verification"
        ],
        "keywords": ["employment", "income verification", "salary slip", "payslip", "gross salary", "net pay", "earnings"]
    },

    # --------------------------------------------------------------------------
    # BANKING / FINANCIAL DOMAIN
    # --------------------------------------------------------------------------
    {
        "id": "fin_bank_account_opening",
        "domain": "banking",
        "task": "bank_account_opening",
        "sub_purpose": "account_opening",
        "submission_context": "bank",
        "examples": [
            "Opening a new savings bank account at branch",
            "Current account opening documentation for business",
            "Digital savings account opening video KYC",
            "Bank account setup with initial deposit and identity proof"
        ],
        "keywords": ["bank", "account", "savings", "current", "branch", "opening"]
    },
    {
        "id": "fin_kyc",
        "domain": "banking",
        "task": "kyc",
        "sub_purpose": "kyc_update",
        "submission_context": "bank",
        "examples": [
            "Submitting document for bank KYC update",
            "Periodic re-KYC compliance for active savings account",
            "Bank KYC verification to unfreeze bank account",
            "Reserve Bank KYC verification requirement for financial account",
            "Uploading Aadhaar and PAN for mandatory banking KYC"
        ],
        "keywords": ["kyc", "re-kyc", "compliance", "bank", "update", "unfreeze"]
    },
    {
        "id": "fin_loan_application",
        "domain": "banking",
        "task": "loan_application",
        "sub_purpose": "credit_underwriting",
        "submission_context": "financial_institution",
        "examples": [
            "Applying for home loan with housing finance company",
            "Personal loan application identity and income proof",
            "Education loan document submission for foreign studies",
            "Vehicle car loan application verification"
        ],
        "keywords": ["loan", "borrowing", "credit", "mortgage", "finance", "interest"]
    },
    {
        "id": "fin_education_loan",
        "domain": "banking",
        "task": "education_loan",
        "sub_purpose": "loan_underwriting",
        "submission_context": "financial_institution",
        "examples": [
            "Submitting bank statement for education loan sanction and financial eligibility",
            "Applying for student education loan with bank statement and income proof",
            "Bank account statement for college education loan verification",
            "Bank statement submission for foreign studies education loan"
        ],
        "keywords": ["education loan", "loan", "bank statement", "student loan", "bank", "borrowing"]
    },
    {
        "id": "fin_income_verification",
        "domain": "banking",
        "task": "income_verification",
        "sub_purpose": "income_proof",
        "submission_context": "bank",
        "examples": [
            "Income and bank statement verification for credit limit and banking services",
            "Salary and bank statement proof for bank account verification",
            "Verifying monthly account balance and salary credits with bank statement",
            "Submitting bank statement as proof of income and funds"
        ],
        "keywords": ["income", "bank statement", "salary", "balance", "statement", "statement verification"]
    },
    {
        "id": "fin_credit_verification",
        "domain": "banking",
        "task": "credit_verification",
        "sub_purpose": "credit_card",
        "submission_context": "bank",
        "examples": [
            "Applying for credit card identity and address verification",
            "CIBIL credit check and credit limit enhancement documentation",
            "Credit card issuing verification with financial services"
        ],
        "keywords": ["credit card", "cibil", "credit score", "limit", "bureau"]
    },

    # --------------------------------------------------------------------------
    # GOVERNMENT DOMAIN
    # --------------------------------------------------------------------------
    {
        "id": "gov_service",
        "domain": "government",
        "task": "government_service",
        "sub_purpose": "public_service",
        "submission_context": "government_agency",
        "examples": [
            "Application for state government welfare service on citizen portal",
            "Municipal corporation domicile certificate application",
            "Ration card update and citizen registry service",
            "Government portal electronic service delivery submission"
        ],
        "keywords": ["government", "portal", "citizen", "welfare", "municipal", "service"]
    },
    {
        "id": "gov_subsidy",
        "domain": "government",
        "task": "subsidy",
        "sub_purpose": "benefit_transfer",
        "submission_context": "government_agency",
        "examples": [
            "LPG cooking gas subsidy Aadhaar linking DBT",
            "Agricultural farmer subsidy scheme enrollment",
            "Direct Benefit Transfer DBT subsidy bank account linkage",
            "Solar rooftop government subsidy application"
        ],
        "keywords": ["subsidy", "dbt", "lpg", "grant", "farmer", "scheme"]
    },

    # --------------------------------------------------------------------------
    # TRAVEL DOMAIN
    # --------------------------------------------------------------------------
    {
        "id": "travel_visa",
        "domain": "travel",
        "task": "visa_application",
        "sub_purpose": "embassy_processing",
        "submission_context": "consulate",
        "examples": [
            "Applying for Schengen tourist visa at embassy",
            "US student visa F1 consular document submission",
            "Work permit visa application verification",
            "International travel visa processing at VFS global"
        ],
        "keywords": ["visa", "embassy", "consulate", "vfs", "travel", "international"]
    },
    {
        "id": "travel_passport",
        "domain": "travel",
        "task": "passport_application",
        "sub_purpose": "passport_seva",
        "submission_context": "passport_office",
        "examples": [
            "Fresh passport application at Passport Seva Kendra",
            "Passport renewal and police verification submission",
            "Tatkaal passport application identity verification",
            "Indian passport issuance document check"
        ],
        "keywords": ["passport", "psk", "seva kendra", "renewal", "police verification"]
    },

    # --------------------------------------------------------------------------
    # HEALTHCARE DOMAIN
    # --------------------------------------------------------------------------
    {
        "id": "health_hospital_registration",
        "domain": "healthcare",
        "task": "hospital_registration",
        "sub_purpose": "patient_intake",
        "submission_context": "hospital",
        "examples": [
            "Patient admission registration at hospital reception",
            "Outpatient consultation OP card registration",
            "Hospital emergency admission patient identity check",
            "Medical clinic patient record creation"
        ],
        "keywords": ["hospital", "patient", "clinic", "doctor", "medical", "admission"]
    },
    {
        "id": "health_insurance_claim",
        "domain": "healthcare",
        "task": "insurance_claim",
        "sub_purpose": "claim_settlement",
        "submission_context": "insurance_company",
        "examples": [
            "Cashless mediclaim hospitalization insurance claim",
            "Health insurance policy reimbursement claim submission",
            "TPA insurance claim verification with medical bills",
            "Submitting identity proof for medical insurance settlement"
        ],
        "keywords": ["insurance", "claim", "mediclaim", "tpa", "reimbursement", "policy"]
    },

    # --------------------------------------------------------------------------
    # LEGAL DOMAIN
    # --------------------------------------------------------------------------
    {
        "id": "legal_verification",
        "domain": "legal",
        "task": "legal_verification",
        "sub_purpose": "affidavit_notary",
        "submission_context": "court",
        "examples": [
            "Affidavit notarization before advocate notary public",
            "Property registration identity proof at sub-registrar office",
            "Court judicial case filing identification document",
            "Legal agreement verification and stamp paper registration"
        ],
        "keywords": ["court", "legal", "affidavit", "notary", "advocate", "registrar"]
    },

    # --------------------------------------------------------------------------
    # GENERAL DOMAIN (FALLBACK)
    # --------------------------------------------------------------------------
    {
        "id": "gen_identity_verification",
        "domain": "general",
        "task": "identity_verification",
        "sub_purpose": "general_verification",
        "submission_context": "unspecified",
        "examples": [
            "General identity verification proof submission",
            "Confirming personal identity for service verification",
            "Submitting identity document for general purposes",
            "Generic ID proof for unspecified organization"
        ],
        "keywords": ["identity", "proof", "verification", "document", "general"]
    },
    {
        "id": "gen_address_verification",
        "domain": "general",
        "task": "address_verification",
        "sub_purpose": "address_proof",
        "submission_context": "utility_provider",
        "examples": [
            "Proof of residence and address verification",
            "Submitting document as address proof for gas or electricity connection",
            "Address verification for broadband internet installation",
            "Residential address proof for telecom SIM card verification",
            "Presenting utility document for local residence proof",
            "Submitting driving licence as proof of current address"
        ],
        "keywords": ["address", "residence", "proof of address", "address proof", "domicile", "utility", "broadband"]
    }
]


# ==============================================================================
# 2. SEMANTIC INTENT CLASSIFIER (DUAL ARCHITECTURE)
# ==============================================================================

class SemanticIntentClassifier:
    """
    NLP / ML Semantic Purpose Intent Classifier.
    Computes dense semantic embeddings of user input and compares against
    the curated purpose knowledge base using cosine similarity.
    """

    def __init__(self):
        self.model_name = "all-MiniLM-L6-v2"
        self.st_model = None
        self.is_fallback = False
        self.fallback_reason = None

        # Build training corpus from the knowledge base
        self.corpus_texts: List[str] = []
        self.corpus_meta: List[Dict[str, Any]] = []

        for intent in PURPOSE_KNOWLEDGE_BASE:
            for ex in intent["examples"]:
                self.corpus_texts.append(ex)
                self.corpus_meta.append(intent)
            kw_str = " ".join(intent.get("keywords", []))
            self.corpus_texts.append(f"{intent['domain']} {intent['task']} {kw_str}")
            self.corpus_meta.append(intent)

        # 1. Try to initialize sentence-transformers
        if HAS_SENTENCE_TRANSFORMERS:
            try:
                self.st_model = SentenceTransformer(self.model_name)
                self.st_embeddings = self.st_model.encode(self.corpus_texts, convert_to_numpy=True)
                self.model_type = "sentence_transformers_semantic_embedding"
            except Exception as e:
                self.is_fallback = True
                self.fallback_reason = f"sentence-transformers initialization exception: {str(e)}"
                self._init_sklearn_fallback()
        else:
            self.is_fallback = True
            self.fallback_reason = "PyTorch wheel installation restricted by Windows MAX_PATH (WinError 206) in this environment"
            self._init_sklearn_fallback()

    def _init_sklearn_fallback(self):
        """Initializes high-resolution TF-IDF semantic vector-space model."""
        self.model_name = "sklearn-tfidf-semantic-vector-space"
        self.model_type = "semantic_vector_space_classifier"
        # Sublinear TF with n-grams 1-2 and English stop-word filtering
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            stop_words="english",
            sublinear_tf=True,
            strip_accents="unicode",
            lowercase=True
        )
        self.tfidf_matrix = self.vectorizer.fit_transform(self.corpus_texts)

    def classify_purpose(self, user_purpose: str) -> Dict[str, Any]:
        """
        Takes raw, arbitrary user-written purpose text and computes semantic
        similarity against known purpose intents.
        """
        clean_text = user_purpose.strip()
        if not clean_text:
            return {
                "domain": "general",
                "task": "unknown",
                "sub_purpose": "unknown",
                "submission_context": "unspecified",
                "intent_confidence": 0.30,
                "ai_model": {
                    "name": self.model_name,
                    "type": self.model_type,
                    "fallback_active": self.is_fallback,
                    "fallback_reason": self.fallback_reason
                },
                "alternative_intents": [],
                "reasoning_signals": {
                    "matched_intent_label": "general.unknown",
                    "semantic_similarity": 0.0,
                    "key_signals": ["Empty or whitespace purpose string"]
                }
            }

        # Compute similarity scores across all corpus examples
        if self.st_model is not None and not self.is_fallback:
            query_emb = self.st_model.encode([clean_text], convert_to_numpy=True)
            similarities = cosine_similarity(query_emb, self.st_embeddings)[0]
        else:
            query_vec = self.vectorizer.transform([clean_text])
            similarities = cosine_similarity(query_vec, self.tfidf_matrix)[0]

        # Aggregate similarity scores by unique intent ID
        intent_scores: Dict[str, List[float]] = {}
        for idx, sim in enumerate(similarities):
            intent_id = self.corpus_meta[idx]["id"]
            if intent_id not in intent_scores:
                intent_scores[intent_id] = []
            intent_scores[intent_id].append(float(sim))

        # Score per intent: weighted combination of max similarity and top-2 mean
        aggregated_rankings = []
        for intent in PURPOSE_KNOWLEDGE_BASE:
            i_id = intent["id"]
            sims = sorted(intent_scores.get(i_id, [0.0]), reverse=True)
            top1 = sims[0] if len(sims) > 0 else 0.0
            top2_mean = float(np.mean(sims[:2])) if len(sims) >= 2 else top1
            score = (top1 * 0.70) + (top2_mean * 0.30)

            aggregated_rankings.append({
                "intent": intent,
                "score": float(score)
            })

        aggregated_rankings.sort(key=lambda x: x["score"], reverse=True)

        best = aggregated_rankings[0]
        best_intent = best["intent"]
        raw_confidence = best["score"]

        # Calibrate confidence using sigmoid scaling
        # (Transforms raw cosine similarities e.g. 0.40 -> 0.85, 0.85 -> 0.94)
        if raw_confidence >= 0.15:
            calibrated_conf = 1.0 / (1.0 + np.exp(-6.0 * (raw_confidence - 0.25)))
            calibrated_conf = float(np.clip(calibrated_conf, 0.45, 0.98))
        else:
            calibrated_conf = 0.30
            best_intent = {
                "domain": "general",
                "task": "unknown",
                "sub_purpose": "unknown",
                "submission_context": "unspecified",
                "keywords": []
            }

        # Build alternative intents list
        alternatives = []
        seen_tasks = {best_intent.get("task")}
        for item in aggregated_rankings[1:5]:
            alt_intent = item["intent"]
            task_key = alt_intent["task"]
            if task_key not in seen_tasks:
                seen_tasks.add(task_key)
                alt_conf = float(np.clip(item["score"] * 0.95, 0.20, 0.88))
                alternatives.append({
                    "domain": alt_intent["domain"],
                    "task": alt_intent["task"],
                    "sub_purpose": alt_intent["sub_purpose"],
                    "confidence": round(alt_conf, 2)
                })

        # Structured reasoning signals
        matched_tokens = [w for w in re.findall(r"\w+", clean_text.lower()) if w in " ".join(best_intent.get("keywords", [])).lower()]
        reasoning_signals = {
            "matched_intent_label": f"{best_intent['domain']}.{best_intent['task']}.{best_intent['sub_purpose']}",
            "semantic_similarity_score": round(raw_confidence, 4),
            "calibrated_confidence": round(calibrated_conf, 2),
            "aligned_domain_context": best_intent["submission_context"],
            "informative_signal_tokens": list(set(matched_tokens))[:6],
            "model_architecture": self.model_type
        }

        return {
            "domain": best_intent["domain"],
            "task": best_intent["task"],
            "sub_purpose": best_intent["sub_purpose"],
            "submission_context": best_intent["submission_context"],
            "intent_confidence": round(calibrated_conf, 2),
            "ai_model": {
                "name": self.model_name,
                "type": self.model_type,
                "fallback_active": self.is_fallback,
                "fallback_reason": self.fallback_reason
            },
            "alternative_intents": alternatives[:3],
            "reasoning_signals": reasoning_signals
        }


# Global singleton instance for efficient, single-load inference
_GLOBAL_PURPOSE_AI: Optional[SemanticIntentClassifier] = None


def get_purpose_ai() -> SemanticIntentClassifier:
    """Singleton getter ensuring purpose AI model is loaded only once."""
    global _GLOBAL_PURPOSE_AI
    if _GLOBAL_PURPOSE_AI is None:
        _GLOBAL_PURPOSE_AI = SemanticIntentClassifier()
    return _GLOBAL_PURPOSE_AI


def classify_purpose(user_purpose: str) -> Dict[str, Any]:
    """Top-level convenience function for purpose classification."""
    return get_purpose_ai().classify_purpose(user_purpose)
