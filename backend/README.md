# InfoShield AI — Purpose-Based PII Exposure Prevention & Secure Sharing Platform

**InfoShield AI** is a production-grade, pixel-level optical recognition, semantic purpose understanding, ML exposure-risk scoring, in-place image redaction, and database persistence system.

> **Zero Fake Data Guarantee**: All document text is extracted directly from image pixels using Tesseract and OpenCV. There are NO ground-truth text sidecars, NO hardcoded document contents, and NO synthetic text injection.
> 
> **Important Disclaimer**: Prototype policy rules and ML model are demonstration-grade and require validation against real organizational policies before production use.

---

## 1. Architecture Overview (Phase 4B)

```
[DOCUMENT IMAGE] + [USER STATED PURPOSE]
                      │
                      ▼
            POST /api/protect
                      │
     ┌────────────────┼──────────────────────────────┐
     │                ▼                              │
     │      [1] DATABASE INITIALIZATION              │
     │      • Insert into documents (UPLOADED)       │
     │      • Record DOCUMENT_UPLOADED audit log     │
     │                │                              │
     │                ▼                              │
     │      [2] REAL OCR ENGINE                      │
     │      • Tesseract word confidence extraction   │
     │      • OpenCV QR matrix localization          │
     │      • Update documents (SCANNED)             │
     │      • Record OCR_COMPLETED & PII_DETECTED    │
     │                │                              │
     │                ▼                              │
     │      [3] PURPOSE AI & ML RISK ENGINE          │
     │      • Semantic purpose intent classification │
     │      • Record purpose_analyses row            │
     │      • Policy data minimization evaluation    │
     │      • RandomForest ML exposure risk scoring  │
     │      • Record PURPOSE_ANALYZED & RISK_ANALYZED│
     │                │                              │
     │                ▼                              │
     │      [4] ZERO RAW PII ENTITY PERSISTENCE      │
     │      • Record pii_entities (metadata + bboxes)│
     │      • Record risk_predictions rows           │
     │      • Record POLICY_APPLIED audit log        │
     │                │                              │
     │                ▼                              │
     │      [5] PHYSICAL IMAGE REDACTION             │
     │      • OpenCV in-place bounding box masking   │
     │      • Record protected_documents row         │
     │      • Update documents (PROTECTED)           │
     │      • Record DOCUMENT_PROTECTED audit log    │
     │                │                              │
     └────────────────┼──────────────────────────────┘
                      ▼
             JSON API RESPONSE
      • Downloadable Redacted Image Route
      • Semantic AI & ML Intelligence
      • Cryptographic Hash-Chained Audit Trail
      • Supabase Persistence Status
```

---

## 2. Supabase PostgreSQL Architecture

### Database Entity Relationships
```
users
  │
  └──< documents
          │
          ├──< purpose_analyses
          │
          ├──< pii_entities
          │       │
          │       └──< risk_predictions
          │
          ├──< protected_documents
          │
          └──< audit_logs (SHA-256 Hash Chained)

policy_rules (Reference configuration table)
```

### Table Definitions
1. **`users`**: Application user identity metadata (supports demo user: `00000000-0000-0000-0000-000000000001`). Passwords are not stored.
2. **`documents`**: Document lifecycle records (`UPLOADED`, `SCANNED`, `ANALYZED`, `PROTECTED`, `FAILED`). Raw OCR text is strictly omitted.
3. **`purpose_analyses`**: Purpose NLP classification (`domain`, `task`, `sub_purpose`, `submission_context`, `intent_confidence`, `ai_model`).
4. **`pii_entities`**: Spatial bounding boxes and policy minimization outcomes. **Strict Data Minimization**: Raw sensitive values (Aadhaar number, phone number, address, DOB) are NEVER stored in the database.
5. **`risk_predictions`**: ML model predictions (`RandomForestClassifier`, `risk_class`, `risk_probability`).
6. **`policy_rules`**: Persistent data minimization policy reference rules.
7. **`protected_documents`**: Metadata, file path, and redaction breakdown for physically masked images.
8. **`audit_logs`**: Chronological event logs with SHA-256 hash chaining for tamper evidence.

---

## 3. Environment Variables Configuration

Create a `.env` file in `InfoShield_AI/` based on `.env.example`:

```bash
# Supabase Project Credentials
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key

# Default Demo User Identifier
DEMO_USER_ID=00000000-0000-0000-0000-000000000001
```

> **Security Mandate**: Never commit `.env` to git. Ensure `SUPABASE_SERVICE_ROLE_KEY` is restricted strictly to the FastAPI backend and never exposed to client-side code.

---

## 4. Database Setup & Deployment

### Schema Deployment
Execute the SQL script in the Supabase SQL Editor:
```bash
supabase/schema.sql
```
This enables `pgcrypto`, creates all 8 tables, indexes foreign keys, and configures Row-Level Security (RLS) policies.

### Seed Data
Populate reference policy rules and the default demo user:
```bash
supabase/seed.sql
```
Seeds statutory data minimization rules for:
- Aadhaar Card (`college_admission`, `scholarship`, `financial_aid`, `kyc`)
- PAN Card (`job_application`, `kyc`)
- Passport (`visa_application`)

---

## 5. Running the Application & API

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Start FastAPI Server
```bash
python api.py
# Server runs on http://127.0.0.1:8000
# OpenAPI Docs: http://127.0.0.1:8000/docs
```

### Database Health Check
```bash
curl -X GET http://127.0.0.1:8000/api/database/health
```
Response:
```json
{
  "success": true,
  "database": "supabase",
  "status": "connected"
}
```

### Protect a Document (Full Pipeline)
```bash
curl -X POST http://127.0.0.1:8000/api/protect \
  -F "file=@test_images/test_document.png" \
  -F "purpose=I need to submit my Aadhaar to my college for admission and financial aid."
```

### Inspect Document Lifecycle
```bash
curl -X GET http://127.0.0.1:8000/api/documents/<DOCUMENT_UUID>
```

### Inspect User Documents
```bash
curl -X GET http://127.0.0.1:8000/api/users/<USER_UUID>/documents
```

### Inspect Tamper-Evident Audit Trail
```bash
curl -X GET http://127.0.0.1:8000/api/documents/<DOCUMENT_UUID>/audit
```

---

## 6. Tamper-Evident SHA-256 Hash Chaining

Audit logs utilize cryptographic hash chaining:
$$\text{event\_hash} = \text{SHA256}(\text{previous\_hash} \parallel \text{action} \parallel \text{document\_id} \parallel \text{timestamp} \parallel \text{metadata})$$

- The initial event for a document utilizes $\text{previous\_hash} = 0^{64}$ (genesis block).
- Each subsequent event captures the hash of the preceding event, creating an unbroken chain.
- Audit metadata is sanitized to prevent raw sensitive PII storage.

---

## 7. Testing & Verification

Run the automated Pytest test suite (all 40 tests):
```bash
python -m pytest -v
```

Execution breakdown:
- `test_api.py`: Baseline OCR and scan endpoint tests (2 passed)
- `test_purpose_engine.py`: Phase 2 purpose policy tests (8 passed)
- `test_redaction.py`: Phase 3 bounding box and physical image redaction tests (7 passed)
- `test_phase4a_ai.py`: Phase 4A AI semantic classification and ML risk tests (10 passed)
- `test_supabase.py`: Phase 4B Supabase persistence and hash-chain audit tests (13 passed)

### Run Demonstrations
```bash
# Phase 4A Model Specifications CLI
python model_info.py

# Phase 4A OCR + AI Intent + ML Risk Demonstration
python demo_phase4a.py

# Phase 4B Complete Supabase Persistence Demonstration
python demo_phase4b.py
```

---

## 8. Data Minimization & Privacy Rules

1. **No Raw PII Storage**: The `pii_entities` database table stores only the field type (`aadhaar_number`, `mobile_number`), spatial bounding boxes, and policy decisions (`CONDITIONAL`, `UNNECESSARY`). Raw values remain in-memory solely for image masking.
2. **No Raw OCR Storage**: Raw OCR extracted text is omitted from the database to prevent unindexed sensitive exposure.
3. **Graceful Fallback**: If the database is unreachable, image redaction and PII protection continue to function seamlessly without corrupting the user experience.
