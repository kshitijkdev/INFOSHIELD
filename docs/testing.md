# InfoShield — Testing & Verification Guide

This document covers the automated testing strategy, test suites, synthetic fixtures, and end-to-end verification procedures for the InfoShield platform.

---

## 1. Automated Test Suite Breakdown

InfoShield contains **45 comprehensive automated tests** run via `pytest`.

| Test Suite | File | Tests | Coverage Scope |
|---|---|:---:|---|
| **API Endpoints** | `tests/test_api.py` | 2 | Health endpoints, OpenAPI schema validation. |
| **Purpose AI & ML Risk** | `tests/test_phase4a_ai.py` | 10 | AI domain/task extraction, RandomForest risk model prediction, confidence scoring, explainability structures. |
| **Necessity Engine** | `tests/test_purpose_engine.py` | 8 | Data minimization rules (`REQUIRED`, `CONDITIONAL`, `UNNECESSARY`), keyword fallbacks, document type classifiers. |
| **Physical Redaction** | `tests/test_redaction.py` | 12 | Coordinate transformations, expanded Gaussian text blur, opaque QR pixelation, coordinate clamping, and disk writes. |
| **Supabase Persistence** | `tests/test_supabase.py` | 13 | 7-step PostgreSQL database operations, entity & risk persistence, audit logs, and graceful offline fallback (`UNAVAILABLE`). |
| **Total** | | **45** | **100% Passing** |

---

## 2. Test Fixtures (Synthetic & Non-Sensitive)

InfoShield tests use non-sensitive synthetic specimens in `test_images/`:
1. `test_document.png`: Synthetic Aadhaar card containing synthetic dummy demographic details and a generated scannable QR code.
2. `pan_sample.png`: Synthetic PAN card specimen.
3. `clean_syllabus.png`: Academic document with zero PII to test safe negative classification.

> [!NOTE]
> Never use or commit real persons' identity documents. Always generate or use synthetic fixtures.

---

## 3. Running the Tests

### 3.1 Backend Test Suite (Pytest)
From the `backend/` directory:
```powershell
python -m pytest
```

To run with verbose output:
```powershell
python -m pytest -v
```

To run a specific test suite:
```powershell
python -m pytest tests/test_redaction.py -v
```

---

## 4. End-to-End System Verification

The end-to-end verification script simulates the complete user journey:
1. Pings `GET /api/health` and `GET /api/database/health`.
2. Packages synthetic `test_document.png` into a `FormData` payload with natural-language purpose.
3. Submits `POST /api/protect`.
4. Verifies OCR accuracy, PII detection, AI purpose domain classification, ML risk scores, and 7-step Supabase audit logging.
5. Downloads the generated protected image from `GET /api/protected/{filename}` and asserts non-zero image size.

Run the verification script:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify_system.ps1
```
