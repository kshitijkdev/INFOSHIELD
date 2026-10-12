# InfoShield — System Architecture

InfoShield is a purpose-based PII (Personally Identifiable Information) exposure prevention and data minimization platform. It enables individuals and organizations to submit identity documents while automatically concealing unnecessary sensitive fields according to the specific, natural-language purpose of submission.

---

## 1. High-Level Architecture Overview

```
[ User Browser ]
       │
       │  1. Multipart Upload (Document Image + Natural-Language Purpose)
       ▼
[ FastAPI Backend (api.py) ]
       │
       ├─────────────────────────────────────────┐
       ▼                                         ▼
[ OCR Engine (Tesseract) ]               [ QR Code Detector (OpenCV) ]
       │                                         │
       └───────────────────┬─────────────────────┘
                           ▼
               [ PII Detector Engine ]
              (Extracts PII & Bounding Boxes)
                           │
                           ▼
               [ Purpose AI Analyzer ]
             (Semantic Intent & Sub-Context)
                           │
                           ▼
            [ Policy Necessity Engine ]
         (REQUIRED / CONDITIONAL / UNNECESSARY)
                           │
                           ▼
            [ ML Exposure-Risk Model ]
         (RandomForest Risk Classification)
                           │
                           ▼
            [ Image Redaction Engine ]
         (Gaussian Blur & QR Pixelation)
                           │
                           ├─────────────────────────────────┐
                           ▼                                 ▼
              [ Protected Image Disk Storage ]      [ Supabase PostgreSQL ]
                (outputs/protected_*.png)             (7-Step Persistence)
                           │                                 │
                           └────────────────┬────────────────┘
                                            ▼
                          [ JSON API Response to Frontend ]
                                            │
                                            ▼
                         [ Frontend Result & Comparison UI ]
```

---

## 2. Core Components

### 2.1 Frontend (`frontend/`)
- **Technology**: Pure HTML5, modern CSS3 (Custom Properties, Flexbox, CSS Grid), and Vanilla JavaScript (ES6+).
- **Zero Framework Footprint**: No React, Vue, Angular, Bootstrap, or Tailwind.
- **Workflow Stepper**: 9 seamless responsive screens:
  1. `screen-select`: Document catalog with live search & Web Speech API microphone input.
  2. `screen-upload`: Drag-and-drop file upload & camera snapshot capture.
  3. `screen-scan`: Background OCR progress animation.
  4. `screen-purpose`: Purpose input with character count & Web Speech dictation.
  5. `screen-analysis`: Progress radar communicating with `POST /api/protect`.
  6. `screen-required`: Dynamic necessity checklist with ML risk badges.
  7. `screen-result`: Side-by-side (desktop) / tabbed (mobile) comparison of Original vs. Protected document, with explainability cards and download trigger.
  8. `screen-history`: Client session document protection records.
  9. `screen-profile`: User privacy preferences and security settings.

### 2.2 Backend (`backend/`)
- **Technology**: Python 3.11, FastAPI, Uvicorn ASGI.
- **Engines**:
  - `ocr_engine.py`: Tesseract OCR with coordinate scaling and OpenCV `QRCodeDetector` fallback.
  - `pii_detector.py`: RegEx and heuristic document parser extracting Name, DOB, Gender, Mobile, Aadhaar, PAN, Address, and QR codes.
  - `purpose_ai.py`: Semantic purpose interpretation identifying submission context, institutional domain, and granular task.
  - `purpose_engine.py`: Data minimization rules classifying detected PII as `REQUIRED`, `CONDITIONAL`, or `UNNECESSARY`.
  - `risk_model.py`: Trained scikit-learn `RandomForestClassifier` assessing exposure vulnerability probability and risk class (`LOW`, `MEDIUM`, `HIGH`).
  - `redaction_engine.py`: Physical image processing using OpenCV Gaussian blur over expanded bounding boxes (for text) and strong opaque pixelation (for QR matrices).
  - `supabase_service.py`: 7-step transactional persistence with audit logging into Supabase PostgreSQL.

### 2.3 Database (`database/`)
- **Technology**: Supabase PostgreSQL with Row Level Security (RLS).
- **Core Entities**:
  - `users`: Registered and demo client profiles.
  - `documents`: Document ingestion metadata and hashes.
  - `purpose_analyses`: Semantic domain, task, intent scores.
  - `pii_entities`: Detected PII fields, sensitivity levels, coordinates.
  - `risk_predictions`: RandomForest exposure-risk metrics.
  - `protected_documents`: Output image metadata and redaction statistics.
  - `audit_logs`: Immutable audit trail for every pipeline transition.
  - `policy_rules`: Default organizational baseline rules.

---

## 3. Physical Redaction Mechanics

Unlike systems that draw superficial CSS overlays or client-side masks, InfoShield performs **physical pixel alteration**:
1. **Coordinate Transformation**: OCR coordinates are dynamically mapped back to original image dimensions via scale ratio calculation.
2. **Expansion & Clamping**: Text bounding boxes receive adaptive padding to guarantee edge character concealment while clamping within image bounds.
3. **Multi-Stage Privacy Blur**: Area downsampling combined with high-kernel Gaussian blur destroys OCR glyph recognition while retaining the document's original background tone and texture.
4. **Opaque QR Pixelation**: QR codes undergo irreversible cell destruction to eliminate biometric and cryptographic payload extraction by third parties.
5. **Disk Write**: The resulting pixel matrix is written directly to disk (`outputs/`) and served via protected endpoints.

---

## 4. Privacy & Zero-Trust Principles

1. **Zero Secret Leaks**: Database service-role credentials and API keys remain exclusively backend-side within `.env`.
2. **No Terminal/Console Dumps**: Sensitive raw PII values and unredacted documents are never written to browser consoles or client storage.
3. **Data Minimization Default**: Any detected field not strictly mandated by the stated submission purpose is redacted by default.
