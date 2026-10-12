# InfoShield — API Reference

Base Server URL: `http://127.0.0.1:8000`

---

## 1. System Health

### `GET /api/health`
Checks the operational status of the FastAPI backend.

**Response `200 OK`**:
```json
{
  "status": "ok",
  "service": "InfoShield OCR"
}
```

---

### `GET /api/database/health`
Checks connectivity to the Supabase PostgreSQL database. Never exposes credentials.

**Response `200 OK`**:
```json
{
  "success": true,
  "database": "supabase",
  "status": "connected"
}
```

---

## 2. Document Scanning & Extraction

### `POST /api/scan`
Uploads a document image, executes Tesseract OCR, detects QR codes, and extracts structured PII.

- **Content-Type**: `multipart/form-data`
- **Body Fields**:
  - `file` (UploadFile, required): An image file (`.png`, `.jpg`, `.jpeg`, `.webp`).

**Response `200 OK`**:
```json
{
  "success": true,
  "document": {
    "filename": "sample_aadhaar.png",
    "type": "Aadhaar Card",
    "qr_detected": true
  },
  "warnings": [],
  "ocr": {
    "engine": "Tesseract",
    "confidence": 91.3
  },
  "pii": [
    {
      "type": "person_name",
      "value": "Aarav Sharma",
      "risk": "LOW",
      "confidence": 0.95,
      "bbox": { "x": 343, "y": 171, "width": 142, "height": 18 }
    }
  ],
  "raw_text": "..."
}
```

---

## 3. Purpose Analysis

### `POST /api/analyze-purpose`
Evaluates natural-language purpose against detected PII entities to determine data necessity.

- **Content-Type**: `application/json`
- **Request Body**:
```json
{
  "document_type": "Aadhaar Card",
  "purpose": "College admission and identity verification",
  "pii": [
    { "type": "person_name", "value": "Aarav Sharma" },
    { "type": "aadhaar_number", "value": "9823 4567 9012" }
  ]
}
```

**Response `200 OK`**:
```json
{
  "success": true,
  "purpose": "College admission and identity verification",
  "domain": "education",
  "task": "college_admission",
  "sub_purpose": "financial_aid",
  "summary": { "required": 1, "conditional": 1, "unnecessary": 0 },
  "requirements": [
    {
      "type": "person_name",
      "decision": "REQUIRED",
      "reason": "Needed to identify the applicant.",
      "action": "PRESERVED",
      "risk": { "class": "LOW", "probability": 0.97 }
    }
  ]
}
```

---

## 4. End-to-End Protection & Redaction

### `POST /api/protect`
The primary production pipeline endpoint. Orchestrates OCR, PII detection, purpose understanding, ML risk scoring, OpenCV pixel redaction, and database persistence in a single operation.

- **Content-Type**: `multipart/form-data`
- **Body Fields**:
  - `file` (UploadFile, required): The document image.
  - `purpose` (string, required): Natural-language submission purpose.
  - `user_id` (string, optional): Specific user UUID (defaults to demo user).

**Response `200 OK`**:
```json
{
  "success": true,
  "document": {
    "original_filename": "test_document.png",
    "protected_filename": "protected_ab1a554f_test_document.png",
    "protected_url": "/api/protected/protected_ab1a554f_test_document.png",
    "type": "Aadhaar Card",
    "qr_detected": true,
    "id": "6af35c8e-566e-4ce2-87dc-f80b866aad36"
  },
  "warnings": [],
  "database": {
    "status": "CONNECTED",
    "document_id": "6af35c8e-566e-4ce2-87dc-f80b866aad36",
    "user_id": "00000000-0000-0000-0000-000000000001",
    "persisted_entities": 8,
    "audit_events_recorded": 7
  },
  "purpose": "College admission and identity verification",
  "intelligence": {
    "purpose_ai": {
      "domain": "education",
      "task": "college_admission",
      "sub_purpose": "financial_aid",
      "confidence": 0.69
    },
    "risk_model": {
      "model": "RandomForestClassifier",
      "version": "prototype-1"
    }
  },
  "decision_summary": {
    "required": 1,
    "conditional": 4,
    "unnecessary": 3
  },
  "requirements": [
    {
      "type": "person_name",
      "decision": "REQUIRED",
      "reason": "Needed to identify the applicant.",
      "action": "PRESERVED",
      "risk": { "class": "LOW", "probability": 0.97 },
      "risk_class": "LOW",
      "risk_probability": 0.97,
      "bbox": { "x": 343, "y": 171, "width": 142, "height": 18 }
    },
    {
      "type": "aadhaar_number",
      "decision": "CONDITIONAL",
      "reason": "The institution may require identity verification, but full exposure should not be assumed necessary.",
      "action": "PARTIAL_MASK",
      "risk": { "class": "HIGH", "probability": 0.79 },
      "risk_class": "HIGH",
      "risk_probability": 0.79,
      "bbox": { "x": 312, "y": 435, "width": 332, "height": 31 }
    }
  ],
  "redactions_applied": [
    {
      "field": "Person Name",
      "action": "PRESERVED",
      "status": "REQUIRED",
      "details": "Untouched per verified necessity",
      "reason": "Needed to identify the applicant."
    },
    {
      "field": "Aadhaar Number",
      "action": "PARTIALLY_REDACTED",
      "status": "CONDITIONAL",
      "details": "Blurred first 8 digits, retained last 4 digits (XXXX XXXX 1234)",
      "reason": "Institution requires reference check only."
    }
  ],
  "stats": {
    "total_detected": 8,
    "fully_redacted": 4,
    "partially_redacted": 2,
    "preserved": 2
  },
  "ocr": {
    "engine": "Tesseract",
    "confidence": 91.3
  }
}
```

---

### `GET /api/protected/{filename}`
Retrieves the physically redacted protected document image.

- **Parameters**: `filename` (path string).
- **Response**: Image byte stream with appropriate MIME type (`image/png`, `image/jpeg`).
- **Status Codes**:
  - `200 OK`: File successfully retrieved.
  - `404 Not Found`: File not found or invalid filename.

---

### `GET /api/documents/{document_id}`
Returns the complete lifecycle audit metadata for a given document UUID. Never returns raw unredacted PII values.

- **Response `200 OK`**: JSON metadata of document analysis and recorded audit events.
