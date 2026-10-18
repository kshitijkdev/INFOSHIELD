"""
Pytest Suite for InfoShield Phase 4B: Supabase Database Integration
Validates:
1. Supabase configuration detection (environment inspection)
2. Database health endpoint (GET /api/database/health)
3. Document creation and tracking (no raw OCR text)
4. Purpose analysis persistence
5. PII metadata persistence (strictly zero raw sensitive PII values stored)
6. ML risk prediction persistence
7. Protected document metadata persistence
8. Audit logging with SHA-256 hash chaining
9. Document history endpoint (GET /api/documents/{id})
10. User documents endpoint (GET /api/users/{id}/documents)
11. Audit events endpoint (GET /api/documents/{id}/audit)
12. End-to-end /api/protect with real image and DB persistence
13. Graceful fallback when database is unavailable (pipeline remains intact)
"""

import os
import sys
import json
import uuid
import pytest
from fastapi.testclient import TestClient

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import time
import jwt as pyjwt
import supabase_client
from supabase_service import get_db_service, SupabaseService
from api import app

client = TestClient(app)

TEST_JWT_SECRET = "test-secret-key-for-infoshield-testing-purposes-only-32bytes"
DEMO_USER_ID = "00000000-0000-0000-0000-000000000001"


def get_test_auth_headers(user_id: str = DEMO_USER_ID, role: str = "authenticated") -> dict:
    """Generate valid test JWT auth headers."""
    payload = {
        "sub": user_id,
        "email": "demo.user@infoshield.ai",
        "role": role,
        "aud": "authenticated",
        "exp": time.time() + 3600,
        "iat": time.time()
    }
    token = pyjwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


AUTH_HEADERS = get_test_auth_headers()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if not os.path.isdir(os.path.join(BASE_DIR, "test_images")):
    BASE_DIR = os.path.dirname(BASE_DIR)
TEST_IMAGE_PATH = os.path.join(BASE_DIR, "test_images", "test_document.png")



# ==============================================================================
# IN-MEMORY POSTGREST / SUPABASE MOCK FOR OFFLINE & DETERMINISTIC UNIT TESTING
# ==============================================================================

class MockResponse:
    def __init__(self, data):
        self.data = data


class MockTable:
    def __init__(self, name: str, store: dict):
        self.name = name
        self.store = store
        self._filters = []
        self._pending_insert = None
        self._pending_update = None
        self._order_col = None
        self._order_desc = False
        self._limit_n = None

    def select(self, cols="*"):
        return self

    def eq(self, col, val):
        self._filters.append((col, val))
        return self

    def order(self, col, desc=False):
        self._order_col = col
        self._order_desc = desc
        return self

    def limit(self, n):
        self._limit_n = n
        return self

    def insert(self, record):
        self._pending_insert = record
        return self

    def upsert(self, record):
        self._pending_insert = record
        return self

    def update(self, record):
        self._pending_update = record
        return self

    def execute(self):
        # Handle insert / upsert
        if self._pending_insert is not None:
            raw = self._pending_insert
            records = raw if isinstance(raw, list) else [raw]
            inserted = []
            for r in records:
                row = dict(r)
                if "id" not in row or not row["id"]:
                    row["id"] = str(uuid.uuid4())
                self.store.setdefault(self.name, []).append(row)
                inserted.append(row)
            return MockResponse(inserted)

        # Handle update
        if self._pending_update is not None:
            updated = []
            for r in self.store.get(self.name, []):
                if all(r.get(c) == v for c, v in self._filters):
                    r.update(self._pending_update)
                    updated.append(dict(r))
            return MockResponse(updated)

        # Handle select query with filtering
        rows = [
            dict(r) for r in self.store.get(self.name, [])
            if all(r.get(c) == v for c, v in self._filters)
        ]

        if self._order_col:
            indexed_rows = list(enumerate(rows))
            indexed_rows.sort(
                key=lambda x: (str(x[1].get(self._order_col) or ""), x[0]),
                reverse=self._order_desc
            )
            rows = [item[1] for item in indexed_rows]

        if self._limit_n is not None:
            rows = rows[:self._limit_n]

        return MockResponse(rows)


class MockSupabaseClient:
    def __init__(self):
        self.store = {
            "users": [
                {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "email": "demo.user@infoshield.ai",
                    "name": "InfoShield Demo User"
                }
            ],
            "documents": [],
            "purpose_analyses": [],
            "pii_entities": [],
            "risk_predictions": [],
            "policy_rules": [
                {
                    "id": str(uuid.uuid4()),
                    "document_type": "Aadhaar Card",
                    "purpose_domain": "education",
                    "purpose_task": "college_admission",
                    "pii_type": "aadhaar_number",
                    "decision": "CONDITIONAL",
                    "mask_strategy": "LAST_4",
                    "reason": "Database policy rule: Full UID exposure unnecessary."
                }
            ],
            "protected_documents": [],
            "audit_logs": []
        }

    def table(self, table_name: str):
        return MockTable(table_name, self.store)


@pytest.fixture(autouse=True)
def setup_mock_db():
    """Injects in-memory mock client for each test, then resets."""
    mock = MockSupabaseClient()
    supabase_client.set_override_client(mock)
    yield mock
    supabase_client.reset_client()


# ==============================================================================
# 1. CONFIGURATION DETECTION & HEALTH
# ==============================================================================

def test_supabase_configuration_detection(setup_mock_db):
    assert supabase_client.is_configured() is True

    # Temporarily remove override and test unconfigured state
    supabase_client.set_override_client(None)
    # When SUPABASE_URL is empty, is_configured returns False
    original_url = supabase_client.SUPABASE_URL
    supabase_client.SUPABASE_URL = ""
    assert supabase_client.is_configured() is False
    supabase_client.SUPABASE_URL = original_url


def test_database_health_endpoint(setup_mock_db):
    resp = client.get("/api/database/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["database"] == "supabase"
    assert data["status"] in ["connected", "unavailable"]


# ==============================================================================
# 2. DOCUMENT CREATION & TRACKING
# ==============================================================================

def test_document_creation(setup_mock_db):
    db_service = get_db_service()
    doc_id = db_service.create_document(
        user_id="00000000-0000-0000-0000-000000000001",
        original_filename="sample_id.png",
        document_type="Aadhaar Card",
        file_size=1024,
        document_hash="abc123hash",
        ocr_engine="Tesseract",
        ocr_confidence=92.5,
        status="SCANNED"
    )
    assert doc_id is not None
    # Verify in mock store
    docs = setup_mock_db.store["documents"]
    assert len(docs) == 1
    doc = docs[0]
    assert doc["id"] == doc_id
    assert doc["original_filename"] == "sample_id.png"
    assert doc["ocr_engine"] == "Tesseract"
    # STRICT DATA MINIMIZATION: Raw OCR text is not in table columns
    assert "raw_ocr_text" not in doc
    assert "text" not in doc


# ==============================================================================
# 3. PURPOSE ANALYSIS PERSISTENCE
# ==============================================================================

def test_purpose_analysis_persistence(setup_mock_db):
    db_service = get_db_service()
    doc_id = str(uuid.uuid4())
    analysis_id = db_service.create_purpose_analysis(
        document_id=doc_id,
        purpose_text="I need this for college admission and financial aid.",
        domain="education",
        task="college_admission",
        sub_purpose="financial_aid",
        submission_context="college",
        intent_confidence=0.95,
        ai_model="sklearn-tfidf-semantic-vector-space"
    )
    assert analysis_id is not None
    analyses = setup_mock_db.store["purpose_analyses"]
    assert len(analyses) == 1
    assert analyses[0]["domain"] == "education"
    assert analyses[0]["task"] == "college_admission"
    assert analyses[0]["sub_purpose"] == "financial_aid"
    assert analyses[0]["intent_confidence"] == 0.95


# ==============================================================================
# 4. PII METADATA PERSISTENCE & ZERO RAW PII SECURITY CHECK
# ==============================================================================

def test_pii_metadata_persistence_no_raw_values(setup_mock_db):
    db_service = get_db_service()
    doc_id = str(uuid.uuid4())

    requirements = [
        {
            "type": "aadhaar_number",
            "value": "8141 5978 8449",  # Raw value in memory only
            "confidence": 0.95,
            "decision": "CONDITIONAL",
            "action": "PARTIAL_MASK",
            "risk": {
                "class": "HIGH",
                "probability": 0.88,
                "model": "RandomForestClassifier",
                "version": "prototype-1"
            },
            "bbox": {"x": 100, "y": 200, "width": 300, "height": 30}
        },
        {
            "type": "mobile_number",
            "value": "9954018168",
            "confidence": 0.90,
            "decision": "UNNECESSARY",
            "action": "FULL_MASK",
            "risk": {
                "class": "HIGH",
                "probability": 0.92,
                "model": "RandomForestClassifier",
                "version": "prototype-1"
            },
            "bbox": {"x": 100, "y": 250, "width": 120, "height": 20}
        }
    ]

    entity_ids = db_service.create_pii_entities_and_risks(doc_id, requirements)
    assert len(entity_ids) == 2

    # Verify rows in pii_entities table
    entities = setup_mock_db.store["pii_entities"]
    assert len(entities) == 2

    for e in entities:
        # STRICT PRIVACY RULE: Never store raw numbers / values
        assert "value" not in e
        assert "raw_value" not in e
        assert "8141 5978 8449" not in json.dumps(e)
        assert "9954018168" not in json.dumps(e)
        # Spatial bbox and classification metadata must be present
        assert e["bbox_x"] == 100
        assert e["decision"] in ["CONDITIONAL", "UNNECESSARY"]
        assert e["action"] in ["PARTIAL_MASK", "FULL_MASK"]


# ==============================================================================
# 5. RISK PREDICTION PERSISTENCE
# ==============================================================================

def test_risk_prediction_persistence(setup_mock_db):
    db_service = get_db_service()
    doc_id = str(uuid.uuid4())
    requirements = [
        {
            "type": "person_name",
            "confidence": 0.99,
            "decision": "REQUIRED",
            "action": "PRESERVED",
            "risk": {
                "class": "LOW",
                "probability": 0.96,
                "model": "RandomForestClassifier",
                "version": "prototype-1"
            }
        }
    ]
    entity_ids = db_service.create_pii_entities_and_risks(doc_id, requirements)
    assert len(entity_ids) == 1

    risk_rows = setup_mock_db.store["risk_predictions"]
    assert len(risk_rows) == 1
    assert risk_rows[0]["pii_entity_id"] == entity_ids[0]
    assert risk_rows[0]["risk_class"] == "LOW"
    assert risk_rows[0]["risk_probability"] == 0.96
    assert risk_rows[0]["model_name"] == "RandomForestClassifier"


# ==============================================================================
# 6. PROTECTED DOCUMENT PERSISTENCE
# ==============================================================================

def test_protected_document_persistence(setup_mock_db):
    db_service = get_db_service()
    doc_id = str(uuid.uuid4())
    prot_id = db_service.create_protected_document(
        document_id=doc_id,
        protected_filename="protected_doc123.png",
        protected_path="/outputs/protected_doc123.png",
        protection_status="PROTECTED",
        total_detected=8,
        fully_redacted=3,
        partially_redacted=2,
        preserved=3,
        protection_summary={"preserved": 3, "partially_redacted": 2, "fully_redacted": 3}
    )
    assert prot_id is not None
    prot_rows = setup_mock_db.store["protected_documents"]
    assert len(prot_rows) == 1
    p = prot_rows[0]
    assert p["protected_filename"] == "protected_doc123.png"
    assert p["total_detected"] == 8
    assert p["fully_redacted"] == 3


# ==============================================================================
# 7. AUDIT LOGGING WITH SHA-256 HASH CHAINING
# ==============================================================================

def test_audit_log_hash_chain(setup_mock_db):
    db_service = get_db_service()
    doc_id = str(uuid.uuid4())
    user_id = "00000000-0000-0000-0000-000000000001"

    # Event 1: Genesis event
    id1 = db_service.create_audit_log(
        user_id=user_id,
        document_id=doc_id,
        action="DOCUMENT_UPLOADED",
        metadata={"filename": "test.png"}
    )
    assert id1 is not None

    logs = setup_mock_db.store["audit_logs"]
    assert len(logs) == 1
    first_event = logs[0]
    assert first_event["previous_hash"] == "0000000000000000000000000000000000000000000000000000000000000000"
    assert len(first_event["event_hash"]) == 64

    # Event 2: OCR Completed (should link to event 1's event_hash)
    id2 = db_service.create_audit_log(
        user_id=user_id,
        document_id=doc_id,
        action="OCR_COMPLETED",
        metadata={"ocr_engine": "Tesseract"}
    )
    assert id2 is not None
    assert len(logs) == 2
    second_event = logs[1]
    assert second_event["previous_hash"] == first_event["event_hash"]
    assert len(second_event["event_hash"]) == 64
    assert second_event["event_hash"] != first_event["event_hash"]


# ==============================================================================
# 8. RETRIEVAL ENDPOINTS (DOCUMENT, USER DOCUMENTS, AUDIT)
# ==============================================================================

def test_document_history_endpoint(setup_mock_db):
    db_service = get_db_service()
    doc_id = str(uuid.uuid4())
    setup_mock_db.store["documents"].append({
        "id": doc_id,
        "user_id": "00000000-0000-0000-0000-000000000001",
        "original_filename": "history_test.png",
        "document_type": "Aadhaar Card",
        "mime_type": "image/png",
        "status": "PROTECTED",
        "created_at": "2026-10-06T00:00:00Z"
    })

    resp = client.get(f"/api/documents/{doc_id}", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["document"]["id"] == doc_id
    assert data["document"]["original_filename"] == "history_test.png"


def test_user_documents_endpoint(setup_mock_db):
    user_id = "00000000-0000-0000-0000-000000000001"
    setup_mock_db.store["documents"].append({
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "original_filename": "user_doc.png",
        "document_type": "PAN Card",
        "mime_type": "image/png",
        "file_size": 2048,
        "status": "UPLOADED",
        "created_at": "2026-10-06T00:00:00Z",
        "updated_at": "2026-10-06T00:00:00Z"
    })

    resp = client.get(f"/api/users/{user_id}/documents", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["count"] >= 1
    assert data["documents"][0]["user_id"] == user_id


def test_audit_endpoint(setup_mock_db):
    doc_id = str(uuid.uuid4())
    # Register document under the requesting user so ownership check passes
    setup_mock_db.store["documents"].append({
        "id": doc_id,
        "user_id": "00000000-0000-0000-0000-000000000001",
        "original_filename": "audit_doc.png",
        "document_type": "Aadhaar Card",
        "mime_type": "image/png",
        "status": "PROTECTED",
        "created_at": "2026-10-06T00:00:00Z"
    })
    db_service = get_db_service()
    db_service.create_audit_log(
        user_id="00000000-0000-0000-0000-000000000001",
        document_id=doc_id,
        action="DOCUMENT_UPLOADED"
    )
    db_service.create_audit_log(
        user_id="00000000-0000-0000-0000-000000000001",
        document_id=doc_id,
        action="DOCUMENT_PROTECTED"
    )

    resp = client.get(f"/api/documents/{doc_id}/audit", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    events = resp.json()
    assert isinstance(events, list)
    assert len(events) == 2
    assert events[0]["action"] == "DOCUMENT_UPLOADED"
    assert events[1]["action"] == "DOCUMENT_PROTECTED"


# ==============================================================================
# 9. END-TO-END POST /api/protect PIPELINE WITH DATABASE PERSISTENCE
# ==============================================================================

def test_api_protect_with_database_persistence(setup_mock_db):
    assert os.path.isfile(TEST_IMAGE_PATH), f"Test image missing: {TEST_IMAGE_PATH}"
    purpose = "I need to submit my Aadhaar to my college for admission and financial aid."

    with open(TEST_IMAGE_PATH, "rb") as f:
        resp = client.post(
            "/api/protect",
            files={"file": ("test_document.png", f, "image/png")},
            data={"purpose": purpose},
            headers=AUTH_HEADERS
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "database" in data
    assert data["database"]["status"] == "CONNECTED"
    doc_id = data["database"]["document_id"]
    assert doc_id is not None
    assert data["database"]["audit_events_recorded"] >= 5

    # Verify that records were saved into the database tables
    assert len(setup_mock_db.store["documents"]) >= 1
    assert len(setup_mock_db.store["purpose_analyses"]) >= 1
    assert len(setup_mock_db.store["pii_entities"]) >= 1
    assert len(setup_mock_db.store["risk_predictions"]) >= 1
    assert len(setup_mock_db.store["protected_documents"]) >= 1
    assert len(setup_mock_db.store["audit_logs"]) >= 5


# ==============================================================================
# 10. GRACEFUL FALLBACK WHEN DATABASE IS UNAVAILABLE
# ==============================================================================

def test_api_protect_graceful_fallback_when_db_unavailable():
    # Remove mock client so database is unconfigured
    supabase_client.set_override_client(None)

    assert os.path.isfile(TEST_IMAGE_PATH)
    purpose = "I need to submit my Aadhaar to my college for admission and financial aid."

    with open(TEST_IMAGE_PATH, "rb") as f:
        resp = client.post(
            "/api/protect",
            files={"file": ("test_document.png", f, "image/png")},
            data={"purpose": purpose},
            headers=AUTH_HEADERS
        )

    # Core document protection must NOT fail even if DB is unavailable
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["document"]["protected_url"] is not None
    assert "database" in data
    # Database status is reported cleanly without breaking the response
    assert data["database"]["status"] in ["UNAVAILABLE", "CONNECTED"]

