"""
Test Suite for InfoShield OCR FastAPI Service
Tests:
1. GET /api/health
2. POST /api/scan with actual test image (test_images/test_document.png)
Verifies:
- Health response structure
- Scan response structure
- Real OCR text and unmasked PII entities:
  Name, DOB, Gender, Mobile, Aadhaar, VID, Address
"""

import os
import sys
import json
from fastapi.testclient import TestClient

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api import app

client = TestClient(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if not os.path.isdir(os.path.join(BASE_DIR, "test_images")):
    BASE_DIR = os.path.dirname(BASE_DIR)
TEST_IMAGE_PATH = os.path.join(BASE_DIR, "test_images", "test_document.png")


def test_health_endpoint():
    print("\n" + "=" * 60)
    print("TEST 1: GET /api/health")
    print("=" * 60)
    response = client.get("/api/health")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")

    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    assert data["status"] == "ok", f"Expected status 'ok', got {data.get('status')}"
    assert data["service"] == "InfoShield OCR", f"Expected service 'InfoShield OCR', got {data.get('service')}"
    print("✓ Health check PASSED!\n")


def test_scan_endpoint():
    print("=" * 60)
    print("TEST 2: POST /api/scan (with test_images/test_document.png)")
    print("=" * 60)

    if not os.path.exists(TEST_IMAGE_PATH):
        print(f"[ERROR] Test image not found at {TEST_IMAGE_PATH}")
        sys.exit(1)

    with open(TEST_IMAGE_PATH, "rb") as f:
        response = client.post(
            "/api/scan",
            files={"file": ("test_document.png", f, "image/png")}
        )

    print(f"Status Code: {response.status_code}")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

    data = response.json()
    print("\nAPI Response Structure:")
    print(json.dumps(data, indent=2))

    # Top-level field assertions
    assert data.get("success") is True, "Expected success: true"
    assert "document" in data, "Missing 'document' field"
    assert "ocr" in data, "Missing 'ocr' field"
    assert "pii" in data, "Missing 'pii' field"
    assert "raw_text" in data, "Missing 'raw_text' field"

    assert data["ocr"]["engine"] == "Tesseract", "OCR engine must be Tesseract"
    assert isinstance(data["ocr"]["confidence"], (int, float)), "Confidence must be a number"

    # Map detected PII fields
    pii_by_type = {item["type"]: item["value"] for item in data["pii"]}
    print("\n" + "-" * 50)
    print("VERIFYING EXTRACTED FIELDS:")
    print("-" * 50)
    fields_to_check = [
        ("person_name", "Name"),
        ("date_of_birth", "DOB"),
        ("gender", "Gender"),
        ("mobile_number", "Mobile"),
        ("aadhaar_number", "Aadhaar"),
        ("vid", "VID"),
        ("address", "Address"),
    ]

    all_matched = True
    for field_key, field_label in fields_to_check:
        val = pii_by_type.get(field_key)
        if val:
            print(f"✓ {field_label:<10} [{field_key}]: {val}")
        else:
            print(f"✕ {field_label:<10} [{field_key}]: NOT DETECTED")
            all_matched = False

    assert "person_name" in pii_by_type, "person_name was not extracted"
    assert "date_of_birth" in pii_by_type, "date_of_birth was not extracted"
    assert "gender" in pii_by_type, "gender was not extracted"
    assert "mobile_number" in pii_by_type, "mobile_number was not extracted"
    assert "aadhaar_number" in pii_by_type, "aadhaar_number was not extracted"
    assert "vid" in pii_by_type, "vid was not extracted"
    assert "address" in pii_by_type, "address was not extracted"

    print("\n✓ ALL REQUIRED FIELDS DETECTED FROM REAL OCR PASS!")


def test_cors_preflight_endpoints():
    print("=" * 60)
    print("TEST 3: CORS OPTIONS Preflight Verification")
    print("=" * 60)

    test_origins = [
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:3000",
        "http://localhost:3000"
    ]

    for origin in test_origins:
        # Preflight on /api/protect
        response = client.options(
            "/api/protect",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            }
        )
        assert response.status_code == 200, f"Expected 200 for preflight from {origin}, got {response.status_code}"
        assert response.headers.get("access-control-allow-origin") == origin, f"Origin {origin} not allowed in preflight"
        assert response.headers.get("access-control-allow-credentials") == "true", "Credentials not allowed"
        allow_methods = response.headers.get("access-control-allow-methods", "")
        assert "POST" in allow_methods or "*" in allow_methods, f"POST method not allowed in preflight: {allow_methods}"
        print(f"✓ CORS preflight allowed for {origin}")

    print("✓ All CORS preflight checks PASSED!\n")


def test_protect_with_cors_headers():
    print("=" * 60)
    print("TEST 4: POST /api/protect from http://127.0.0.1:5500")
    print("=" * 60)

    if not os.path.exists(TEST_IMAGE_PATH):
        print(f"[ERROR] Test image not found at {TEST_IMAGE_PATH}")
        sys.exit(1)

    origin = "http://127.0.0.1:5500"
    with open(TEST_IMAGE_PATH, "rb") as f:
        response = client.post(
            "/api/protect",
            data={"purpose": "Identity verification for college admission"},
            files={"file": ("test_document.png", f, "image/png")},
            headers={"Origin": origin}
        )

    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    assert response.headers.get("access-control-allow-origin") == origin, f"CORS header missing in POST response for {origin}"
    
    data = response.json()
    assert data.get("success") is True
    assert "document" in data
    assert "protected_url" in data["document"]
    assert "requirements" in data
    print(f"✓ Protected document generated: {data['document']['protected_filename']}")
    print(f"✓ CORS origin preserved in response: {response.headers.get('access-control-allow-origin')}")
    print("✓ Document analysis and protection flow PASSED with CORS!\n")


if __name__ == "__main__":
    try:
        test_health_endpoint()
        test_cors_preflight_endpoints()
        test_protect_with_cors_headers()
        test_scan_endpoint()
        print("\n" + "=" * 60)
        print("ALL TESTS PASSED SUCCESSFULLY!")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n[TEST FAILED]: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[UNEXPECTED ERROR]: {e}")
        sys.exit(1)
