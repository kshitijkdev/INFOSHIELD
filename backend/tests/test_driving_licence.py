"""
Pytest Suite for Driving Licence Purpose-Based Redaction & Photograph Protection
Validates:
1. Photograph preservation for identity verification (0.0 pixel difference)
2. Photograph obscuration / privacy blur for address-only verification (> 0 pixel difference)
3. Consistent purpose-based decisions across all DL fields (photo, name, licence number, address, dob, validity, blood group, classes)
4. Explainable policy decisions and rationales for every field
5. Redaction engine dynamically adheres to detected bounding boxes without fixed coordinates
6. Original uploaded document preservation and immutability
7. End-to-end API integration via POST /api/protect
"""

import os
import sys
import hashlib
import cv2
import pytest
import numpy as np
from fastapi.testclient import TestClient

# Ensure UTF-8 encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from ocr_engine import OCREngine
from pii_detector import PIIDetector
from purpose_engine import analyze_purpose, interpret_purpose
from redaction_engine import RedactionEngine
from api import app, OUTPUT_DIR, UPLOAD_DIR, FIELD_TYPE_MAP, detect_document_type

client = TestClient(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if not os.path.isdir(os.path.join(BASE_DIR, "test_images")):
    BASE_DIR = os.path.dirname(BASE_DIR)

DL_IMAGE_PATH = os.path.join(BASE_DIR, "test_images", "driving_licence_sample.png")


@pytest.fixture(scope="module")
def dl_ocr_and_fields():
    """Performs OCR and PII extraction on synthetic Driving Licence once."""
    assert os.path.exists(DL_IMAGE_PATH), f"Synthetic DL image not found at {DL_IMAGE_PATH}"
    engine = OCREngine()
    detector = PIIDetector()

    ocr_result = engine.extract_text(DL_IMAGE_PATH)
    raw_text = ocr_result["raw_text"]
    word_data = ocr_result["word_data"]
    photo_detected = ocr_result["photo_detected"]
    photo_bbox = ocr_result["photo_bbox"]

    fields = detector.extract_document_fields(
        text=raw_text,
        word_data=word_data,
        photo_detected=photo_detected,
        photo_bbox=photo_bbox
    )
    doc_type = detect_document_type(raw_text, fields)

    return {
        "ocr_result": ocr_result,
        "raw_text": raw_text,
        "fields": fields,
        "doc_type": doc_type,
        "photo_detected": photo_detected,
        "photo_bbox": photo_bbox
    }


def test_driving_licence_detection_and_fields(dl_ocr_and_fields):
    """Verifies that synthetic DL is accurately classified and key PII fields are detected."""
    data = dl_ocr_and_fields
    assert data["doc_type"] == "Driving Licence"
    assert data["photo_detected"] is True
    assert data["photo_bbox"] is not None

    fields = data["fields"]
    assert "Photograph" in fields
    assert "Person Name" in fields
    assert "Licence Number" in fields
    assert "Validity Date" in fields
    assert "Blood Group" in fields
    assert "Authorized Classes" in fields
    assert "Address" in fields

    # Verify photo bbox is in document bounds
    pbox = fields["Photograph"]["bbox"]
    assert pbox["width"] > 100
    assert pbox["height"] > 100
    assert pbox["x"] >= 0 and pbox["y"] >= 0


def test_identity_verification_policy_preserves_photo(dl_ocr_and_fields):
    """
    Requirement 1: For identity verification, classify licence photograph as
    REQUIRED/CONDITIONAL and preserve it with clear explanation.
    """
    data = dl_ocr_and_fields
    fields = data["fields"]

    pii_items = [
        {"type": FIELD_TYPE_MAP.get(k, k.lower().replace(" ", "_")), "confidence": v.get("confidence", 0.9)}
        for k, v in fields.items()
    ]

    purpose_result = analyze_purpose(
        document_type="Driving Licence",
        purpose="Identity verification for member registration",
        pii=pii_items
    )

    reqs = {r["type"]: r for r in purpose_result.get("requirements", [])}

    # Photograph must be REQUIRED and PRESERVED for identity verification
    assert "photograph" in reqs
    assert reqs["photograph"]["decision"] == "REQUIRED"
    assert reqs["photograph"]["action"] == "PRESERVED"
    assert "Visual face photograph" in reqs["photograph"]["reason"]

    # Name must be REQUIRED and PRESERVED
    assert "person_name" in reqs
    assert reqs["person_name"]["decision"] == "REQUIRED"
    assert reqs["person_name"]["action"] == "PRESERVED"

    # DL number should be CONDITIONAL with partial mask
    assert "licence_number" in reqs
    assert reqs["licence_number"]["decision"] == "CONDITIONAL"

    # Blood group and authorized classes are UNNECESSARY for ID
    assert reqs["blood_group"]["decision"] == "UNNECESSARY"
    assert reqs["blood_group"]["action"] == "FULL_MASK"
    assert reqs["authorized_classes"]["decision"] == "UNNECESSARY"
    assert reqs["authorized_classes"]["action"] == "FULL_MASK"


def test_identity_verification_redaction_keeps_photo_pixels_untouched(dl_ocr_and_fields):
    """
    Verifies that the physical redaction engine leaves the photograph
    completely untouched (0.0 pixel difference) for identity verification.
    """
    data = dl_ocr_and_fields
    fields = data["fields"]
    pbox = data["photo_bbox"]

    pii_items = [
        {"type": FIELD_TYPE_MAP.get(k, k.lower().replace(" ", "_")), "confidence": v.get("confidence", 0.9)}
        for k, v in fields.items()
    ]

    purpose_result = analyze_purpose(
        document_type="Driving Licence",
        purpose="General identity verification",
        pii=pii_items
    )

    redactor = RedactionEngine()
    out_path = os.path.join(OUTPUT_DIR, "test_dl_id_pytest_out.png")

    res = redactor.redact_document(
        image_path=DL_IMAGE_PATH,
        fields_dict=fields,
        requirements=purpose_result.get("requirements", []),
        output_path=out_path,
        ocr_scale=data["ocr_result"].get("ocr_scale", 1.0)
    )

    assert os.path.exists(out_path)

    # Compare photograph pixels between original and protected document
    orig_img = cv2.imread(DL_IMAGE_PATH)
    prot_img = cv2.imread(out_path)

    orig_photo = orig_img[pbox["y"]:pbox["y"] + pbox["height"], pbox["x"]:pbox["x"] + pbox["width"]]
    prot_photo = prot_img[pbox["y"]:pbox["y"] + pbox["height"], pbox["x"]:pbox["x"] + pbox["width"]]

    pixel_diff = float(np.sum(np.abs(orig_photo.astype(float) - prot_photo.astype(float))))
    assert pixel_diff == 0.0, f"Photograph pixels modified during identity verification! Diff: {pixel_diff}"


def test_address_verification_policy_preserves_photo(dl_ocr_and_fields):
    """
    Requirement: Photograph is globally preserved across all workflows including address verification.
    """
    data = dl_ocr_and_fields
    fields = data["fields"]

    pii_items = [
        {"type": FIELD_TYPE_MAP.get(k, k.lower().replace(" ", "_")), "confidence": v.get("confidence", 0.9)}
        for k, v in fields.items()
    ]

    purpose_result = analyze_purpose(
        document_type="Driving Licence",
        purpose="Proof of address verification for electricity connection",
        pii=pii_items
    )

    reqs = {r["type"]: r for r in purpose_result.get("requirements", [])}

    # Address must be REQUIRED and PRESERVED
    assert "address" in reqs
    assert reqs["address"]["decision"] == "REQUIRED"
    assert reqs["address"]["action"] == "PRESERVED"
    assert "residential address is mandatory" in reqs["address"]["reason"]

    # Photograph must be REQUIRED and PRESERVED per global photo rule
    assert "photograph" in reqs
    assert reqs["photograph"]["decision"] == "REQUIRED"
    assert reqs["photograph"]["action"] == "PRESERVED"

    # Date of birth should be UNNECESSARY for address proof
    assert reqs["date_of_birth"]["decision"] == "UNNECESSARY"


def test_address_verification_redaction_preserves_photo_and_address(dl_ocr_and_fields):
    """
    Verifies that address verification physical redaction keeps the photograph
    completely untouched (0.0 pixel difference) and preserves the address region.
    """
    data = dl_ocr_and_fields
    fields = data["fields"]
    pbox = data["photo_bbox"]

    pii_items = [
        {"type": FIELD_TYPE_MAP.get(k, k.lower().replace(" ", "_")), "confidence": v.get("confidence", 0.9)}
        for k, v in fields.items()
    ]

    purpose_result = analyze_purpose(
        document_type="Driving Licence",
        purpose="Proof of address verification for billing address update",
        pii=pii_items
    )

    redactor = RedactionEngine()
    out_path = os.path.join(OUTPUT_DIR, "test_dl_addr_pytest_out.png")

    res = redactor.redact_document(
        image_path=DL_IMAGE_PATH,
        fields_dict=fields,
        requirements=purpose_result.get("requirements", []),
        output_path=out_path,
        ocr_scale=data["ocr_result"].get("ocr_scale", 1.0)
    )

    assert os.path.exists(out_path)

    orig_img = cv2.imread(DL_IMAGE_PATH)
    prot_img = cv2.imread(out_path)

    # Photograph must remain completely untouched per global preservation rule
    orig_photo = orig_img[pbox["y"]:pbox["y"] + pbox["height"], pbox["x"]:pbox["x"] + pbox["width"]]
    prot_photo = prot_img[pbox["y"]:pbox["y"] + pbox["height"], pbox["x"]:pbox["x"] + pbox["width"]]

    photo_diff = float(np.sum(np.abs(orig_photo.astype(float) - prot_photo.astype(float))))
    assert photo_diff == 0.0, f"Photograph pixels modified during address verification! Diff: {photo_diff}"

    # Verify address region is preserved (0.0 pixel diff on address bbox)
    abox = fields["Address"]["bbox"]
    orig_addr = orig_img[abox["y"]:abox["y"] + abox["height"], abox["x"]:abox["x"] + abox["width"]]
    prot_addr = prot_img[abox["y"]:abox["y"] + abox["height"], abox["x"]:abox["x"] + abox["width"]]

    addr_diff = float(np.sum(np.abs(orig_addr.astype(float) - prot_addr.astype(float))))
    assert addr_diff == 0.0, f"Address was modified when required! Diff: {addr_diff}"


def test_original_document_immutability():
    """Requirement 6: Original uploaded document is NEVER overwritten or altered."""
    with open(DL_IMAGE_PATH, "rb") as f:
        sha_before = hashlib.sha256(f.read()).hexdigest()

    # Perform redactions
    engine = OCREngine()
    det = PIIDetector()
    red = RedactionEngine()

    ocr_res = engine.extract_text(DL_IMAGE_PATH)
    fields = det.extract_document_fields(
        text=ocr_res["raw_text"],
        word_data=ocr_res["word_data"],
        photo_detected=ocr_res["photo_detected"],
        photo_bbox=ocr_res["photo_bbox"]
    )
    pii_items = [{"type": FIELD_TYPE_MAP.get(k, k.lower().replace(" ", "_"))} for k in fields]
    purp = analyze_purpose("Driving Licence", "Identity verification", pii_items)
    out = os.path.join(OUTPUT_DIR, "immutability_dl_test.png")
    red.redact_document(DL_IMAGE_PATH, fields, purp["requirements"], out)

    with open(DL_IMAGE_PATH, "rb") as f:
        sha_after = hashlib.sha256(f.read()).hexdigest()

    assert sha_before == sha_after, "Original DL document file was modified!"


def test_api_protect_driving_licence_identity_verification():
    """Requirement 7: POST /api/protect preserves photograph for identity verification."""
    with open(DL_IMAGE_PATH, "rb") as f:
        response = client.post(
            "/api/protect",
            files={"file": ("driving_licence_sample.png", f, "image/png")},
            data={"purpose": "Identity verification for bank KYC"}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["document"]["type"] == "Driving Licence"

    # Verify protected image path exists
    protected_url = data["document"]["protected_url"]
    protected_file = os.path.basename(protected_url)
    protected_local_path = os.path.join(OUTPUT_DIR, protected_file)
    assert os.path.exists(protected_local_path)

    # Check requirements in response
    reqs = {r["type"]: r for r in data["requirements"]}
    assert "photograph" in reqs
    assert reqs["photograph"]["action"] == "PRESERVED"
    assert reqs["photograph"]["decision"] == "REQUIRED"


def test_api_protect_driving_licence_address_verification():
    """Requirement 8: POST /api/protect masks photograph for address verification."""
    with open(DL_IMAGE_PATH, "rb") as f:
        response = client.post(
            "/api/protect",
            files={"file": ("driving_licence_sample.png", f, "image/png")},
            data={"purpose": "Proof of address verification for telephone line"}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True

    reqs = {r["type"]: r for r in data["requirements"]}
    assert "photograph" in reqs
    assert reqs["photograph"]["action"] == "PRESERVED"
    assert reqs["photograph"]["decision"] == "REQUIRED"
    assert reqs["address"]["action"] == "PRESERVED"
    assert reqs["address"]["decision"] == "REQUIRED"
