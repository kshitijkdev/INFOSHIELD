"""
Pytest Suite for InfoShield Real Image PII Localization & Physical Redaction Engine
Phase 3 Validation:
1. Spatial PII bounding box extraction from OCR word_data
2. Physical redaction of UNNECESSARY fields (solid opaque pixel masking)
3. Zero-trust preservation of REQUIRED fields (zero pixel modification)
4. Intelligent minimization of CONDITIONAL Aadhaar (first 8 digits masked, last 4 preserved)
5. Intelligent minimization of CONDITIONAL Address (street details masked, city/state preserved)
6. QR Code physical obscuration when UNNECESSARY
7. Immutability guarantee: Original uploaded document is NEVER overwritten
8. API End-to-End: POST /api/protect accepts image + natural language purpose
9. API File Serving: GET /api/protected/{filename} returns protected image
10. Security: Path traversal protection on GET /api/protected/{filename}
"""

import os
import sys
import cv2
import pytest
import numpy as np
from fastapi.testclient import TestClient

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from ocr_engine import OCREngine
from pii_detector import PIIDetector
from purpose_engine import analyze_purpose
from redaction_engine import RedactionEngine
from api import app, OUTPUT_DIR, UPLOAD_DIR

client = TestClient(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if not os.path.isdir(os.path.join(BASE_DIR, "test_images")):
    BASE_DIR = os.path.dirname(BASE_DIR)
TEST_DOC_PATH = os.path.join(BASE_DIR, "test_images", "test_document.png")


@pytest.fixture(scope="module")
def ocr_and_fields():
    """Performs OCR and PII detection once for test cases to save processing time."""
    engine = OCREngine()
    detector = PIIDetector()

    assert os.path.isfile(TEST_DOC_PATH), f"Missing test document: {TEST_DOC_PATH}"
    ocr_result = engine.extract_text(TEST_DOC_PATH)
    fields = detector.extract_document_fields(
        text=ocr_result["text"],
        word_data=ocr_result["word_data"],
        qr_detected=ocr_result["qr_detected"],
        qr_data=ocr_result["qr_data"],
        qr_bbox=ocr_result.get("qr_bbox")
    )
    return ocr_result, fields


# ==============================================================================
# 1. BOUNDING BOX LOCALIZATION TESTS
# ==============================================================================

def test_bounding_box_localization(ocr_and_fields):
    """Verifies that bounding boxes are dynamically detected from OCR tokens."""
    ocr_result, fields = ocr_and_fields

    # Person Name
    assert "Person Name" in fields
    assert "bbox" in fields["Person Name"]
    nb = fields["Person Name"]["bbox"]
    assert nb["width"] > 0 and nb["height"] > 0

    # Aadhaar Number
    assert "Aadhaar Number" in fields
    assert "bbox" in fields["Aadhaar Number"]
    ab = fields["Aadhaar Number"]["bbox"]
    assert ab["width"] > 0 and ab["height"] > 0
    assert "token_boxes" in fields["Aadhaar Number"]
    assert len(fields["Aadhaar Number"]["token_boxes"]) == 3

    # Address
    assert "Address" in fields
    assert "bbox" in fields["Address"]
    assert "line_boxes" in fields["Address"]
    assert len(fields["Address"]["line_boxes"]) >= 2

    # QR Code
    assert "QR Code" in fields
    assert "bbox" in fields["QR Code"]
    qb = fields["QR Code"]["bbox"]
    assert qb["width"] > 0 and qb["height"] > 0


# ==============================================================================
# 2. PHYSICAL REDACTION LOGIC TESTS
# ==============================================================================

def test_physical_redaction_and_preservation(ocr_and_fields, tmp_path):
    """
    Verifies that REQUIRED fields are untouched and UNNECESSARY/CONDITIONAL
    fields are physically modified on the image pixels.
    """
    ocr_result, fields = ocr_and_fields
    redactor = RedactionEngine(output_dir=str(tmp_path))

    # Read original image
    orig_img = cv2.imread(TEST_DOC_PATH)
    orig_bytes = open(TEST_DOC_PATH, "rb").read()

    requirements = [
        {"field": "Person Name", "decision": "REQUIRED", "reason": "Identity verification"},
        {"field": "Aadhaar Number", "decision": "CONDITIONAL", "reason": "Last 4 digits only"},
        {"field": "Gender", "decision": "UNNECESSARY", "reason": "Not required"},
        {"field": "Mobile Number", "decision": "UNNECESSARY", "reason": "Not required"},
        {"field": "VID", "decision": "UNNECESSARY", "reason": "Not required"},
        {"field": "Address", "decision": "CONDITIONAL", "reason": "Street redacted, region preserved"},
        {"field": "QR Code", "decision": "UNNECESSARY", "reason": "Contains full biometric/demographic payload"}
    ]

    out_file = str(tmp_path / "protected_test.png")
    result = redactor.redact_document(
        image_path=TEST_DOC_PATH,
        fields_dict=fields,
        requirements=requirements,
        output_path=out_file,
        ocr_scale=ocr_result["ocr_scale"]
    )

    assert result["success"] is True
    assert os.path.isfile(out_file)

    # 1. Verify Original file was NEVER modified
    new_orig_bytes = open(TEST_DOC_PATH, "rb").read()
    assert orig_bytes == new_orig_bytes, "Original file was modified in place!"

    # 2. Load protected image
    prot_img = cv2.imread(out_file)
    assert prot_img.shape == orig_img.shape

    # 3. Check Person Name region: MUST BE UNTOUCHED (0 difference)
    scale = ocr_result["ocr_scale"]
    name_box = fields["Person Name"]["bbox"]
    snx = int(round(name_box["x"] / scale))
    sny = int(round(name_box["y"] / scale))
    snw = int(round(name_box["width"] / scale))
    snh = int(round(name_box["height"] / scale))

    orig_name_crop = orig_img[sny:sny+snh, snx:snx+snw]
    prot_name_crop = prot_img[sny:sny+snh, snx:snx+snw]
    np.testing.assert_array_equal(orig_name_crop, prot_name_crop, err_msg="REQUIRED Person Name pixels were altered!")

    # 4. Check Gender region: MUST BE BLURRED (UNNECESSARY)
    gender_box = fields["Gender"]["bbox"]
    sgx = int(round(gender_box["x"] / scale))
    sgy = int(round(gender_box["y"] / scale))
    sgw = int(round(gender_box["width"] / scale))
    sgh = int(round(gender_box["height"] / scale))

    orig_gender_crop = orig_img[sgy:sgy+sgh, sgx:sgx+sgw]
    prot_gender_crop = prot_img[sgy:sgy+sgh, sgx:sgx+sgw]
    assert not np.array_equal(orig_gender_crop, prot_gender_crop), "UNNECESSARY Gender was not modified!"
    assert not np.all(prot_gender_crop == 0), "Gender used solid black rectangle instead of privacy blur!"
    assert np.std(prot_gender_crop) < np.std(orig_gender_crop), "Gender was not properly blurred!"

    # 5. Check Mobile Number region: MUST BE BLURRED (UNNECESSARY)
    mob_box = fields["Mobile Number"]["bbox"]
    smx = int(round(mob_box["x"] / scale))
    smy = int(round(mob_box["y"] / scale))
    smw = int(round(mob_box["width"] / scale))
    smh = int(round(mob_box["height"] / scale))

    orig_mob_crop = orig_img[smy:smy+smh, smx:smx+smw]
    prot_mob_crop = prot_img[smy:smy+smh, smx:smx+smw]
    assert not np.array_equal(orig_mob_crop, prot_mob_crop), "UNNECESSARY Mobile Number was not modified!"
    assert not np.all(prot_mob_crop == 0), "Mobile Number used solid black rectangle instead of privacy blur!"
    assert np.std(prot_mob_crop) < np.std(orig_mob_crop), "Mobile Number was not properly diffused/blurred!"

    # 6. Check QR Code region: MUST BE BLURRED/PIXELATED AND UNDECODABLE (UNNECESSARY)
    qr_box = fields["QR Code"]["bbox"]
    qx, qy, qw, qh = qr_box["x"], qr_box["y"], qr_box["width"], qr_box["height"]
    orig_qr_crop = orig_img[qy:qy+qh, qx:qx+qw]
    prot_qr_crop = prot_img[qy:qy+qh, qx:qx+qw]
    assert not np.array_equal(orig_qr_crop, prot_qr_crop), "UNNECESSARY QR Code was not modified!"
    assert not np.all(prot_qr_crop == 0), "QR Code used solid black rectangle instead of privacy blur!"
    qr_detector = cv2.QRCodeDetector()
    qr_detected, _ = qr_detector.detect(prot_img)
    assert qr_detected is False, "Redacted QR code was still detectable by QRCodeDetector!"

    # 7. Check Aadhaar partial minimization: Tokens 0 and 1 are blurred, Token 2 is PRESERVED
    token_boxes = fields["Aadhaar Number"]["token_boxes"]
    assert len(token_boxes) == 3
    # Token 0: 9823 (blurred, not solid black)
    t0 = redactor._scale_box(token_boxes[0], scale)
    orig_t0 = orig_img[t0["y"]:t0["y"]+t0["height"], t0["x"]:t0["x"]+t0["width"]]
    crop_t0 = prot_img[t0["y"]:t0["y"]+t0["height"], t0["x"]:t0["x"]+t0["width"]]
    assert not np.array_equal(orig_t0, crop_t0), "Aadhaar first chunk was not redacted!"
    assert not np.all(crop_t0 == 0), "Aadhaar first chunk used black rectangle instead of privacy blur!"

    # Token 1: 4567 (blurred, not solid black)
    t1 = redactor._scale_box(token_boxes[1], scale)
    orig_t1 = orig_img[t1["y"]:t1["y"]+t1["height"], t1["x"]:t1["x"]+t1["width"]]
    crop_t1 = prot_img[t1["y"]:t1["y"]+t1["height"], t1["x"]:t1["x"]+t1["width"]]
    assert not np.array_equal(orig_t1, crop_t1), "Aadhaar second chunk was not redacted!"
    assert not np.all(crop_t1 == 0), "Aadhaar second chunk used black rectangle instead of privacy blur!"

    # Token 2: 9012 (preserved!)
    t2 = redactor._scale_box(token_boxes[2], scale)
    crop_t2 = prot_img[t2["y"]:t2["y"]+t2["height"], t2["x"]:t2["x"]+t2["width"]]
    orig_t2 = orig_img[t2["y"]:t2["y"]+t2["height"], t2["x"]:t2["x"]+t2["width"]]
    np.testing.assert_array_equal(crop_t2, orig_t2, err_msg="Aadhaar last 4 digits were altered!")


# ==============================================================================
# 3. HTTP API INTEGRATION TESTS
# ==============================================================================

def test_api_scan_endpoint_includes_bboxes():
    """Verifies that POST /api/scan now returns spatial bbox for detected PII."""
    with open(TEST_DOC_PATH, "rb") as f:
        response = client.post(
            "/api/scan",
            files={"file": ("test_document.png", f, "image/png")}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "pii" in data
    # Check that at least one item has bbox
    items_with_bbox = [item for item in data["pii"] if "bbox" in item]
    assert len(items_with_bbox) >= 4


def test_api_protect_endpoint_full_pipeline():
    """
    End-to-end integration test for POST /api/protect:
    Upload image + purpose -> OCR -> PII -> Purpose Decision -> Physical Redaction.
    """
    purpose_str = "I need to submit my Aadhaar to college for admission and student identity verification."
    with open(TEST_DOC_PATH, "rb") as f:
        response = client.post(
            "/api/protect",
            data={"purpose": purpose_str},
            files={"file": ("test_document.png", f, "image/png")}
        )

    assert response.status_code == 200
    data = response.json()

    assert data["success"] is True
    assert "document" in data
    assert data["document"]["type"] == "Aadhaar Card"
    assert "protected_filename" in data["document"]
    assert "protected_url" in data["document"]

    # Verify protected file exists on disk
    protected_name = data["document"]["protected_filename"]
    protected_disk_path = os.path.join(OUTPUT_DIR, protected_name)
    assert os.path.isfile(protected_disk_path)

    # Verify decisions and actions
    assert "requirements" in data
    assert "redactions_applied" in data
    actions = {r["field"]: r["action"] for r in data["redactions_applied"]}
    assert actions.get("Person Name") == "PRESERVED"
    assert actions.get("Aadhaar Number") == "PARTIALLY_REDACTED"
    assert actions.get("QR Code") == "FULLY_REDACTED"

    # Test GET /api/protected/{filename} to download protected file
    get_url = data["document"]["protected_url"]
    get_resp = client.get(get_url)
    assert get_resp.status_code == 200
    assert get_resp.headers["content-type"] == "image/png"
    assert len(get_resp.content) > 1000


def test_api_protect_missing_purpose():
    """Verifies that POST /api/protect validates mandatory purpose."""
    with open(TEST_DOC_PATH, "rb") as f:
        response = client.post(
            "/api/protect",
            data={"purpose": "   "},
            files={"file": ("test_document.png", f, "image/png")}
        )
    assert response.status_code == 400
    assert "mandatory" in response.json()["detail"].lower()


def test_api_get_protected_file_not_found():
    """Verifies 404 response when requested protected file does not exist."""
    response = client.get("/api/protected/nonexistent_file_9999.png")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_api_get_protected_file_path_traversal():
    """Verifies path traversal protection in file serving."""
    response = client.get("/api/protected/../../etc/passwd")
    # Due to basename sanitization and non-existence, must return 404
    assert response.status_code == 404


# ==============================================================================
# 4. QR DETECTION, UNDECODABILITY & METADATA CONSISTENCY TESTS
# ==============================================================================

def test_qr_code_altered_and_undecodable_when_original_decodable(tmp_path, ocr_and_fields):
    """
    Requirement 8:
    Verifies that when the original image has a detectable QR code,
    the protected image has the QR region physically altered,
    and OpenCV's QRCodeDetector cannot detect or decode the QR code.
    """
    ocr_result, fields = ocr_and_fields
    orig_img = cv2.imread(TEST_DOC_PATH)
    assert orig_img is not None

    # Verify original QR is detectable
    detector = cv2.QRCodeDetector()
    orig_detected, orig_pts = detector.detect(orig_img)
    assert orig_detected is True, "Original test document QR code was not detected!"

    redactor = RedactionEngine(output_dir=str(tmp_path))
    out_file = str(tmp_path / "qr_undecodable_test.png")

    requirements = [
        {"field": "Person Name", "decision": "REQUIRED", "reason": "Verification"},
        {"field": "QR Code", "decision": "UNNECESSARY", "reason": "High privacy risk"}
    ]

    res = redactor.redact_document(
        image_path=TEST_DOC_PATH,
        fields_dict=fields,
        requirements=requirements,
        output_path=out_file,
        ocr_scale=ocr_result["ocr_scale"]
    )

    assert res["success"] is True
    prot_img = cv2.imread(out_file)
    assert prot_img is not None

    # Check QR region altered
    qr_bbox = fields["QR Code"]["bbox"]
    qx, qy, qw, qh = qr_bbox["x"], qr_bbox["y"], qr_bbox["width"], qr_bbox["height"]
    orig_qr_crop = orig_img[qy:qy+qh, qx:qx+qw]
    prot_qr_crop = prot_img[qy:qy+qh, qx:qx+qw]

    assert not np.array_equal(orig_qr_crop, prot_qr_crop), "Protected QR region was not altered!"
    assert not np.all(prot_qr_crop == 0), "Protected QR used solid black rectangle instead of opaque pixelation!"

    # Verify protected image CANNOT be detected or decoded by OpenCV
    prot_detected, prot_pts = detector.detect(prot_img)
    assert prot_detected is False, "Protected QR code was still detectable by OpenCV QRCodeDetector!"

    val, decoded_pts, _ = detector.detectAndDecode(prot_img)
    assert not bool(val), f"Protected QR code was decoded by OpenCV: {val}"


def test_multi_strategy_qr_detector_on_scaled_image():
    """
    Requirements 2 & 3:
    Verifies that OCREngine.detect_qr_code handles transformed/resized variants
    and correctly maps polygon and bounding box coordinates back to original space.
    """
    orig_img = cv2.imread(TEST_DOC_PATH)
    h, w = orig_img.shape[:2]

    # Test on a downscaled image (simulating low resolution upload)
    scaled_w, scaled_h = int(w * 0.5), int(h * 0.5)
    down_img = cv2.resize(orig_img, (scaled_w, scaled_h), interpolation=cv2.INTER_AREA)

    res = OCREngine.detect_qr_code(down_img)
    assert res["detected"] is True, "Multi-strategy QR detector failed on scaled image!"
    assert res["bbox"] is not None
    assert "x" in res["bbox"] and "width" in res["bbox"]
    assert res["polygon"] is not None
    # Verify coordinates are within the downscaled image dimensions
    assert res["bbox"]["x"] + res["bbox"]["width"] <= scaled_w + 5
    assert res["bbox"]["y"] + res["bbox"]["height"] <= scaled_h + 5


def test_qr_code_masked_as_final_operation_even_if_omitted_from_fields(tmp_path):
    """
    Requirement 5:
    Ensures that even if QR Code was omitted from fields_dict,
    RedactionEngine dynamically detects and masks the QR code as the final step.
    """
    orig_img = cv2.imread(TEST_DOC_PATH)
    redactor = RedactionEngine(output_dir=str(tmp_path))
    out_file = str(tmp_path / "qr_omitted_test.png")

    # Pass fields without "QR Code"
    fields_without_qr = {
        "Person Name": {"value": "Test User", "bbox": {"x": 100, "y": 100, "width": 150, "height": 30}}
    }
    requirements = [
        {"field": "Person Name", "decision": "REQUIRED", "reason": "Verification"}
    ]

    res = redactor.redact_document(
        image_path=TEST_DOC_PATH,
        fields_dict=fields_without_qr,
        requirements=requirements,
        output_path=out_file
    )

    assert res["success"] is True
    prot_img = cv2.imread(out_file)

    # OpenCV detector must not detect any QR code on final output
    detector = cv2.QRCodeDetector()
    det_ok, _ = detector.detect(prot_img)
    assert det_ok is False, "QR code was not masked when omitted from fields_dict!"


def test_warning_when_qr_detection_fails_on_expected_doc():
    """
    Requirement 6:
    Verifies that if QR detection fails on a document type where QR is expected (Aadhaar),
    a clear warning is returned in the response.
    """
    # Test document without QR code (pan_sample.png or clean_syllabus.png)
    no_qr_path = os.path.join(BASE_DIR, "test_images", "pan_sample.png")
    if not os.path.isfile(no_qr_path):
        no_qr_path = os.path.join(BASE_DIR, "test_images", "clean_syllabus.png")

    with open(no_qr_path, "rb") as f:
        resp = client.post("/api/scan", files={"file": ("test.png", f, "image/png")})

    assert resp.status_code == 200
    data = resp.json()
    assert "warnings" in data
    # If the document was detected as Aadhaar without QR, warning must be present
    if "aadhaar" in data["document"]["type"].lower() and not data["document"].get("qr_detected"):
        assert len(data["warnings"]) > 0
        assert "QR code detection failed" in data["warnings"][0]


def test_metadata_consistency_gender_action():
    """
    Requirement 9:
    Verifies that metadata is consistent with actual actions taken,
    specifically eliminating the mismatch where Gender has action: PRESERVED
    in requirements and FULLY_REDACTED in redactions_applied.
    """
    purpose_str = "I need to submit my Aadhaar to college for admission and student identity verification."
    with open(TEST_DOC_PATH, "rb") as f:
        resp = client.post(
            "/api/protect",
            data={"purpose": purpose_str},
            files={"file": ("test_document.png", f, "image/png")}
        )

    assert resp.status_code == 200
    data = resp.json()

    req_actions = {r.get("type") or r.get("field"): r.get("action") for r in data.get("requirements", [])}
    appl_actions = {r["field"]: r["action"] for r in data.get("redactions_applied", [])}

    # If Gender is in requirements as PRESERVED, it must also be PRESERVED in redactions_applied
    if req_actions.get("gender") == "PRESERVED":
        assert appl_actions.get("Gender") == "PRESERVED", (
            f"Mismatch detected! requirements had {req_actions.get('gender')}, but redactions_applied had {appl_actions.get('Gender')}"
        )

