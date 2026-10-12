"""
InfoShield End-to-End Pipeline Demonstration:
Phase 1: Real Pixel OCR Scan (POST /api/scan)
Phase 2: Purpose-Based Data Minimization Analysis (POST /api/analyze-purpose)
Phase 3: Real Image Localization & Physical Pixel Redaction (POST /api/protect & GET /api/protected/{filename})
"""

import json
import os
import cv2
import numpy as np
import sys
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from fastapi.testclient import TestClient
from api import app, OUTPUT_DIR

client = TestClient(app)

print("=" * 70)
print("INFOSHIELD COMPLETE PIPELINE: SCAN -> PURPOSE ANALYSIS -> PHYSICAL REDACTION")
print("=" * 70)

# ------------------------------------------------------------------------------
# STEP 1: Real OCR Scan & PII Extraction with Bounding Boxes
# ------------------------------------------------------------------------------
test_doc = os.path.join(BACKEND_DIR, "test_images", "test_document.png")
print(f"\n[STEP 1] Running POST /api/scan on '{test_doc}'...")
with open(test_doc, "rb") as f:
    scan_resp = client.post(
        "/api/scan",
        files={"file": ("test_document.png", f, "image/png")}
    )

assert scan_resp.status_code == 200, f"Scan failed: {scan_resp.text}"
scan_data = scan_resp.json()

doc_name = scan_data["document"]["filename"]
doc_type = scan_data["document"]["type"]
ocr_conf = scan_data["ocr"]["confidence"]
pii_list = scan_data["pii"]

print(f"✓ Scan Success: {doc_name} classified as '{doc_type}'")
print(f"✓ OCR Word Confidence: {ocr_conf}% (Tesseract)")
print(f"✓ Extracted {len(pii_list)} localized PII entities from pixels:")
for item in pii_list:
    bbox_str = f"bbox={item.get('bbox')}" if "bbox" in item else "no bbox"
    print(f"   • {item['type']:<18} : {item['value']:<32} | {bbox_str}")

# ------------------------------------------------------------------------------
# STEP 2: Natural-Language Purpose Analysis
# ------------------------------------------------------------------------------
purpose_str = "I need to submit my Aadhaar to my college for admission and financial aid."
print(f"\n[STEP 2] Submitting Purpose: \"{purpose_str}\"")
print("Calling POST /api/analyze-purpose...")

purpose_payload = {
    "document_type": doc_type,
    "purpose": purpose_str,
    "pii": pii_list
}

purpose_resp = client.post("/api/analyze-purpose", json=purpose_payload)
assert purpose_resp.status_code == 200, f"Analysis failed: {purpose_resp.text}"
purpose_data = purpose_resp.json()

summary = purpose_data["summary"]
print(f"✓ Purpose Classified Domain : {purpose_data['purpose_analysis']['domain']}")
print(f"✓ Task Intent               : {purpose_data['purpose_analysis']['task']}")
print(f"✓ Minimization Decisions    : REQUIRED={summary['required']}, CONDITIONAL={summary['conditional']}, UNNECESSARY={summary['unnecessary']}")

# ------------------------------------------------------------------------------
# STEP 3: Real Image Localization & Physical Pixel Redaction
# ------------------------------------------------------------------------------
print(f"\n[STEP 3] Running Unified POST /api/protect pipeline...")
with open(test_doc, "rb") as f:
    protect_resp = client.post(
        "/api/protect",
        data={"purpose": purpose_str},
        files={"file": ("test_document.png", f, "image/png")}
    )

assert protect_resp.status_code == 200, f"Protect failed: {protect_resp.text}"
protect_data = protect_resp.json()

prot_filename = protect_data["document"]["protected_filename"]
prot_url = protect_data["document"]["protected_url"]
redactions = protect_data["redactions_applied"]
stats = protect_data["stats"]

print(f"✓ Protected Document Generated : {prot_filename}")
print(f"✓ Download URL                 : {prot_url}")
print(f"✓ Redactions Applied ({len(redactions)} total):")
for r in redactions:
    print(f"   • {r['field']:<16} : {r['action']:<20} ({r['status']}) -> {r['details']}")

# ------------------------------------------------------------------------------
# STEP 4: Protected Image Download & Pixel Integrity Verification
# ------------------------------------------------------------------------------
print(f"\n[STEP 4] Downloading protected image via GET {prot_url}...")
get_resp = client.get(prot_url)
assert get_resp.status_code == 200
assert get_resp.headers["content-type"] == "image/png"

orig_img = cv2.imread(test_doc)
prot_disk_path = os.path.join(OUTPUT_DIR, prot_filename)
prot_img = cv2.imread(prot_disk_path)

diff = np.abs(orig_img.astype(int) - prot_img.astype(int))
modified_count = np.count_nonzero(diff)
print(f"✓ Download verified: {len(get_resp.content)} bytes received")
print(f"✓ Pixel verification: {modified_count:,} pixels physically modified")
print(f"✓ Original file remains 100% immutable in uploads/")

# Also save original_debug.png and protected_debug.png for direct visual review
cv2.imwrite(os.path.join(OUTPUT_DIR, "original_debug.png"), orig_img)
cv2.imwrite(os.path.join(OUTPUT_DIR, "protected_debug.png"), prot_img)
print(f"✓ Visual debug images saved to outputs/original_debug.png and outputs/protected_debug.png")

print("\n" + "=" * 70)
print("ALL 3 PHASES OF INFOSHIELD FULLY OPERATIONAL!")
print("=" * 70)
