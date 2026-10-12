#!/usr/bin/env python3
"""
InfoShield AI - Real Document PII Scanner & Multi-Stage Protection Engine
Purpose-Based PII Exposure Prevention & Document Integrity Verification

STAGE 1: Information Extraction (Actual values from OCR)
STAGE 2: Security Classification (Risk stratification by PII type)
STAGE 3: Protection Preview (Zero-trust data minimization and masking)

NO hardcoded values, NO fake data, operates on actual pixels via Tesseract OCR.
"""

import sys
import os
import time
from typing import Dict, Any

# Ensure UTF-8 stdout encoding on Windows terminals
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from ocr_engine import OCREngine, OCREngineError
from pii_detector import PIIDetector


def display_startup_banner(ocr_engine: OCREngine):
    """Displays standard enterprise startup header and Tesseract status."""
    print("OCR ENGINE")
    print("-----------")
    print("Tesseract\n")
    print("Tesseract Version:")
    print(f"{ocr_engine.version}\n")


def print_step(step_num: int, total_steps: int, title: str):
    """Prints progressive execution feedback."""
    print(f"[{step_num}/{total_steps}] {title}...")
    time.sleep(0.12)


def validate_image_path(image_path: str, supported_extensions: set) -> bool:
    """Validates existence and extension of user-supplied image file."""
    if not os.path.exists(image_path):
        print(f"\n[ERROR] File not found: '{image_path}'")
        print("Please verify the file path and try again.\n")
        return False

    if not os.path.isfile(image_path):
        print(f"\n[ERROR] Path is not a file: '{image_path}'\n")
        return False

    ext = os.path.splitext(image_path)[1].lower()
    if ext not in supported_extensions:
        print(f"\n[ERROR] Unsupported image format: '{ext}'")
        print(f"Supported formats: {', '.join(sorted(supported_extensions))}\n")
        return False

    return True


def scan_document(image_path: str, ocr_engine: OCREngine, pii_detector: PIIDetector) -> bool:
    """Executes the full pixel OCR -> Extraction -> Classification -> Protection pipeline."""
    # Step 1: Preprocessing & Real OCR
    print_step(1, 3, "Image preprocessing")
    print_step(2, 3, "Performing real OCR")

    try:
        ocr_result = ocr_engine.extract_text(image_path)
    except OCREngineError as e:
        print(f"\n[OCR ERROR]:\n{e}\n")
        return False
    except Exception as e:
        print(f"\n[UNEXPECTED ERROR DURING OCR]: {e}\n")
        return False

    extracted_text = ocr_result.get("raw_text", "").strip()
    qr_detected = ocr_result.get("qr_detected", False)
    qr_data = ocr_result.get("qr_data", None)
    word_data = ocr_result.get("word_data", None)

    # Step 2: Extract structured fields
    print_step(3, 3, "Extracting document information")
    print()

    # --------------------------------------------------------------------------
    # DISPLAY RAW OCR OUTPUT
    # --------------------------------------------------------------------------
    print("-" * 50)
    print("RAW OCR TEXT EXTRACTED FROM IMAGE")
    print("-" * 50)
    if extracted_text:
        print(extracted_text)
    else:
        print("[No textual characters extracted from image pixels]")
    print()

    # Run multi-stage extraction
    fields_dict = pii_detector.extract_document_fields(
        text=extracted_text,
        word_data=word_data,
        qr_detected=qr_detected,
        qr_data=qr_data
    )

    # --------------------------------------------------------------------------
    # STAGE 1 — INFORMATION EXTRACTION (ACTUAL VALUES)
    # --------------------------------------------------------------------------
    print("-" * 50)
    print("EXTRACTED DOCUMENT INFORMATION")
    print("-" * 50)
    print()

    if not fields_dict:
        print("No sensitive document fields detected.")
        print()
    else:
        for field_name, item in fields_dict.items():
            print(f"{field_name}:")
            print(f"{item['value']}")
            print()

    # --------------------------------------------------------------------------
    # STAGE 2 — SECURITY CLASSIFICATION
    # --------------------------------------------------------------------------
    print("-" * 50)
    print("PII CLASSIFICATION")
    print("-" * 50)
    print()

    classified_items = [item for item in fields_dict.values() if item["value"] != "Could not confidently determine"]

    if not classified_items:
        print("No PII entities identified for classification.")
        print()
    else:
        for item in classified_items:
            field_name = item["field"]
            # Pad field name cleanly for alignment
            padding = " " * max(1, 18 - len(field_name))
            print(f"{field_name}{padding}→ {item['risk']}")
        print()

    # --------------------------------------------------------------------------
    # STAGE 3 — PROTECTION PREVIEW (DATA MINIMIZATION)
    # --------------------------------------------------------------------------
    print("-" * 50)
    print("PROTECTION PREVIEW (DATA MINIMIZATION)")
    print("-" * 50)
    print()

    if not classified_items:
        print("Document requires zero redactions.")
        print()
    else:
        for item in classified_items:
            print(f"{item['field']}:")
            print(f"{item['masked_value']}")
            print()

    # --------------------------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------------------------
    total_detected = len(classified_items)
    high_count = sum(1 for item in classified_items if item["risk"] == "HIGH")
    med_count = sum(1 for item in classified_items if item["risk"] == "MEDIUM")
    low_count = sum(1 for item in classified_items if item["risk"] == "LOW")
    qr_status = "Yes" if qr_detected else "No"

    print("-" * 50)
    print("SUMMARY")
    print("-" * 50)
    print(f"Total PII Detected: {total_detected}")
    print(f"High Risk:          {high_count}")
    print(f"Medium Risk:        {med_count}")
    print(f"Low Risk:           {low_count}")
    print(f"QR Code Detected:   {qr_status}")
    print()
    print("Recommendation:")
    if high_count > 0:
        print("Apply purpose-based data minimization before sharing.")
    elif med_count > 0:
        print("Apply conditional field masking based on recipient purpose.")
    else:
        print("Safe for general sharing under standard access policies.")
    print()

    return True


def main():
    ocr_engine = OCREngine()
    pii_detector = PIIDetector()

    # Verify Tesseract installation
    if not ocr_engine.is_available:
        print("OCR ENGINE")
        print("-----------")
        print("Tesseract\n")
        print("Tesseract Version:")
        print("Not installed\n")
        print(ocr_engine.get_installation_instructions())
        sys.exit(1)

    display_startup_banner(ocr_engine)

    # Resolve target image path from CLI argument or interactive prompt
    if len(sys.argv) > 1:
        raw_path = sys.argv[1].strip().strip('"').strip("'")
    else:
        try:
            raw_path = input("Enter document image path: ").strip().strip('"').strip("'")
        except (KeyboardInterrupt, EOFError):
            print("\nScan aborted by user.")
            sys.exit(0)

    if not raw_path:
        print("\n[ERROR] No image path provided. Exiting.")
        sys.exit(1)

    # Normalize relative paths
    image_path = os.path.abspath(raw_path)

    # Validate file
    if not validate_image_path(image_path, ocr_engine.SUPPORTED_EXTENSIONS):
        sys.exit(1)

    # Execute scanner
    success = scan_document(image_path, ocr_engine, pii_detector)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
