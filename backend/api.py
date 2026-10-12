"""
InfoShield AI - FastAPI Document OCR & PII Exposure Prevention Service
Production HTTP API wrapping real Tesseract OCR and PII classification.
"""

import os
import sys
import uuid
import shutil
import hashlib
import logging
import traceback
import time
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# Ensure backend directory is in sys.path so modules resolve anywhere
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Load environment configuration (.env) from backend/ or project root
backend_env = os.path.join(BASE_DIR, ".env")
root_env = os.path.join(PROJECT_ROOT, ".env")
if os.path.isfile(backend_env):
    load_dotenv(backend_env)
elif os.path.isfile(root_env):
    load_dotenv(root_env)
else:
    load_dotenv()

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

logger = logging.getLogger("infoshield.api")

from ocr_engine import OCREngine, OCREngineError
from pii_detector import PIIDetector
from purpose_engine import analyze_purpose
from redaction_engine import RedactionEngine
from purpose_ai import get_purpose_ai
from risk_model import get_risk_model
from supabase_service import get_db_service

# Resolve file storage directories relative to backend if not absolute
_env_upload = os.getenv("UPLOAD_DIR")
if not _env_upload:
    UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
elif not os.path.isabs(_env_upload):
    UPLOAD_DIR = os.path.join(BASE_DIR, _env_upload)
else:
    UPLOAD_DIR = _env_upload

_env_output = os.getenv("OUTPUT_DIR")
if not _env_output:
    OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
elif not os.path.isabs(_env_output):
    OUTPUT_DIR = os.path.join(BASE_DIR, _env_output)
else:
    OUTPUT_DIR = _env_output

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

def cleanup_stale_files(directory: str, max_age_seconds: int = 7200):
    """Safely cleans up temporary processing files older than max_age_seconds (default 2 hours)."""
    try:
        if os.path.isdir(directory):
            now = time.time()
            for fname in os.listdir(directory):
                fpath = os.path.join(directory, fname)
                if os.path.isfile(fpath) and (now - os.path.getmtime(fpath) > max_age_seconds):
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass
    except Exception as e:
        logger.warning(f"Error during cleanup of {directory}: {e}")

# File constraints
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Initialize engines
ocr_engine = OCREngine()
pii_detector = PIIDetector()
redaction_engine = RedactionEngine(OUTPUT_DIR)
purpose_ai = get_purpose_ai()
risk_model = get_risk_model()
db_service = get_db_service()

SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}

FIELD_TYPE_MAP = {
    "Person Name": "person_name",
    "Date of Birth": "date_of_birth",
    "Gender": "gender",
    "Mobile Number": "mobile_number",
    "Email Address": "email_address",
    "Aadhaar Number": "aadhaar_number",
    "VID": "vid",
    "PAN Number": "pan_number",
    "Bank Account Number": "bank_account_number",
    "IFSC Code": "ifsc_code",
    "Address": "address",
    "QR Code": "qr_code",
    "Photograph": "photograph",
    "Licence Number": "licence_number",
    "Driving Licence Number": "licence_number",
    "Validity Date": "validity_date",
    "Blood Group": "blood_group",
    "Authorized Classes": "authorized_classes",
    "Passport Number": "passport_number",
    "MRZ": "mrz",
    "Roll Number": "roll_number",
    "Marks / CGPA": "marks_cgpa",
    "Passing Year": "passing_year",
    "Employee ID": "employee_id",
    "Salary / Income": "salary_income",
    "Designation": "designation",
    "Statement Period": "statement_period",
    "Nationality": "nationality",
}

app = FastAPI(
    title="InfoShield OCR API",
    description="Real OCR & PII Exposure Prevention API for InfoShield",
    version="1.0.0"
)

# ------------------------------------------------------------------------------
# Robust CORS Configuration (Local Laptop Dev + Cloud Hosting)
# ------------------------------------------------------------------------------
# Local development origins (always enabled so local laptop testing never fails)
LOCAL_DEV_ORIGINS = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:8080",
    "http://localhost:8080",
]

# Additional configured origins from environment (.env or cloud settings)
raw_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
env_origins = [orig.strip() for orig in raw_origins.split(",") if orig.strip()]

# Combine local dev origins and environment origins (deduplicated, preserving order)
allowed_origins = list(dict.fromkeys(LOCAL_DEV_ORIGINS + env_origins))

frontend_url = os.getenv("FRONTEND_URL", "").strip()
if frontend_url and frontend_url not in allowed_origins:
    allowed_origins.append(frontend_url)

# Support any port on localhost / 127.0.0.1, plus Vercel preview domains
cors_regex = os.getenv(
    "ALLOWED_ORIGIN_REGEX",
    r"^(https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?|https:\/\/.*\.vercel\.app)$"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=cors_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,
)

@app.on_event("startup")
def startup_event():
    """Startup routine: clean up stale temporary files on boot."""
    cleanup_stale_files(UPLOAD_DIR, max_age_seconds=3600)
    cleanup_stale_files(OUTPUT_DIR, max_age_seconds=7200)


def classify_document_type(text: str, fields_dict: Dict[str, Any]) -> Tuple[str, float, List[str]]:
    """
    Classifies document category, confidence score, and warnings.
    Supports: Aadhaar, PAN, Driving Licence, Passport, Bank Statement,
    Marksheet, Employment Document, and Unknown Document.
    """
    upper = text.upper()
    warnings = []

    # 1. Aadhaar Card
    if "AADHAAR" in upper or "UNIQUE IDENTIFICATION" in upper or "Aadhaar Number" in fields_dict or "VID" in fields_dict:
        conf = 0.95 if ("AADHAAR" in upper and "Aadhaar Number" in fields_dict) else 0.88
        return "Aadhaar Card", conf, warnings

    # 2. PAN Card
    if "PERMANENT ACCOUNT NUMBER" in upper or "INCOME TAX DEPARTMENT" in upper or "PAN Number" in fields_dict or "INCOMETAX" in upper:
        conf = 0.95 if "PAN Number" in fields_dict else 0.88
        return "PAN Card", conf, warnings

    # 3. Passport
    if "PASSPORT" in upper or "REPUBLIC OF INDIA" in upper or "Passport Number" in fields_dict or "MRZ" in fields_dict:
        conf = 0.95 if ("Passport Number" in fields_dict or "MRZ" in fields_dict) else 0.88
        return "Passport", conf, warnings

    # 4. Driving Licence
    if "DRIVING LICENCE" in upper or "DRIVING LICENSE" in upper or "UNION OF INDIA" in upper or "Licence Number" in fields_dict or "Driving Licence Number" in fields_dict:
        conf = 0.95 if ("Licence Number" in fields_dict or "Driving Licence Number" in fields_dict) else 0.88
        return "Driving Licence", conf, warnings

    # 5. Bank Statement
    if any(k in upper for k in ["ACCOUNT STATEMENT", "STATEMENT OF ACCOUNT", "BANK STATEMENT", "CLOSING BALANCE", "TRANSACTION"]) or ("Bank Account Number" in fields_dict and "IFSC Code" in fields_dict):
        conf = 0.92 if ("Bank Account Number" in fields_dict) else 0.82
        return "Bank Statement", conf, warnings

    # 6. Marksheet / Academic Certificate
    if any(k in upper for k in ["MARKSHEET", "CENTRAL BOARD", "SECONDARY EDUCATION", "STATEMENT OF MARKS", "REPORT CARD", "GRADE SHEET", "EXAMINATION"]) or ("Marks / CGPA" in fields_dict or "Roll Number" in fields_dict):
        conf = 0.92 if ("Marks / CGPA" in fields_dict or "Roll Number" in fields_dict) else 0.82
        return "Marksheet", conf, warnings

    # 7. Employment Document / Payslip
    if any(k in upper for k in ["PAYSLIP", "SALARY SLIP", "EMPLOYEE", "BASIC SALARY", "NET PAY", "GROSS PAY"]) or ("Employee ID" in fields_dict or "Salary / Income" in fields_dict):
        conf = 0.92 if ("Employee ID" in fields_dict or "Salary / Income" in fields_dict) else 0.82
        return "Employment Document", conf, warnings

    # 8. College / Student ID
    if any(k in upper for k in ["COLLEGE", "STUDENT ID", "CAMPUS"]):
        return "College ID", 0.75, warnings

    # 9. Fallback / Unknown Document with low confidence warning
    warnings.append("Document type could not be confidently identified; default zero-trust protection applied.")
    return "Unknown Document", 0.35, warnings


def detect_document_type(text: str, fields_dict: Dict[str, Any]) -> str:
    """Backward-compatible helper returning document type string."""
    doc_type, _, _ = classify_document_type(text, fields_dict)
    return doc_type


@app.get("/api/health")
def health_check():
    """
    Health check endpoint.
    Returns status and service identifier.
    """
    return {
        "status": "ok",
        "service": "InfoShield OCR"
    }


@app.post("/api/scan")
async def scan_document_endpoint(file: UploadFile = File(...)):
    """
    Accepts multipart/form-data upload of an image (.jpg, .jpeg, .png, .webp),
    saves the image temporarily to uploads/, runs real Tesseract OCR + PII detection,
    and returns unmasked structured extraction data.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file uploaded or filename is missing."
        )

    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported image format: '{ext}'. Supported formats: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )

    # Save uploaded image to uploads directory
    safe_basename = os.path.basename(filename)
    unique_name = f"{uuid.uuid4().hex}_{safe_basename}"
    saved_path = os.path.join(UPLOAD_DIR, unique_name)

    try:
        with open(saved_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save uploaded file: {str(e)}"
        )

    file_size = os.path.getsize(saved_path)
    if file_size > MAX_FILE_SIZE:
        os.remove(saved_path)
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File size exceeds maximum permitted limit of 10MB."
        )

    # Execute real OCR pipeline on uploaded image
    try:
        ocr_result = ocr_engine.extract_text(saved_path)
    except OCREngineError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OCR Engine error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error during OCR processing: {str(e)}"
        )
    finally:
        # Secure cleanup: Remove temporary scan file immediately to avoid storing unredacted uploads
        if os.getenv("CLEANUP_SCAN_TEMP", "true").lower() == "true":
            try:
                if os.path.isfile(saved_path):
                    os.remove(saved_path)
            except Exception:
                pass

    raw_text = ocr_result.get("raw_text", "").strip()
    qr_detected = ocr_result.get("qr_detected", False)
    qr_data = ocr_result.get("qr_data", None)
    qr_bbox = ocr_result.get("qr_bbox", None)
    qr_polygon = ocr_result.get("qr_polygon", None)
    photo_detected = ocr_result.get("photo_detected", False)
    photo_bbox = ocr_result.get("photo_bbox", None)
    word_data = ocr_result.get("word_data", None)
    ocr_scale = ocr_result.get("ocr_scale", 1.0)
    confidence = float(ocr_result.get("confidence", 50.0))

    # Extract structured PII fields
    fields_dict = pii_detector.extract_document_fields(
        text=raw_text,
        word_data=word_data,
        qr_detected=qr_detected,
        qr_data=qr_data,
        qr_bbox=qr_bbox,
        qr_polygon=qr_polygon,
        photo_detected=photo_detected,
        photo_bbox=photo_bbox
    )

    # Transform into required API PII list format
    pii_items = []
    for field_name, item in fields_dict.items():
        val = item.get("value", "").strip()
        if not val or val == "Could not confidently determine":
            continue
        pii_entry = {
            "type": FIELD_TYPE_MAP.get(field_name, field_name.lower().replace(" ", "_")),
            "value": val,
            "risk": item.get("risk", "MEDIUM"),
            "confidence": round(float(item.get("confidence", 0.9)), 2)
        }
        raw_box = item.get("bbox")
        if raw_box:
            is_orig = (field_name in ["QR Code", "Photograph"])
            pii_entry["bbox"] = redaction_engine._scale_box(raw_box, ocr_scale, is_already_original=is_orig)
        pii_items.append(pii_entry)

    # Classify document type
    doc_type, doc_conf, doc_warnings = classify_document_type(raw_text, fields_dict)

    warnings = list(doc_warnings)
    if "aadhaar" in doc_type.lower() and not qr_detected:
        warnings.append(
            f"WARNING: QR code detection failed on {doc_type}. Physical QR redaction could not be applied automatically. Verify document privacy before sharing."
        )

    doc_meta = {
        "filename": safe_basename,
        "type": doc_type,
        "confidence": doc_conf,
        "qr_detected": qr_detected
    }
    if warnings:
        doc_meta["warnings"] = warnings

    res = {
        "success": True,
        "document": doc_meta,
        "warnings": warnings,
        "ocr": {
            "engine": "Tesseract",
            "confidence": confidence
        },
        "pii": pii_items,
        "raw_text": raw_text
    }
    return res


class PIIEntityInput(BaseModel):
    type: str
    value: Optional[str] = None
    risk: Optional[str] = None
    confidence: Optional[float] = None


class AnalyzePurposeRequest(BaseModel):
    document_type: Optional[str] = "Identity Document"
    purpose: str
    pii: List[PIIEntityInput]


@app.post("/api/analyze-purpose")
async def analyze_purpose_endpoint(payload: AnalyzePurposeRequest):
    """
    Analyzes natural language submission purpose and determines purpose-based
    PII requirements (REQUIRED, CONDITIONAL, UNNECESSARY) for data minimization.
    """
    if not payload.purpose or not payload.purpose.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The 'purpose' field is mandatory and cannot be empty."
        )

    # Convert Pydantic items to dictionaries
    pii_dicts = [
        item.model_dump() if hasattr(item, "model_dump") else item.dict()
        for item in payload.pii
    ]

    analysis_result = analyze_purpose(
        document_type=payload.document_type or "Identity Document",
        purpose=payload.purpose.strip(),
        pii=pii_dicts
    )

    return analysis_result


@app.post("/api/protect")
async def protect_document_endpoint(
    file: UploadFile = File(...),
    purpose: str = Form(...),
    user_id: Optional[str] = Form(None)
):
    """
    Phase 4B Unified Real Document Protection & Database Persistence Pipeline:
    1. Uploaded Image -> Document record (status: UPLOADED) + Audit Log
    2. Real Tesseract OCR -> Document record (status: SCANNED) + Audit Log
    3. PII Detection + Spatial Bounding Boxes + Audit Log
    4. AI Semantic Purpose Analysis -> Purpose Analysis record + Audit Log
    5. Policy Layer Data Minimization & ML Exposure Risk Estimation
    6. Real Image Physical Pixel Redaction -> Protected Document record + Audit Log
    7. Returns complete explainable protection results with Database Status.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file uploaded or filename is missing."
        )

    if not purpose or not purpose.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The 'purpose' form parameter is mandatory and cannot be empty."
        )

    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported image format: '{ext}'. Supported formats: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )

    # Save uploaded image to uploads directory (preserves original untouched!)
    safe_basename = os.path.basename(filename)
    unique_id = uuid.uuid4().hex[:8]
    unique_name = f"{unique_id}_{safe_basename}"
    saved_path = os.path.join(UPLOAD_DIR, unique_name)

    try:
        with open(saved_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save uploaded file: {str(e)}"
        )

    # Calculate file size & SHA-256 hash for document integrity
    file_size = os.path.getsize(saved_path)
    if file_size > MAX_FILE_SIZE:
        os.remove(saved_path)
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File size exceeds maximum permitted limit of 10MB."
        )

    with open(saved_path, "rb") as f_chk:
        file_hash = hashlib.sha256(f_chk.read()).hexdigest()

    # --------------------------------------------------------------------------
    # Database Step 1: Initialize Document Tracking Record
    # --------------------------------------------------------------------------
    print("\n" + "=" * 70, flush=True)
    print("[SUPABASE DB] Phase 4B Database Operations Started for /api/protect", flush=True)
    effective_user_id = user_id
    if not effective_user_id:
        print("[SUPABASE DB] [Step 1/7] Ensuring demo user exists in database...", flush=True)
        effective_user_id = db_service.ensure_demo_user()
        print(f"[SUPABASE DB] [Step 1/7] User ID resolved: {effective_user_id}", flush=True)
    else:
        print(f"[SUPABASE DB] [Step 1/7] User ID provided by client: {effective_user_id}", flush=True)

    db_doc_id = None
    db_status = "UNAVAILABLE"
    db_error = None
    audit_events_recorded = 0

    print(f"[SUPABASE DB] [Step 2/7] Inserting document: '{safe_basename}' (size: {file_size} bytes, hash: {file_hash[:16]}...)...", flush=True)
    try:
        db_doc_id = db_service.create_document(
            user_id=effective_user_id,
            original_filename=safe_basename,
            document_type="Pending OCR",
            mime_type=file.content_type or "image/png",
            file_size=file_size,
            document_hash=file_hash,
            ocr_engine="Tesseract",
            status="UPLOADED"
        )
        if db_doc_id:
            db_status = "CONNECTED"
            print(f"[SUPABASE DB] [Step 2/7] SUCCESS: Document created with ID: {db_doc_id}", flush=True)
            audit_id = db_service.create_audit_log(
                user_id=effective_user_id,
                document_id=db_doc_id,
                action="DOCUMENT_UPLOADED",
                status="SUCCESS",
                metadata={"filename": safe_basename, "file_size": file_size, "hash": file_hash}
            )
            print(f"[SUPABASE DB] [Audit Log 1] Recorded DOCUMENT_UPLOADED -> ID: {audit_id}", flush=True)
            audit_events_recorded += 1
        else:
            db_error = db_service.last_error or "create_document returned None"
            print(f"[SUPABASE DB ERROR] [Step 2/7] Document creation returned None! Error: {db_error}", flush=True)
    except Exception as e:
        db_error = f"{type(e).__name__}: {str(e)}"
        print(f"[SUPABASE DB ERROR] [Step 2/7] Exception during document creation: {db_error}", flush=True)
        traceback.print_exc()
        logger.error(f"DB document initialization error: {e}", exc_info=True)

    # --------------------------------------------------------------------------
    # Pipeline Step 1: OCR Extraction
    # --------------------------------------------------------------------------
    try:
        ocr_result = ocr_engine.extract_text(saved_path)
    except OCREngineError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OCR Engine error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error during OCR processing: {str(e)}"
        )

    raw_text = ocr_result.get("raw_text", "").strip()
    qr_detected = ocr_result.get("qr_detected", False)
    qr_data = ocr_result.get("qr_data", None)
    qr_bbox = ocr_result.get("qr_bbox", None)
    qr_polygon = ocr_result.get("qr_polygon", None)
    photo_detected = ocr_result.get("photo_detected", False)
    photo_bbox = ocr_result.get("photo_bbox", None)
    word_data = ocr_result.get("word_data", None)
    ocr_scale = ocr_result.get("ocr_scale", 1.0)
    confidence = float(ocr_result.get("confidence", 50.0))

    # --------------------------------------------------------------------------
    # Pipeline Step 2: PII Detection & Bounding Boxes
    # --------------------------------------------------------------------------
    fields_dict = pii_detector.extract_document_fields(
        text=raw_text,
        word_data=word_data,
        qr_detected=qr_detected,
        qr_data=qr_data,
        qr_bbox=qr_bbox,
        qr_polygon=qr_polygon,
        photo_detected=photo_detected,
        photo_bbox=photo_bbox
    )

    pii_items = []
    for field_name, item in fields_dict.items():
        val = item.get("value", "").strip()
        if not val or val == "Could not confidently determine":
            continue
        pii_items.append({
            "type": FIELD_TYPE_MAP.get(field_name, field_name.lower().replace(" ", "_")),
            "value": val,
            "risk": item.get("risk", "MEDIUM"),
            "confidence": round(float(item.get("confidence", 0.9)), 2)
        })

    # Document type classification
    doc_type, doc_conf, doc_warnings = classify_document_type(raw_text, fields_dict)

    warnings = list(doc_warnings)
    if "aadhaar" in doc_type.lower() and not qr_detected:
        warnings.append(
            f"WARNING: QR code detection failed on {doc_type}. Physical QR redaction could not be applied automatically. Verify document privacy before sharing."
        )

    if db_doc_id:
        print(f"[SUPABASE DB] [Step 3/7] Updating document status to SCANNED (confidence: {confidence}%, type: '{doc_type}')...", flush=True)
        try:
            up_ok = db_service.update_document_status(
                document_id=db_doc_id,
                status="SCANNED",
                ocr_confidence=confidence,
                document_type=doc_type
            )
            print(f"[SUPABASE DB] [Step 3/7] Document status update result: {up_ok}", flush=True)
            al1 = db_service.create_audit_log(
                user_id=effective_user_id,
                document_id=db_doc_id,
                action="OCR_COMPLETED",
                status="SUCCESS",
                metadata={"ocr_engine": "Tesseract", "confidence": confidence, "document_type": doc_type}
            )
            print(f"[SUPABASE DB] [Audit Log 2] Recorded OCR_COMPLETED -> ID: {al1}", flush=True)
            audit_events_recorded += 1
            al2 = db_service.create_audit_log(
                user_id=effective_user_id,
                document_id=db_doc_id,
                action="PII_DETECTED",
                status="SUCCESS",
                metadata={"detected_field_count": len(fields_dict), "detected_types": list(fields_dict.keys())}
            )
            print(f"[SUPABASE DB] [Audit Log 3] Recorded PII_DETECTED ({len(fields_dict)} fields) -> ID: {al2}", flush=True)
            audit_events_recorded += 1
        except Exception as e:
            err_msg = f"{type(e).__name__}: {str(e)}"
            print(f"[SUPABASE DB ERROR] [Step 3/7] OCR/PII audit update error: {err_msg}", flush=True)
            traceback.print_exc()
            logger.error(f"DB OCR/PII audit update error: {e}", exc_info=True)
            if not db_error:
                db_error = err_msg

    # --------------------------------------------------------------------------
    # Pipeline Step 3: AI Purpose Analysis & Risk Modeling
    # --------------------------------------------------------------------------
    purpose_clean = purpose.strip()
    purpose_decision = analyze_purpose(
        document_type=doc_type,
        purpose=purpose_clean,
        pii=pii_items
    )

    if db_doc_id:
        domain = purpose_decision.get("domain", "general")
        task = purpose_decision.get("task", "unknown")
        ai_name = (
            purpose_decision.get("ai_model", {}).get("name")
            if isinstance(purpose_decision.get("ai_model"), dict)
            else str(purpose_decision.get("ai_model"))
        )
        print(f"[SUPABASE DB] [Step 4/7] Inserting purpose analysis: domain='{domain}', task='{task}', model='{ai_name}'...", flush=True)
        try:
            pa_id = db_service.create_purpose_analysis(
                document_id=db_doc_id,
                purpose_text=purpose_clean,
                domain=domain,
                task=task,
                sub_purpose=purpose_decision.get("sub_purpose"),
                submission_context=purpose_decision.get("submission_context"),
                intent_confidence=purpose_decision.get("intent_confidence"),
                ai_model=ai_name
            )
            print(f"[SUPABASE DB] [Step 4/7] SUCCESS: Purpose analysis persisted with ID: {pa_id}", flush=True)
            al3 = db_service.create_audit_log(
                user_id=effective_user_id,
                document_id=db_doc_id,
                action="PURPOSE_ANALYZED",
                status="SUCCESS",
                metadata={
                    "domain": domain,
                    "task": task,
                    "intent_confidence": purpose_decision.get("intent_confidence")
                }
            )
            print(f"[SUPABASE DB] [Audit Log 4] Recorded PURPOSE_ANALYZED -> ID: {al3}", flush=True)
            audit_events_recorded += 1
        except Exception as e:
            err_msg = f"{type(e).__name__}: {str(e)}"
            print(f"[SUPABASE DB ERROR] [Step 4/7] Purpose analysis error: {err_msg}", flush=True)
            traceback.print_exc()
            logger.error(f"DB purpose analysis audit error: {e}", exc_info=True)
            if not db_error:
                db_error = err_msg

    # --------------------------------------------------------------------------
    # Pipeline Step 4: Physical Image Redaction
    # --------------------------------------------------------------------------
    protected_filename = f"protected_{unique_id}_{safe_basename}"
    output_path = os.path.join(OUTPUT_DIR, protected_filename)

    requirements = purpose_decision.get("requirements", [])
    try:
        redaction_result = redaction_engine.redact_document(
            image_path=saved_path,
            fields_dict=fields_dict,
            requirements=requirements,
            output_path=output_path,
            ocr_scale=ocr_scale
        )
        if redaction_result.get("warnings"):
            warnings.extend(redaction_result["warnings"])
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Redaction failed: {str(e)}"
        )

    # Attach bounding boxes to requirements
    enhanced_requirements = []
    for req in requirements:
        req_item = dict(req)
        field_type = req_item.get("type", "")
        for f_name, f_data in fields_dict.items():
            mapped_type = FIELD_TYPE_MAP.get(f_name, f_name.lower().replace(" ", "_"))
            if mapped_type == field_type and "bbox" in f_data:
                is_orig = (f_name in ["QR Code", "Photograph"])
                req_item["bbox"] = redaction_engine._scale_box(f_data["bbox"], ocr_scale, is_already_original=is_orig)
                break
        enhanced_requirements.append(req_item)

    # --------------------------------------------------------------------------
    # Database Step 2: Persist PII Entities, ML Risks & Protected Doc
    # --------------------------------------------------------------------------
    if db_doc_id:
        print(f"[SUPABASE DB] [Step 5/7] Inserting {len(enhanced_requirements)} PII entities & ML risk predictions...", flush=True)
        try:
            created_pii_ids = db_service.create_pii_entities_and_risks(
                document_id=db_doc_id,
                requirements=enhanced_requirements
            )
            print(f"[SUPABASE DB] [Step 5/7] SUCCESS: Persisted {len(created_pii_ids)} PII entities & risk predictions", flush=True)

            al4 = db_service.create_audit_log(
                user_id=effective_user_id,
                document_id=db_doc_id,
                action="RISK_ANALYZED",
                status="SUCCESS",
                metadata={"entities_analyzed": len(enhanced_requirements)}
            )
            print(f"[SUPABASE DB] [Audit Log 5] Recorded RISK_ANALYZED -> ID: {al4}", flush=True)
            audit_events_recorded += 1

            al5 = db_service.create_audit_log(
                user_id=effective_user_id,
                document_id=db_doc_id,
                action="POLICY_APPLIED",
                status="SUCCESS",
                metadata={"decision_summary": purpose_decision.get("summary", {})}
            )
            print(f"[SUPABASE DB] [Audit Log 6] Recorded POLICY_APPLIED -> ID: {al5}", flush=True)
            audit_events_recorded += 1

            print(f"[SUPABASE DB] [Step 6/7] Inserting protected document record: '{protected_filename}'...", flush=True)
            prot_id = db_service.create_protected_document(
                document_id=db_doc_id,
                protected_filename=protected_filename,
                protected_path=output_path,
                protection_status="PROTECTED",
                total_detected=len(enhanced_requirements),
                fully_redacted=redaction_result["stats"]["fully_redacted"],
                partially_redacted=redaction_result["stats"]["partially_redacted"],
                preserved=redaction_result["stats"]["preserved"],
                protection_summary=redaction_result["stats"]
            )
            print(f"[SUPABASE DB] [Step 6/7] SUCCESS: Protected document created with ID: {prot_id}", flush=True)

            print(f"[SUPABASE DB] [Step 7/7] Updating document status to PROTECTED...", flush=True)
            db_service.update_document_status(
                document_id=db_doc_id,
                status="PROTECTED"
            )
            print(f"[SUPABASE DB] [Step 7/7] SUCCESS: Document status updated to PROTECTED", flush=True)

            al6 = db_service.create_audit_log(
                user_id=effective_user_id,
                document_id=db_doc_id,
                action="DOCUMENT_PROTECTED",
                status="SUCCESS",
                metadata={
                    "protected_filename": protected_filename,
                    "redactions_count": len(redaction_result["redactions_applied"])
                }
            )
            print(f"[SUPABASE DB] [Audit Log 7] Final audit log recorded: DOCUMENT_PROTECTED -> ID: {al6}", flush=True)
            audit_events_recorded += 1
            print("[SUPABASE DB] ALL 7 DATABASE OPERATIONS PERSISTED SUCCESSFULLY TO SUPABASE POSTGRESQL!", flush=True)
            print("=" * 70 + "\n", flush=True)
        except Exception as e:
            err_msg = f"{type(e).__name__}: {str(e)}"
            print(f"[SUPABASE DB ERROR] Entity/protection persistence error: {err_msg}", flush=True)
            traceback.print_exc()
            logger.error(f"DB entity and protection record persistence error: {e}", exc_info=True)
            if not db_error:
                db_error = err_msg

    # Build response payload
    if db_status == "UNAVAILABLE" and not db_error:
        if not db_service.is_connected():
            db_error = "Supabase credentials not configured in environment (.env) or client unavailable."
        else:
            db_error = db_service.last_error or "Database persistence failed during document initialization."

    db_meta = {
        "status": db_status,
        "document_id": db_doc_id,
        "user_id": effective_user_id if db_doc_id else None,
        "persisted_entities": len(enhanced_requirements) if db_doc_id else 0,
        "audit_events_recorded": audit_events_recorded
    }
    if db_error:
        db_meta["error"] = db_error

    doc_meta = {
        "original_filename": safe_basename,
        "protected_filename": protected_filename,
        "protected_url": f"/api/protected/{protected_filename}",
        "type": doc_type,
        "confidence": doc_conf,
        "qr_detected": qr_detected
    }
    if warnings:
        doc_meta["warnings"] = warnings
    if db_doc_id:
        doc_meta["id"] = db_doc_id

    review_required = purpose_decision.get("review_required", False) or (doc_conf < 0.60) or (len(warnings) > 0)

    return {
        "success": True,
        "document": doc_meta,
        "review_required": review_required,
        "warnings": warnings,
        "database": db_meta,
        "purpose": purpose_clean,
        "intelligence": {
            "purpose_ai": {
                "domain": purpose_decision.get("domain", "general"),
                "task": purpose_decision.get("task", "unknown"),
                "sub_purpose": purpose_decision.get("sub_purpose", "unknown"),
                "confidence": purpose_decision.get("intent_confidence", 0.90)
            },
            "risk_model": {
                "model": "RandomForestClassifier",
                "version": "prototype-1"
            }
        },
        "purpose_analysis": purpose_decision.get("purpose_analysis", {}),
        "decision_summary": purpose_decision.get("summary", {}),
        "requirements": enhanced_requirements,
        "redactions_applied": redaction_result["redactions_applied"],
        "stats": redaction_result["stats"],
        "ocr": {
            "engine": "Tesseract",
            "confidence": confidence
        }
    }


# ==============================================================================
# PHASE 4B: SUPABASE DATABASE MANAGEMENT ENDPOINTS
# ==============================================================================

@app.get("/api/database/health")
async def database_health_endpoint():
    """
    Returns the operational status of the Supabase PostgreSQL connection.
    Never exposes credentials or secrets.
    """
    return db_service.check_health()


@app.get("/api/documents/{document_id}")
async def get_document_endpoint(document_id: str):
    """
    Returns complete document lifecycle metadata (purpose analysis, PII metadata,
    risk predictions, protection details, audit events).
    Never returns raw PII values.
    """
    doc_info = db_service.get_document_full(document_id)
    if not doc_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document '{document_id}' not found."
        )
    return {
        "success": True,
        "document_id": document_id,
        **doc_info
    }


@app.get("/api/users/{user_id}/documents")
async def get_user_documents_endpoint(user_id: str):
    """
    Returns all document metadata uploaded by the specified user.
    Metadata only, zero raw PII.
    """
    docs = db_service.get_user_documents(user_id)
    return {
        "success": True,
        "user_id": user_id,
        "count": len(docs),
        "documents": docs
    }


@app.get("/api/documents/{document_id}/audit")
async def get_document_audit_endpoint(document_id: str):
    """
    Returns chronological audit events for the document with SHA-256 hash chaining.
    """
    return db_service.get_document_audit_trail(document_id)


@app.get("/api/protected/{filename}")
async def get_protected_file_endpoint(filename: str):
    """
    Serves the physically redacted/protected document image safely from outputs/.
    Prevents path traversal attacks and sets anti-caching privacy headers.
    """
    safe_name = os.path.basename(filename)

    # Path traversal protection
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid document identifier."
        )

    # Access control & file existence: only serve legitimate existing protected files
    file_path = os.path.join(OUTPUT_DIR, safe_name)
    if not safe_name.startswith("protected_") or not os.path.isfile(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Protected document '{safe_name}' not found."
        )

    ext = os.path.splitext(safe_name)[1].lower()
    media_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp"
    }
    media_type = media_types.get(ext, "application/octet-stream")

    return FileResponse(
        file_path,
        media_type=media_type,
        headers={
            "Cache-Control": "private, no-cache, no-store, must-revalidate",
            "X-Content-Type-Options": "nosniff"
        }
    )


@app.get("/api/history")
async def get_history_endpoint(user_id: Optional[str] = None):
    """
    Returns document protection history for the user or local session.
    If database is available, queries Supabase documents;
    otherwise lists generated protected outputs safely with metadata.
    """
    effective_user = user_id or db_service.demo_user_id
    db_docs = []
    if db_service.is_connected():
        try:
            db_docs = db_service.get_user_documents(effective_user)
        except Exception as e:
            logger.warning(f"Error retrieving user documents from database: {e}")

    # Build local list from output directory
    local_docs = []
    if os.path.exists(OUTPUT_DIR):
        for f in sorted(os.listdir(OUTPUT_DIR), reverse=True):
            if f.startswith("protected_") and any(f.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
                f_path = os.path.join(OUTPUT_DIR, f)
                stat = os.stat(f_path)
                local_docs.append({
                    "id": f,
                    "protected_filename": f,
                    "original_filename": f.replace("protected_", ""),
                    "protected_url": f"/api/protected/{f}",
                    "file_size": stat.st_size,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
                    "status": "PROTECTED"
                })

    return {
        "success": True,
        "count": len(db_docs) if db_docs else len(local_docs),
        "source": "database" if db_docs else "local_outputs",
        "documents": db_docs if db_docs else local_docs
    }


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("api:app", host=host, port=port, reload=False)
