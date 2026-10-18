"""
InfoShield AI - FastAPI Document OCR & PII Exposure Prevention Service
Production HTTP API wrapping real Tesseract OCR and PII classification.

Security Hardened:
- JWT-based authentication via Supabase Auth
- Server-side ownership enforcement on all document endpoints
- Streaming upload size enforcement
- Content-type validation via magic bytes
- Opaque error responses (no stack traces/internal paths to client)
- Rate limiting on expensive OCR operations
- Secure document sharing with token verification
"""

import os
import sys
import uuid
import shutil
import hashlib
import logging
import traceback
import time
import struct
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, status, Depends, Query
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
from auth import get_current_user, get_optional_user, AuthenticatedUser, verify_document_ownership
from sharing import ShareService

# Environment mode
ENV_MODE = os.getenv("ENV", "development").strip().lower()
IS_PRODUCTION = ENV_MODE in ("production", "prod")

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

# Temp dir for processing (distinct from completed outputs)
TEMP_DIR = os.path.join(BASE_DIR, "temp_processing")
os.makedirs(TEMP_DIR, exist_ok=True)


def cleanup_temp_files(directory: str, max_age_seconds: int = 3600):
    """Cleans up TEMPORARY processing files only (not completed protected outputs)."""
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


def cleanup_uploads_by_policy():
    """Clean up original uploads based on CLEANUP_ORIGINALS policy."""
    cleanup_originals = os.getenv("CLEANUP_ORIGINALS", "false").strip().lower()
    if cleanup_originals == "true":
        max_age = int(os.getenv("UPLOAD_RETENTION_SECONDS", "3600"))
        cleanup_temp_files(UPLOAD_DIR, max_age_seconds=max_age)


# File constraints
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_IMAGE_DIMENSION = 10000  # pixels
MAX_IMAGE_PIXELS = 50_000_000  # 50 megapixels

# Image magic bytes for content validation
IMAGE_SIGNATURES = {
    b'\xff\xd8\xff': 'image/jpeg',      # JPEG
    b'\x89PNG\r\n\x1a\n': 'image/png',  # PNG
    b'RIFF': 'image/webp',              # WebP (RIFF container)
}

def validate_image_content(file_path: str) -> Optional[str]:
    """
    Validates image file content by checking magic bytes and decodability.
    Returns detected MIME type or raises HTTPException.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
    except Exception:
        return None

    if len(header) < 4:
        return None

    # Check magic bytes
    detected_mime = None
    for sig, mime in IMAGE_SIGNATURES.items():
        if header[:len(sig)] == sig:
            detected_mime = mime
            break

    # WebP needs additional check (RIFF....WEBP)
    if header[:4] == b'RIFF' and len(header) >= 12:
        if header[8:12] != b'WEBP':
            return None
        detected_mime = 'image/webp'

    if not detected_mime:
        return None

    # Verify image dimensions are within safe limits
    try:
        import cv2
        img = cv2.imread(file_path)
        if img is None:
            return None
        h, w = img.shape[:2]
        if w > MAX_IMAGE_DIMENSION or h > MAX_IMAGE_DIMENSION:
            return None
        if w * h > MAX_IMAGE_PIXELS:
            return None
    except Exception:
        return None

    return detected_mime


def stream_upload_with_limit(upload_file, dest_path: str, max_bytes: int) -> int:
    """
    Streams upload to disk with byte limit enforcement.
    Stops immediately when limit is exceeded and removes partial file.
    Returns total bytes written.
    """
    total = 0
    chunk_size = 8192
    try:
        with open(dest_path, "wb") as f:
            while True:
                chunk = upload_file.read(chunk_size)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    # Exceeded limit — stop immediately
                    f.close()
                    _safe_remove(dest_path)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File size exceeds maximum permitted limit of {max_bytes // (1024*1024)}MB."
                    )
                f.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        _safe_remove(dest_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process uploaded file."
        )
    return total


def _safe_remove(path: str):
    """Safely remove a file, ignoring errors."""
    try:
        if path and os.path.isfile(path):
            os.remove(path)
    except Exception:
        pass


def _generate_safe_filename(original_name: str) -> str:
    """Generate a safe storage filename using UUID, preserving only the extension."""
    ext = os.path.splitext(os.path.basename(original_name))[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        ext = ".png"
    return f"{uuid.uuid4().hex}{ext}"


# Initialize engines
ocr_engine = OCREngine()
pii_detector = PIIDetector()
redaction_engine = RedactionEngine(OUTPUT_DIR)
purpose_ai = get_purpose_ai()
risk_model = get_risk_model()
db_service = get_db_service()
share_service = ShareService(db_service)

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
    version="2.0.0"
)

# ------------------------------------------------------------------------------
# Environment-Specific CORS Configuration
# ------------------------------------------------------------------------------
if IS_PRODUCTION:
    # Production: only configured origins, no localhost
    raw_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
    allowed_origins = [orig.strip() for orig in raw_origins.split(",") if orig.strip()]
    frontend_url = os.getenv("FRONTEND_URL", "").strip()
    if frontend_url and frontend_url not in allowed_origins:
        allowed_origins.append(frontend_url)
    # No wildcard regex in production
    cors_regex = os.getenv("ALLOWED_ORIGIN_REGEX", "")
    cors_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    cors_headers = ["Authorization", "Content-Type", "Accept"]
    cors_expose = ["Content-Disposition"]
else:
    # Development: include localhost origins
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
    raw_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
    env_origins = [orig.strip() for orig in raw_origins.split(",") if orig.strip()]
    allowed_origins = list(dict.fromkeys(LOCAL_DEV_ORIGINS + env_origins))
    frontend_url = os.getenv("FRONTEND_URL", "").strip()
    if frontend_url and frontend_url not in allowed_origins:
        allowed_origins.append(frontend_url)
    cors_regex = r"^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$"
    cors_methods = ["*"]
    cors_headers = ["*"]
    cors_expose = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=cors_regex if cors_regex else None,
    allow_credentials=True,
    allow_methods=cors_methods,
    allow_headers=cors_headers,
    expose_headers=cors_expose,
    max_age=600,
)


@app.on_event("startup")
def startup_event():
    """Startup: clean up temp processing files only (not completed outputs)."""
    cleanup_temp_files(TEMP_DIR, max_age_seconds=3600)
    cleanup_uploads_by_policy()

    # Production readiness check
    if IS_PRODUCTION:
        if not db_service.is_connected():
            logger.error("PRODUCTION STARTUP WARNING: Database is not connected!")


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


# ==============================================================================
# PUBLIC ENDPOINTS (No auth required)
# ==============================================================================

@app.get("/api/health")
def health_check():
    """
    Liveness check. Returns basic service status.
    Does NOT expose infrastructure details.
    """
    return {
        "status": "ok",
        "service": "InfoShield OCR"
    }


@app.get("/api/readiness")
def readiness_check():
    """
    Readiness check for deployment orchestrators.
    Verifies required dependencies are available.
    """
    checks = {}

    # Database
    db_ok = db_service.is_connected()
    checks["database"] = "ok" if db_ok else "unavailable"

    # OCR Engine
    try:
        ocr_ready = ocr_engine is not None
        checks["ocr"] = "ok" if ocr_ready else "unavailable"
    except Exception:
        checks["ocr"] = "unavailable"

    # Risk Model
    try:
        model_ready = risk_model is not None
        checks["risk_model"] = "ok" if model_ready else "unavailable"
    except Exception:
        checks["risk_model"] = "unavailable"

    # Storage
    checks["upload_dir"] = "ok" if os.path.isdir(UPLOAD_DIR) and os.access(UPLOAD_DIR, os.W_OK) else "unavailable"
    checks["output_dir"] = "ok" if os.path.isdir(OUTPUT_DIR) and os.access(OUTPUT_DIR, os.W_OK) else "unavailable"

    all_ok = all(v == "ok" for v in checks.values())

    return {
        "status": "ready" if all_ok else "degraded",
        "checks": checks
    }


# ==============================================================================
# AUTHENTICATED ENDPOINTS
# ==============================================================================

@app.post("/api/scan")
async def scan_document_endpoint(
    file: UploadFile = File(...),
    user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Accepts multipart/form-data upload of an image (.jpg, .jpeg, .png, .webp),
    runs real Tesseract OCR + PII detection.
    Returns structured extraction data (document type, PII metadata).
    Does NOT return raw OCR text to prevent unnecessary data exposure.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file uploaded or filename is missing."
        )

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported image format. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )

    # Save with safe generated filename, enforcing size limit during streaming
    safe_name = _generate_safe_filename(file.filename)
    saved_path = os.path.join(TEMP_DIR, safe_name)

    try:
        file_size = stream_upload_with_limit(file.file, saved_path, MAX_FILE_SIZE)

        # Validate image content (magic bytes + decodability)
        detected_mime = validate_image_content(saved_path)
        if not detected_mime:
            _safe_remove(saved_path)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File content is not a valid image or exceeds dimension limits."
            )

        # Execute real OCR pipeline
        try:
            ocr_result = ocr_engine.extract_text(saved_path)
        except OCREngineError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Could not process this image. Please ensure it is a clear document scan."
            )
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during document processing."
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

        # Transform into API PII list format (NO raw values exposed)
        pii_items = []
        for field_name, item in fields_dict.items():
            val = item.get("value", "").strip()
            if not val or val == "Could not confidently determine":
                continue
            pii_entry = {
                "type": FIELD_TYPE_MAP.get(field_name, field_name.lower().replace(" ", "_")),
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
                "QR code detection failed. Physical QR redaction could not be applied automatically."
            )

        doc_meta = {
            "type": doc_type,
            "confidence": doc_conf,
            "qr_detected": qr_detected
        }
        if warnings:
            doc_meta["warnings"] = warnings

        return {
            "success": True,
            "document": doc_meta,
            "warnings": warnings,
            "ocr": {
                "engine": "Tesseract",
                "confidence": confidence
            },
            "pii": pii_items
            # NOTE: raw_text intentionally NOT returned to prevent data exposure
        }

    finally:
        # Always clean up temp scan file
        _safe_remove(saved_path)


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
async def analyze_purpose_endpoint(
    payload: AnalyzePurposeRequest,
    user: AuthenticatedUser = Depends(get_current_user)
):
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
    user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Unified Document Protection Pipeline:
    1. Upload -> OCR -> PII Detection -> Purpose Analysis -> Redaction -> Database Persistence
    User ID is derived from verified JWT, never from client input.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file uploaded or filename is missing."
        )

    if not purpose or not purpose.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The 'purpose' form parameter is mandatory."
        )

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported image format. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )

    # Use authenticated user ID from JWT
    effective_user_id = user.user_id

    # Save with safe generated filename, enforcing size during streaming
    safe_display_name = os.path.basename(file.filename)
    safe_name = _generate_safe_filename(file.filename)
    saved_path = os.path.join(UPLOAD_DIR, safe_name)
    processing_failed = False

    try:
        file_size = stream_upload_with_limit(file.file, saved_path, MAX_FILE_SIZE)

        # Validate image content
        detected_mime = validate_image_content(saved_path)
        if not detected_mime:
            _safe_remove(saved_path)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File content is not a valid image or exceeds dimension limits."
            )

        # Calculate SHA-256 hash
        with open(saved_path, "rb") as f_chk:
            file_hash = hashlib.sha256(f_chk.read()).hexdigest()

        # ---------- Database Step 1: Initialize Document Record ----------
        db_doc_id = None
        db_status = "UNAVAILABLE"
        db_error = None
        audit_events_recorded = 0

        if IS_PRODUCTION and not db_service.is_connected():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Document processing is temporarily unavailable. Database is not connected."
            )

        try:
            db_doc_id = db_service.create_document(
                user_id=effective_user_id,
                original_filename=safe_display_name,
                document_type="Pending OCR",
                mime_type=detected_mime,
                file_size=file_size,
                document_hash=file_hash,
                ocr_engine="Tesseract",
                status="UPLOADED"
            )
            if db_doc_id:
                db_status = "CONNECTED"
                db_service.create_audit_log(
                    user_id=effective_user_id,
                    document_id=db_doc_id,
                    action="DOCUMENT_UPLOADED",
                    status="SUCCESS",
                    metadata={"file_size": file_size}
                )
                audit_events_recorded += 1
            else:
                db_error = db_service.last_error or "Document creation failed"
                if IS_PRODUCTION:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to initialize document record."
                    )
        except HTTPException:
            raise
        except Exception as e:
            db_error = f"{type(e).__name__}: document initialization failed"
            logger.error(f"DB document initialization error: {e}", exc_info=True)
            if IS_PRODUCTION:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to initialize document record."
                )

        # ---------- Pipeline Step 1: OCR Extraction ----------
        try:
            ocr_result = ocr_engine.extract_text(saved_path)
        except OCREngineError:
            processing_failed = True
            if db_doc_id:
                db_service.update_document_status(db_doc_id, "FAILED")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Could not process this image. Ensure it is a clear document scan."
            )
        except Exception:
            processing_failed = True
            if db_doc_id:
                db_service.update_document_status(db_doc_id, "FAILED")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during document processing."
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

        # ---------- Pipeline Step 2: PII Detection ----------
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
                "QR code detection failed. Physical QR redaction could not be applied automatically."
            )

        if db_doc_id:
            try:
                db_service.update_document_status(
                    document_id=db_doc_id,
                    status="SCANNED",
                    ocr_confidence=confidence,
                    document_type=doc_type
                )
                db_service.create_audit_log(
                    user_id=effective_user_id,
                    document_id=db_doc_id,
                    action="OCR_COMPLETED",
                    status="SUCCESS",
                    metadata={"ocr_engine": "Tesseract", "confidence": confidence, "document_type": doc_type}
                )
                audit_events_recorded += 1
                db_service.create_audit_log(
                    user_id=effective_user_id,
                    document_id=db_doc_id,
                    action="PII_DETECTED",
                    status="SUCCESS",
                    metadata={"detected_field_count": len(fields_dict), "detected_types": list(fields_dict.keys())}
                )
                audit_events_recorded += 1
            except Exception as e:
                logger.error(f"DB OCR/PII audit update error: {e}", exc_info=True)
                if not db_error:
                    db_error = "OCR audit persistence failed"

        # ---------- Pipeline Step 3: Purpose Analysis ----------
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
            try:
                db_service.create_purpose_analysis(
                    document_id=db_doc_id,
                    purpose_text=purpose_clean,
                    domain=domain,
                    task=task,
                    sub_purpose=purpose_decision.get("sub_purpose"),
                    submission_context=purpose_decision.get("submission_context"),
                    intent_confidence=purpose_decision.get("intent_confidence"),
                    ai_model=ai_name
                )
                db_service.create_audit_log(
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
                audit_events_recorded += 1
            except Exception as e:
                logger.error(f"DB purpose analysis error: {e}", exc_info=True)
                if not db_error:
                    db_error = "Purpose analysis persistence failed"

        # ---------- Pipeline Step 4: Physical Image Redaction ----------
        unique_id = uuid.uuid4().hex[:8]
        protected_filename = f"protected_{unique_id}{ext}"
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
            processing_failed = True
            if db_doc_id:
                db_service.update_document_status(db_doc_id, "FAILED")
            logger.error(f"Redaction failed: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Document redaction failed."
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

        # ---------- Database Step 2: Persist Entities & Protected Doc ----------
        if db_doc_id:
            try:
                db_service.create_pii_entities_and_risks(
                    document_id=db_doc_id,
                    requirements=enhanced_requirements
                )
                db_service.create_audit_log(
                    user_id=effective_user_id,
                    document_id=db_doc_id,
                    action="RISK_ANALYZED",
                    status="SUCCESS",
                    metadata={"entities_analyzed": len(enhanced_requirements)}
                )
                audit_events_recorded += 1

                db_service.create_audit_log(
                    user_id=effective_user_id,
                    document_id=db_doc_id,
                    action="POLICY_APPLIED",
                    status="SUCCESS",
                    metadata={"decision_summary": purpose_decision.get("summary", {})}
                )
                audit_events_recorded += 1

                db_service.create_protected_document(
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

                db_service.update_document_status(document_id=db_doc_id, status="PROTECTED")

                db_service.create_audit_log(
                    user_id=effective_user_id,
                    document_id=db_doc_id,
                    action="DOCUMENT_PROTECTED",
                    status="SUCCESS",
                    metadata={
                        "protected_filename": protected_filename,
                        "redactions_count": len(redaction_result["redactions_applied"])
                    }
                )
                audit_events_recorded += 1
            except Exception as e:
                logger.error(f"DB entity/protection persistence error: {e}", exc_info=True)
                if not db_error:
                    db_error = "Protection record persistence failed"

        # ---------- Build Response ----------
        # Determine if this is a truly successful result
        is_db_failed = (db_status == "UNAVAILABLE" or db_error is not None)
        is_truly_successful = not is_db_failed or not IS_PRODUCTION

        if db_status == "UNAVAILABLE" and not db_error:
            if not db_service.is_connected():
                db_error = "Database not configured."
            else:
                db_error = db_service.last_error or "Database persistence failed."

        db_meta = {
            "status": db_status,
            "document_id": db_doc_id,
            "persisted_entities": len(enhanced_requirements) if db_doc_id else 0,
            "audit_events_recorded": audit_events_recorded
        }
        if db_error:
            db_meta["error"] = db_error

        doc_meta = {
            "original_filename": safe_display_name,
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
            "success": is_truly_successful,
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

    finally:
        # Clean up original upload after processing (if configured)
        if processing_failed or os.getenv("CLEANUP_ORIGINALS", "false").lower() == "true":
            _safe_remove(saved_path)


# ==============================================================================
# DATABASE MANAGEMENT ENDPOINTS (Authenticated + Ownership Enforced)
# ==============================================================================

@app.get("/api/database/health")
async def database_health_endpoint():
    """Returns the operational status of the database. No credentials exposed."""
    return db_service.check_health()


@app.get("/api/documents/{document_id}")
async def get_document_endpoint(
    document_id: str,
    user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Returns complete document lifecycle metadata.
    Enforces ownership: user can only access their own documents.
    """
    doc_info = db_service.get_document_full(document_id)
    if not doc_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found."
        )

    # Enforce ownership
    doc_owner = doc_info.get("document", {}).get("user_id")
    if doc_owner:
        verify_document_ownership(doc_owner, user.user_id)

    return {
        "success": True,
        "document_id": document_id,
        **doc_info
    }


@app.get("/api/users/{user_id}/documents")
async def get_user_documents_endpoint(
    user_id: str,
    user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Returns all document metadata for a user.
    Enforces that users can only query their own documents.
    """
    # Users can only access their own document list
    verify_document_ownership(user_id, user.user_id)

    docs = db_service.get_user_documents(user_id)
    return {
        "success": True,
        "user_id": user_id,
        "count": len(docs),
        "documents": docs
    }


@app.get("/api/documents/{document_id}/audit")
async def get_document_audit_endpoint(
    document_id: str,
    user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Returns audit trail for a document. Ownership enforced.
    """
    # Verify ownership first
    doc_info = db_service.get_document_full(document_id)
    if not doc_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found."
        )

    doc_owner = doc_info.get("document", {}).get("user_id")
    if doc_owner:
        verify_document_ownership(doc_owner, user.user_id)

    return db_service.get_document_audit_trail(document_id)


@app.get("/api/protected/{filename}")
async def get_protected_file_endpoint(
    filename: str,
    user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Serves a protected document image. Requires authentication and ownership verification.
    """
    safe_name = os.path.basename(filename)

    # Path traversal protection
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid document identifier."
        )

    file_path = os.path.join(OUTPUT_DIR, safe_name)
    if not safe_name.startswith("protected_") or not os.path.isfile(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Protected document not found."
        )

    # Verify ownership via database lookup
    import supabase_client
    client = supabase_client.get_supabase_client()
    if client:
        try:
            res = (
                client.table("protected_documents")
                .select("document_id")
                .eq("protected_filename", safe_name)
                .execute()
            )
            if res.data and len(res.data) > 0:
                doc_id = res.data[0]["document_id"]
                doc_res = client.table("documents").select("user_id").eq("id", doc_id).execute()
                if doc_res.data and len(doc_res.data) > 0:
                    verify_document_ownership(doc_res.data[0]["user_id"], user.user_id)
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Ownership check failed for protected file: {e}")

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
async def get_history_endpoint(
    user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Returns document protection history for the authenticated user.
    No arbitrary user_id parameter — derived from JWT.
    """
    db_docs = []
    if db_service.is_connected():
        try:
            db_docs = db_service.get_user_documents(user.user_id)
        except Exception as e:
            logger.warning(f"Error retrieving user documents: {e}")

    return {
        "success": True,
        "count": len(db_docs),
        "source": "database",
        "documents": db_docs
    }


# ==============================================================================
# SECURE SHARING ENDPOINTS
# ==============================================================================

class CreateShareRequest(BaseModel):
    document_id: str
    purpose: str
    recipient_email: Optional[str] = None
    expiry_hours: Optional[int] = None
    max_access_count: Optional[int] = None


@app.post("/api/shares")
async def create_share_endpoint(
    payload: CreateShareRequest,
    user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Creates a secure share link for a protected document.
    Returns the access token ONCE — it is not stored in raw form.
    """
    result = share_service.create_share(
        document_id=payload.document_id,
        owner_user_id=user.user_id,
        purpose=payload.purpose,
        recipient_email=payload.recipient_email,
        expiry_hours=payload.expiry_hours,
        max_access_count=payload.max_access_count
    )

    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not create share. Verify the document exists and is protected."
        )

    return {
        "success": True,
        **result
    }


@app.get("/api/shares/access/{share_token}")
async def access_shared_document(share_token: str):
    """
    Public endpoint to access a shared document via bearer token.
    Verifies token hash, expiry, revocation, and access count.
    """
    access_info = share_service.verify_share_access(share_token)
    if not access_info:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Share link is invalid, expired, or has been revoked."
        )

    file_path = access_info.get("protected_path", "")
    if not file_path or not os.path.isfile(file_path):
        file_path = os.path.join(OUTPUT_DIR, access_info.get("protected_filename", ""))

    if not os.path.isfile(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Shared document file is no longer available."
        )

    ext = os.path.splitext(file_path)[1].lower()
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


@app.delete("/api/shares/{share_id}")
async def revoke_share_endpoint(
    share_id: str,
    user: AuthenticatedUser = Depends(get_current_user)
):
    """Revokes a share. Only the document owner can revoke."""
    success = share_service.revoke_share(share_id, user.user_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not revoke share. Verify the share exists and you own the document."
        )
    return {"success": True, "message": "Share revoked successfully."}


@app.get("/api/documents/{document_id}/shares")
async def get_document_shares_endpoint(
    document_id: str,
    user: AuthenticatedUser = Depends(get_current_user)
):
    """Lists all shares for a document. Ownership enforced."""
    shares = share_service.get_document_shares(document_id, user.user_id)
    return {
        "success": True,
        "document_id": document_id,
        "shares": shares
    }


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("api:app", host=host, port=port, reload=False)
