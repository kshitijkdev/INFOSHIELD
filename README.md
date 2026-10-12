# InfoShield — Purpose-Based PII Exposure Prevention Platform

> **Zero-trust, purpose-based data minimization assistant for identity document submissions.**

InfoShield physically conceals sensitive Personally Identifiable Information (PII) on document images based on what is strictly required for the user's specific submission context.

---

## 1. Project Architecture & Structure

```
InfoShield/
├── frontend/                     # Pure HTML5, CSS3 & Vanilla JavaScript UI
│   ├── index.html                # Single-page application (9 workflow screens)
│   ├── css/                      # Responsive stylesheets (mobile, desktop, components)
│   ├── js/app.js                 # Frontend application controller & API client
│   └── assets/                   # Static assets & icons
├── backend/                      # FastAPI Python Application
│   ├── api.py                    # HTTP API entrypoint
│   ├── ocr_engine.py             # Tesseract OCR & OpenCV QR detector
│   ├── pii_detector.py           # Structured PII entity detection
│   ├── purpose_ai.py             # Semantic purpose analysis layer
│   ├── purpose_engine.py         # Data minimization policy necessity engine
│   ├── redaction_engine.py       # OpenCV physical pixel blur & QR pixelation
│   ├── risk_model.py             # RandomForest exposure-risk prediction model
│   ├── supabase_client.py        # Supabase PostgreSQL client wrapper
│   ├── supabase_service.py       # 7-step transactional persistence & audit service
│   ├── ml_models/                # Trained ML models & metadata
│   ├── data/                     # Sensitivity configurations & training data
│   ├── test_images/              # Synthetic non-sensitive test specimens
│   ├── tests/                    # 45 automated pytest tests
│   ├── uploads/                  # Transient uploads directory (.gitkeep)
│   ├── outputs/                  # Protected documents output directory (.gitkeep)
│   ├── requirements.txt          # Python dependencies
│   ├── .env                      # Local environment configuration (private)
│   └── .env.example              # Environment variables template
├── database/                     # Database Definitions
│   ├── schema.sql                # Supabase PostgreSQL schema & RLS policies
│   └── seed.sql                  # Default policy rules & baseline seed data
├── docs/                         # Technical Documentation
│   ├── architecture.md           # System architecture & component design
│   ├── api.md                    # REST API endpoints & request/response schemas
│   └── testing.md                # Testing strategy & verification guide
├── scripts/                      # Developer Tooling & Verification Scripts
│   ├── start_backend.ps1         # Launches FastAPI backend on port 8000
│   ├── start_frontend.ps1        # Launches frontend web server on port 3000
│   └── verify_system.ps1         # Full pipeline automated verification script
├── .gitignore                    # Production gitignore (excluding .env, outputs, uploads)
└── README.md                     # Root project documentation
```

---

## 2. Prerequisites

1. **Python 3.11+**
2. **Tesseract OCR**:
   - Windows installation:
     ```powershell
     winget install UB-Mannheim.TesseractOCR
     ```
   - Standard binary path: `C:\Program Files\Tesseract-OCR\tesseract.exe` (or in User `AppData`).
3. **Web Browser**: Chrome, Edge, or Firefox.

---

## 3. Installation & Setup

1. **Clone or navigate to the project root**:
   ```powershell
   cd path\to\InfoShield  # e.g., cd C:\Users\YourUser\Downloads\InfoShield
   ```

2. **Set up Python Virtual Environment**:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. **Install Dependencies**:
   ```powershell
   pip install -r backend/requirements.txt
   ```

4. **Environment Variables**:
   Copy the example environment template into `backend/.env`:
   ```powershell
   copy backend\.env.example backend\.env
   ```
   Add your Supabase project credentials in `backend/.env`:
   ```ini
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
   DEMO_USER_ID=00000000-0000-0000-0000-000000000001
   ```
   *(If Supabase credentials are not configured, the system automatically runs with graceful local fallback).*

---

## 4. Running the Platform

### Start the Backend (Port 8000)
Run using the provided script:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_backend.ps1
```
*Or directly via Python:*
```powershell
cd backend
python -m uvicorn api:app --reload --host 127.0.0.1 --port 8000
```
- API Base URL: `http://127.0.0.1:8000`
- API Health: `http://127.0.0.1:8000/api/health`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`

### Start the Frontend (Port 3000)
Run using the provided script:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_frontend.ps1
```
*Or directly via Python:*
```powershell
python -m http.server 3000 --directory frontend
```
- Frontend UI: `http://127.0.0.1:3000`

---

## 5. Verification & Testing

### Run Automated Backend Tests (45 Tests)
```powershell
cd backend
python -m pytest
```

### Run End-to-End System Verification
```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify_system.ps1
```

---

## 6. Security Principles

- **Zero-Trust Physical Redaction**: Unnecessary PII is physically blurred (Gaussian blur) and QR codes are irreversibly pixelated before writing to disk.
- **Credential Isolation**: Database service-role keys are kept exclusively backend-side in `.env` and are excluded from Git.
- **Zero Client Leaks**: Raw OCR text and unredacted PII values are never logged to browser consoles.
