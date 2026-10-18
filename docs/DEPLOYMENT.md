# InfoShield — Deployment and Production Guide

This guide describes how to configure, test, secure, and deploy InfoShield to cloud environments (Render, Vercel, Supabase).

---

## 1. System Architecture

```
[User Browser] (Vanilla HTML / CSS / JS)
       │
       │ (HTTPS + Verified Supabase Auth JWT)
       ▼
[FastAPI Backend] (Render / Docker)
       ├── Authentication & Authorization (`auth.py`)
       ├── Cryptographic Document Sharing (`sharing.py`)
       ├── OCR Engine (`ocr_engine.py` with Tesseract)
       ├── PII Detection (`pii_detector.py`)
       ├── Purpose Analysis & Policy Engine (`purpose_engine.py`)
       ├── Physical Pixel Redaction (`redaction_engine.py`)
       └── Exposure Risk ML (`risk_model.py`)
       │
       │ (PostgreSQL over HTTPS / Service-Role)
       ▼
[Supabase Database]
       ├── Documents, Analyses, PII Metadata
       ├── Document Shares (hashed access tokens)
       ├── Tamper-evident SHA-256 Audit Logs
       └── Row-Level Security (RLS) Policies
```

---

## 2. Environment Variables & Secret Configuration

Configure these environment variables in your hosting provider (e.g., Render Dashboard):

| Variable | Description | Production Value |
|---|---|---|
| `ENV` | Environment mode | `production` |
| `SUPABASE_URL` | Supabase project URL | `https://your-project-id.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase backend service role key | Private key (never in frontend) |
| `SUPABASE_JWT_SECRET` | Supabase project JWT secret | Project JWT secret (from Supabase API settings) |
| `AUTH_ENABLED` | Enforce JWT verification on all protected routes | `true` |
| `ALLOWED_ORIGINS` | Exact allowed frontend origins | `https://your-app.vercel.app` |
| `ALLOWED_ORIGIN_REGEX` | Optional narrow regex for origins | Leave empty or strictly specify trusted subdomains |
| `SHARE_EXPIRY_HOURS` | Default expiry for bearer shares | `72` |
| `CLEANUP_ORIGINALS` | Policy for raw input uploads | `true` or `false` |
| `UPLOAD_RETENTION_SECONDS` | Maximum lifetime for raw uploads | `3600` |

---

## 3. Database Setup

1. Open your Supabase Dashboard -> **SQL Editor**.
2. Run `database/schema.sql`:
   - Creates `users`, `documents`, `purpose_analyses`, `pii_entities`, `risk_predictions`, `policy_rules`, `protected_documents`, `audit_logs`, and `document_shares`.
   - Creates performance indexes and enables Row Level Security (RLS) on all tables.
3. Run `database/seed.sql` to populate baseline data minimization policies.

---

## 4. Frontend Deployment (Vercel or Static Host)

1. Set the production backend URL in `frontend/js/config.js`:
   ```javascript
   window.INFOSHIELD_CONFIG = {
     BACKEND_URL: "https://your-backend.onrender.com"
   };
   ```
2. Deploy the `frontend/` directory to Vercel or your static host.
3. Notice: The untrusted `?backend=` query parameter override is automatically disabled in production.

---

## 5. Backend Deployment (Render / Docker)

1. Use the included `Dockerfile`:
   - Installs Tesseract OCR binaries and leptonica libraries (`tesseract-ocr`, `libtesseract-dev`).
   - Installs Python dependencies from `requirements.txt`.
   - Runs `uvicorn api:app --host 0.0.0.0 --port 8000`.
2. Connect your Git repository to Render as a Web Service:
   - Environment: Docker
   - Branch: `main`
   - Add environment variables defined in Section 2.
3. Health check path: `/api/health`
4. Readiness check path: `/api/readiness`
