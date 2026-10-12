-- =============================================================================
-- InfoShield - Supabase PostgreSQL Database Schema
-- Phase 4B: Persistent Purpose-Based PII Exposure Prevention Backend
-- =============================================================================

-- Ensure UUID generator extension is present
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- 1. USERS TABLE
-- -----------------------------------------------------------------------------
-- Stores application user identity metadata.
-- Prototype supports explicit demo user (DEMO_USER_ID).
-- Passwords are strictly NOT stored here.
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- 2. DOCUMENTS TABLE
-- -----------------------------------------------------------------------------
-- Core document tracking table.
-- Raw OCR text is NOT stored by default to adhere to data minimization.
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_filename TEXT NOT NULL,
    document_type TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    file_size BIGINT,
    document_hash TEXT,
    ocr_engine TEXT NOT NULL,
    ocr_confidence NUMERIC,
    status TEXT NOT NULL DEFAULT 'UPLOADED' CHECK (status IN ('UPLOADED', 'SCANNED', 'ANALYZED', 'PROTECTED', 'FAILED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- 3. PURPOSE ANALYSES TABLE
-- -----------------------------------------------------------------------------
-- Stores semantic purpose understanding results produced by Phase 4A AI engine.
CREATE TABLE IF NOT EXISTS purpose_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    purpose_text TEXT NOT NULL,
    domain TEXT NOT NULL,
    task TEXT NOT NULL,
    sub_purpose TEXT,
    submission_context TEXT,
    intent_confidence NUMERIC,
    ai_model TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- 4. PII ENTITIES TABLE
-- -----------------------------------------------------------------------------
-- Stores detected PII metadata, bounding box coordinates, and policy decisions.
-- SECURITY RULE: Raw sensitive PII values (Aadhaar numbers, phone numbers,
-- address strings, DOB) are NEVER persisted in this table.
CREATE TABLE IF NOT EXISTS pii_entities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    pii_type TEXT NOT NULL,
    confidence NUMERIC NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('REQUIRED', 'CONDITIONAL', 'UNNECESSARY')),
    action TEXT NOT NULL CHECK (action IN ('PRESERVED', 'PARTIAL_MASK', 'FULL_MASK')),
    risk_class TEXT CHECK (risk_class IN ('LOW', 'MEDIUM', 'HIGH')),
    risk_probability NUMERIC,
    bbox_x INTEGER,
    bbox_y INTEGER,
    bbox_width INTEGER,
    bbox_height INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- 5. RISK PREDICTIONS TABLE
-- -----------------------------------------------------------------------------
-- ML exposure-risk predictions from the RandomForestClassifier.
CREATE TABLE IF NOT EXISTS risk_predictions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pii_entity_id UUID NOT NULL REFERENCES pii_entities(id) ON DELETE CASCADE,
    model_name TEXT NOT NULL,
    model_version TEXT NOT NULL,
    risk_class TEXT NOT NULL CHECK (risk_class IN ('LOW', 'MEDIUM', 'HIGH')),
    risk_probability NUMERIC NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- 6. POLICY RULES TABLE
-- -----------------------------------------------------------------------------
-- Statutory data minimization rules per document type and domain task.
-- Reference configuration table.
CREATE TABLE IF NOT EXISTS policy_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_type TEXT NOT NULL,
    purpose_domain TEXT NOT NULL,
    purpose_task TEXT NOT NULL,
    pii_type TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('REQUIRED', 'CONDITIONAL', 'UNNECESSARY')),
    mask_strategy TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_policy_rule UNIQUE (document_type, purpose_domain, purpose_task, pii_type)
);

-- -----------------------------------------------------------------------------
-- 7. PROTECTED DOCUMENTS TABLE
-- -----------------------------------------------------------------------------
-- Metadata and paths for physically redacted document images.
-- Binary pixel data is stored in the local file system or Supabase Storage,
-- NOT as raw BLOBs in PostgreSQL.
CREATE TABLE IF NOT EXISTS protected_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    protected_filename TEXT NOT NULL,
    protected_path TEXT NOT NULL,
    protection_status TEXT NOT NULL DEFAULT 'PROTECTED',
    total_detected INTEGER NOT NULL DEFAULT 0,
    fully_redacted INTEGER NOT NULL DEFAULT 0,
    partially_redacted INTEGER NOT NULL DEFAULT 0,
    preserved INTEGER NOT NULL DEFAULT 0,
    protection_summary JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- 8. AUDIT LOGS TABLE (HASH-CHAIN VERIFIABLE)
-- -----------------------------------------------------------------------------
-- Chronological event log with SHA-256 hash chaining for tamper evidence.
-- No raw PII is permitted inside the metadata JSONB.
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    document_id UUID REFERENCES documents(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'SUCCESS',
    metadata JSONB,
    event_hash TEXT,
    previous_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =============================================================================
-- PERFORMANCE INDEXES
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);
CREATE INDEX IF NOT EXISTS idx_purpose_analyses_document_id ON purpose_analyses(document_id);
CREATE INDEX IF NOT EXISTS idx_pii_entities_document_id ON pii_entities(document_id);
CREATE INDEX IF NOT EXISTS idx_risk_predictions_pii_entity_id ON risk_predictions(pii_entity_id);
CREATE INDEX IF NOT EXISTS idx_protected_documents_document_id ON protected_documents(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_document_id ON audit_logs(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_policy_rules_lookup ON policy_rules(document_type, purpose_domain, purpose_task, pii_type);

-- =============================================================================
-- ROW LEVEL SECURITY (RLS)
-- =============================================================================
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE purpose_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE pii_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_predictions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE protected_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Service role access policies (FastAPI backend uses service role key)
CREATE POLICY service_role_users ON users FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_documents ON documents FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_purpose ON purpose_analyses FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_pii ON pii_entities FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_risk ON risk_predictions FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_policy ON policy_rules FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_protected ON protected_documents FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_audit ON audit_logs FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Authenticated user policies (Users access only their own records)
CREATE POLICY user_own_documents ON documents FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY user_own_purpose ON purpose_analyses FOR SELECT TO authenticated USING (EXISTS (SELECT 1 FROM documents WHERE documents.id = purpose_analyses.document_id AND documents.user_id = auth.uid()));
CREATE POLICY user_own_pii ON pii_entities FOR SELECT TO authenticated USING (EXISTS (SELECT 1 FROM documents WHERE documents.id = pii_entities.document_id AND documents.user_id = auth.uid()));
CREATE POLICY user_own_protected ON protected_documents FOR SELECT TO authenticated USING (EXISTS (SELECT 1 FROM documents WHERE documents.id = protected_documents.document_id AND documents.user_id = auth.uid()));
CREATE POLICY user_own_audit ON audit_logs FOR SELECT TO authenticated USING (user_id = auth.uid() OR EXISTS (SELECT 1 FROM documents WHERE documents.id = audit_logs.document_id AND documents.user_id = auth.uid()));

-- Policy rules reference table is read-only for authenticated and public
CREATE POLICY read_policy_rules ON policy_rules FOR SELECT TO anon, authenticated USING (true);
