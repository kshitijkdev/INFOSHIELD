-- =============================================================================
-- InfoShield - Supabase Seed Data
-- Phase 4B: Prototype Policy Rules and Demo User
-- =============================================================================
-- DISCLAIMER:
-- Prototype policy rules are demonstration-grade representations of data
-- minimization standards and require formal validation against real organizational
-- governance policies before production use.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 0. DEFAULT DEMO USER
-- -----------------------------------------------------------------------------
INSERT INTO users (id, email, name)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'demo.user@infoshield.ai',
    'InfoShield Demo User'
)
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 1. AADHAAR CARD POLICIES
-- -----------------------------------------------------------------------------

-- Context: Aadhaar + College Admission
INSERT INTO policy_rules (document_type, purpose_domain, purpose_task, pii_type, decision, mask_strategy, reason)
VALUES
('Aadhaar Card', 'education', 'college_admission', 'person_name', 'REQUIRED', 'PRESERVED', 'Needed to verify identity of applicant.'),
('Aadhaar Card', 'education', 'college_admission', 'date_of_birth', 'CONDITIONAL', 'LAST_4', 'May be required for age eligibility verification.'),
('Aadhaar Card', 'education', 'college_admission', 'gender', 'CONDITIONAL', 'PRESERVED', 'May be relevant for category reservation or hostel allocation.'),
('Aadhaar Card', 'education', 'college_admission', 'mobile_number', 'UNNECESSARY', 'FULL_MASK', 'Not required for academic admission verification; contact info is captured on form.'),
('Aadhaar Card', 'education', 'college_admission', 'aadhaar_number', 'CONDITIONAL', 'LAST_4', 'Full Aadhaar exposure should not be assumed necessary; masked Aadhaar is sufficient.'),
('Aadhaar Card', 'education', 'college_admission', 'vid', 'UNNECESSARY', 'FULL_MASK', 'Virtual ID not required for academic enrollment.'),
('Aadhaar Card', 'education', 'college_admission', 'address', 'CONDITIONAL', 'PARTIAL_MASK', 'State/district may be needed for domicile verification; street details masked.'),
('Aadhaar Card', 'education', 'college_admission', 'qr_code', 'UNNECESSARY', 'FULL_MASK', 'Embedded biometrics and cryptographic data are unnecessary for academic admission.')
ON CONFLICT (document_type, purpose_domain, purpose_task, pii_type) DO UPDATE
SET decision = EXCLUDED.decision, mask_strategy = EXCLUDED.mask_strategy, reason = EXCLUDED.reason, updated_at = now();

-- Context: Aadhaar + Scholarship
INSERT INTO policy_rules (document_type, purpose_domain, purpose_task, pii_type, decision, mask_strategy, reason)
VALUES
('Aadhaar Card', 'education', 'scholarship', 'person_name', 'REQUIRED', 'PRESERVED', 'Essential for cross-matching student applicant with scholarship roster.'),
('Aadhaar Card', 'education', 'scholarship', 'date_of_birth', 'REQUIRED', 'PRESERVED', 'Required for verifying age eligibility under scheme guidelines.'),
('Aadhaar Card', 'education', 'scholarship', 'gender', 'REQUIRED', 'PRESERVED', 'Required for gender-specific scholarship quotas.'),
('Aadhaar Card', 'education', 'scholarship', 'mobile_number', 'CONDITIONAL', 'LAST_4', 'SMS notification token verification; full digits unnecessary.'),
('Aadhaar Card', 'education', 'scholarship', 'aadhaar_number', 'CONDITIONAL', 'LAST_4', 'Direct Benefit Transfer linking verification; mask first 8 digits.'),
('Aadhaar Card', 'education', 'scholarship', 'vid', 'UNNECESSARY', 'FULL_MASK', 'Virtual ID not required when UID token is supplied.'),
('Aadhaar Card', 'education', 'scholarship', 'address', 'REQUIRED', 'PRESERVED', 'Domicile verification is mandatory for state scholarship schemes.'),
('Aadhaar Card', 'education', 'scholarship', 'qr_code', 'UNNECESSARY', 'FULL_MASK', 'Barcode scanning not utilized in standard scholarship processing.')
ON CONFLICT (document_type, purpose_domain, purpose_task, pii_type) DO UPDATE
SET decision = EXCLUDED.decision, mask_strategy = EXCLUDED.mask_strategy, reason = EXCLUDED.reason, updated_at = now();

-- Context: Aadhaar + Financial Aid
INSERT INTO policy_rules (document_type, purpose_domain, purpose_task, pii_type, decision, mask_strategy, reason)
VALUES
('Aadhaar Card', 'education', 'financial_aid', 'person_name', 'REQUIRED', 'PRESERVED', 'Applicant identity binding for financial assistance.'),
('Aadhaar Card', 'education', 'financial_aid', 'date_of_birth', 'CONDITIONAL', 'LAST_4', 'Age verification for dependent eligibility status.'),
('Aadhaar Card', 'education', 'financial_aid', 'gender', 'CONDITIONAL', 'PRESERVED', 'Quota eligibility determination.'),
('Aadhaar Card', 'education', 'financial_aid', 'mobile_number', 'UNNECESSARY', 'FULL_MASK', 'Contact details collected via main financial application form.'),
('Aadhaar Card', 'education', 'financial_aid', 'aadhaar_number', 'CONDITIONAL', 'LAST_4', 'Aadhaar masking standard under UIDAI regulations (first 8 digits masked).'),
('Aadhaar Card', 'education', 'financial_aid', 'vid', 'UNNECESSARY', 'FULL_MASK', 'Virtual ID not required.'),
('Aadhaar Card', 'education', 'financial_aid', 'address', 'CONDITIONAL', 'PARTIAL_MASK', 'Local domicile verification only; street details masked.'),
('Aadhaar Card', 'education', 'financial_aid', 'qr_code', 'UNNECESSARY', 'FULL_MASK', 'Cryptographic payload unnecessary for financial aid audit.')
ON CONFLICT (document_type, purpose_domain, purpose_task, pii_type) DO UPDATE
SET decision = EXCLUDED.decision, mask_strategy = EXCLUDED.mask_strategy, reason = EXCLUDED.reason, updated_at = now();

-- Context: Aadhaar + Banking KYC
INSERT INTO policy_rules (document_type, purpose_domain, purpose_task, pii_type, decision, mask_strategy, reason)
VALUES
('Aadhaar Card', 'banking', 'kyc', 'person_name', 'REQUIRED', 'PRESERVED', 'Mandatory customer identification for bank account opening.'),
('Aadhaar Card', 'banking', 'kyc', 'date_of_birth', 'REQUIRED', 'PRESERVED', 'Mandatory for customer age and minor/major account status determination.'),
('Aadhaar Card', 'banking', 'kyc', 'gender', 'REQUIRED', 'PRESERVED', 'Mandatory regulatory KYC demographic requirement.'),
('Aadhaar Card', 'banking', 'kyc', 'mobile_number', 'REQUIRED', 'PRESERVED', 'Mandatory for two-factor authentication and transaction alerts.'),
('Aadhaar Card', 'banking', 'kyc', 'aadhaar_number', 'CONDITIONAL', 'LAST_4', 'RBI/UIDAI compliance mandates masked Aadhaar (first 8 digits obscured).'),
('Aadhaar Card', 'banking', 'kyc', 'vid', 'CONDITIONAL', 'LAST_4', 'Allowed alternate identifier if masked UID is utilized.'),
('Aadhaar Card', 'banking', 'kyc', 'address', 'REQUIRED', 'PRESERVED', 'Proof of Address is a core regulatory KYC mandate.'),
('Aadhaar Card', 'banking', 'kyc', 'qr_code', 'CONDITIONAL', 'PRESERVED', 'May be scanned by banking agent for offline e-KYC XML verification.')
ON CONFLICT (document_type, purpose_domain, purpose_task, pii_type) DO UPDATE
SET decision = EXCLUDED.decision, mask_strategy = EXCLUDED.mask_strategy, reason = EXCLUDED.reason, updated_at = now();


-- -----------------------------------------------------------------------------
-- 2. PAN CARD POLICIES
-- -----------------------------------------------------------------------------

-- Context: PAN + Job Application / Onboarding
INSERT INTO policy_rules (document_type, purpose_domain, purpose_task, pii_type, decision, mask_strategy, reason)
VALUES
('PAN Card', 'employment', 'job_application', 'person_name', 'REQUIRED', 'PRESERVED', 'Candidate identity validation against application.'),
('PAN Card', 'employment', 'job_application', 'date_of_birth', 'CONDITIONAL', 'LAST_4', 'Birth date verification for minimum legal working age.'),
('PAN Card', 'employment', 'job_application', 'pan_number', 'CONDITIONAL', 'LAST_4', 'Tax identifier masking during early candidate screening stage.'),
('PAN Card', 'employment', 'job_application', 'father_name', 'UNNECESSARY', 'FULL_MASK', 'Parental name is irrelevant for employment suitability assessment.'),
('PAN Card', 'employment', 'job_application', 'signature', 'UNNECESSARY', 'FULL_MASK', 'Biometric signature exposure risk during recruitment stage.')
ON CONFLICT (document_type, purpose_domain, purpose_task, pii_type) DO UPDATE
SET decision = EXCLUDED.decision, mask_strategy = EXCLUDED.mask_strategy, reason = EXCLUDED.reason, updated_at = now();

-- Context: PAN + Banking
INSERT INTO policy_rules (document_type, purpose_domain, purpose_task, pii_type, decision, mask_strategy, reason)
VALUES
('PAN Card', 'banking', 'kyc', 'person_name', 'REQUIRED', 'PRESERVED', 'Tax entity name matching with bank records.'),
('PAN Card', 'banking', 'kyc', 'date_of_birth', 'REQUIRED', 'PRESERVED', 'Core verification against central tax database.'),
('PAN Card', 'banking', 'kyc', 'pan_number', 'REQUIRED', 'PRESERVED', 'Statutory requirement for high-value financial reporting and TDS.'),
('PAN Card', 'banking', 'kyc', 'father_name', 'CONDITIONAL', 'PRESERVED', 'Used as secondary identity disambiguation token.'),
('PAN Card', 'banking', 'kyc', 'signature', 'REQUIRED', 'PRESERVED', 'Signature specimen verification for branch transactions.')
ON CONFLICT (document_type, purpose_domain, purpose_task, pii_type) DO UPDATE
SET decision = EXCLUDED.decision, mask_strategy = EXCLUDED.mask_strategy, reason = EXCLUDED.reason, updated_at = now();


-- -----------------------------------------------------------------------------
-- 3. PASSPORT POLICIES
-- -----------------------------------------------------------------------------

-- Context: Passport + Visa Application
INSERT INTO policy_rules (document_type, purpose_domain, purpose_task, pii_type, decision, mask_strategy, reason)
VALUES
('Passport', 'travel', 'visa_application', 'person_name', 'REQUIRED', 'PRESERVED', 'Consular identity verification.'),
('Passport', 'travel', 'visa_application', 'date_of_birth', 'REQUIRED', 'PRESERVED', 'Consular international border requirement.'),
('Passport', 'travel', 'visa_application', 'passport_number', 'REQUIRED', 'PRESERVED', 'Primary international travel identifier.'),
('Passport', 'travel', 'visa_application', 'nationality', 'REQUIRED', 'PRESERVED', 'Sovereign border admission requirement.'),
('Passport', 'travel', 'visa_application', 'address', 'CONDITIONAL', 'PARTIAL_MASK', 'Permanent residence jurisdiction only.'),
('Passport', 'travel', 'visa_application', 'mrz_code', 'REQUIRED', 'PRESERVED', 'Machine-readable zone verification by consular border systems.')
ON CONFLICT (document_type, purpose_domain, purpose_task, pii_type) DO UPDATE
SET decision = EXCLUDED.decision, mask_strategy = EXCLUDED.mask_strategy, reason = EXCLUDED.reason, updated_at = now();
