"""
InfoShield AI - Supabase Service & Repository Layer (Phase 4B)
Encapsulates all database operations for:
- Users (demo user fallback)
- Documents metadata tracking (no raw OCR text)
- Purpose Analysis persistence
- PII Entities metadata & Bounding Boxes (strictly no raw PII values)
- ML Risk Predictions
- Policy Rules lookup
- Protected Documents records
- Chronological, Hash-Chained Audit Logging (SHA-256)
"""

import os
import json
import time
import logging
import hashlib
import traceback
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from uuid import uuid4

import supabase_client

logger = logging.getLogger("infoshield.supabase_service")

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


_LAST_TIMESTAMP = 0.0


def _now_iso() -> str:
    global _LAST_TIMESTAMP
    now = datetime.now(timezone.utc).timestamp()
    if now <= _LAST_TIMESTAMP:
        now = _LAST_TIMESTAMP + 0.001
    _LAST_TIMESTAMP = now
    return datetime.fromtimestamp(now, timezone.utc).isoformat()


def _sanitize_metadata(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Ensures no raw sensitive PII values leak into audit log metadata.
    Redacts keys that may hold raw sensitive values.
    """
    if not meta:
        return {}
    clean = {}
    sensitive_keys = {
        "value", "raw_value", "aadhaar", "phone", "mobile",
        "address", "dob", "date_of_birth", "pan", "passport", "signature"
    }
    for k, v in meta.items():
        k_lower = k.lower()
        if any(s in k_lower for s in sensitive_keys):
            clean[k] = "[REDACTED_BY_DATA_MINIMIZATION_POLICY]"
        elif isinstance(v, dict):
            clean[k] = _sanitize_metadata(v)
        elif isinstance(v, list):
            clean[k] = [
                _sanitize_metadata(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            clean[k] = v
    return clean


class SupabaseService:
    """
    Central database service repository for InfoShield.
    Handles persistence and queries with built-in resilience and fallbacks.
    """

    def __init__(self):
        self.demo_user_id = supabase_client.DEMO_USER_ID
        self.last_error: Optional[str] = None

    def _execute_with_retry(self, fn, description: str = "Supabase query", max_retries: int = 2):
        """
        Executes a PostgREST query with automatic retry for transient socket/read timeouts.
        Logs status clearly and captures the exception details.
        """
        last_exc = None
        for attempt in range(1, max_retries + 1):
            try:
                return fn()
            except Exception as e:
                last_exc = e
                err_text = str(e)
                is_transient = (
                    "timeout" in err_text.lower()
                    or "timed out" in err_text.lower()
                    or "timeout" in type(e).__name__.lower()
                    or "connection" in err_text.lower()
                )
                if attempt < max_retries and is_transient:
                    print(f"[SUPABASE DB RETRY] {description} hit transient network condition ({err_text}). Retrying attempt {attempt + 1}/{max_retries}...", flush=True)
                    time.sleep(0.5)
                    continue
                self.last_error = f"{type(e).__name__}: {err_text}"
                print(f"[SUPABASE DB ERROR] {description} FAILED: {self.last_error}", flush=True)
                logger.error(f"{description} FAILED: {e}", exc_info=True)
                raise
        raise last_exc

    def is_connected(self) -> bool:
        """Checks if Supabase is configured and reachable."""
        return supabase_client.is_configured()

    def check_health(self) -> Dict[str, Any]:
        """
        Returns the health status of the Supabase PostgreSQL connection.
        Never exposes secret keys in the response.
        """
        is_ok, msg = supabase_client.check_connection()
        if is_ok:
            return {
                "success": True,
                "database": "supabase",
                "status": "connected"
            }
        return {
            "success": False,
            "database": "supabase",
            "status": "unavailable",
            "error": msg
        }

    # --------------------------------------------------------------------------
    # 1. USER MANAGEMENT
    # --------------------------------------------------------------------------

    def ensure_demo_user(self) -> Optional[str]:
        """
        Ensures the default demo user exists in the database.
        Returns the user UUID on success, or None on failure.
        """
        client = supabase_client.get_supabase_client()
        if not client:
            return self.demo_user_id

        try:
            print(f"[SUPABASE DB] [Step 1/7] Ensuring demo user exists (ID: {self.demo_user_id})...", flush=True)
            res = self._execute_with_retry(
                lambda: client.table("users").select("id").eq("id", self.demo_user_id).execute(),
                description=f"User lookup ({self.demo_user_id})"
            )
            if res.data and len(res.data) > 0:
                print(f"[SUPABASE DB] [Step 1/7] Demo user confirmed: {self.demo_user_id}", flush=True)
                return self.demo_user_id

            # Insert demo user
            print(f"[SUPABASE DB] [Step 1/7] Demo user not found; creating demo user record...", flush=True)
            user_data = {
                "id": self.demo_user_id,
                "email": "demo.user@infoshield.ai",
                "name": "InfoShield Demo User",
                "created_at": _now_iso(),
                "updated_at": _now_iso()
            }
            ins_res = self._execute_with_retry(
                lambda: client.table("users").upsert(user_data).execute(),
                description="Demo user upsert"
            )
            if ins_res.data:
                print(f"[SUPABASE DB] [Step 1/7] Demo user created successfully: {self.demo_user_id}", flush=True)
                return self.demo_user_id
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {str(e)}"
            print(f"[SUPABASE DB ERROR] [Step 1/7] Could not ensure demo user: {self.last_error}", flush=True)
            logger.warning(f"Could not ensure demo user in database: {e}", exc_info=True)

        return self.demo_user_id

    def create_user(self, email: str, name: Optional[str] = None, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Creates or registers a new application user (without password)."""
        client = supabase_client.get_supabase_client()
        if not client:
            return None

        u_id = user_id or str(uuid4())
        record = {
            "id": u_id,
            "email": email.strip().lower(),
            "name": name,
            "created_at": _now_iso(),
            "updated_at": _now_iso()
        }
        try:
            res = client.table("users").insert(record).execute()
            return res.data[0] if res.data else None
        except Exception as e:
            logger.error(f"Failed to create user in database: {e}")
            return None

    # --------------------------------------------------------------------------
    # 2. DOCUMENT TRACKING
    # --------------------------------------------------------------------------

    def create_document(
        self,
        user_id: str,
        original_filename: str,
        document_type: str,
        mime_type: str = "image/png",
        file_size: Optional[int] = None,
        document_hash: Optional[str] = None,
        ocr_engine: str = "Tesseract",
        ocr_confidence: Optional[float] = None,
        status: str = "UPLOADED"
    ) -> Optional[str]:
        """
        Creates a new document record.
        Strictly does NOT store raw OCR text to minimize sensitive data exposure.
        """
        self.last_error = None
        client = supabase_client.get_supabase_client()
        doc_id = str(uuid4())

        if not client:
            self.last_error = "Supabase client not initialized or credentials unconfigured."
            print(f"[SUPABASE DB] [Step 2/7] {self.last_error} Proceeding without document DB persistence.", flush=True)
            logger.info("Supabase not active; proceeding without document DB persistence.")
            return None

        record = {
            "id": doc_id,
            "user_id": user_id,
            "original_filename": original_filename,
            "document_type": document_type,
            "mime_type": mime_type,
            "file_size": file_size,
            "document_hash": document_hash,
            "ocr_engine": ocr_engine,
            "ocr_confidence": ocr_confidence,
            "status": status,
            "created_at": _now_iso(),
            "updated_at": _now_iso()
        }
        try:
            print(f"[SUPABASE DB] [Step 2/7] Inserting into documents table: '{original_filename}' (doc_id={doc_id})...", flush=True)
            res = self._execute_with_retry(
                lambda: client.table("documents").insert(record).execute(),
                description=f"Insert document '{original_filename}'"
            )
            actual_id = res.data[0]["id"] if res.data else doc_id
            print(f"[SUPABASE DB] [Step 2/7] SUCCESS: Document created with ID: {actual_id}", flush=True)
            return actual_id
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {str(e)}"
            print(f"[SUPABASE DB ERROR] [Step 2/7] Failed to insert document into Supabase: {self.last_error}", flush=True)
            logger.error(f"Failed to insert document into Supabase: {e}", exc_info=True)
            return None

    def update_document_status(
        self,
        document_id: str,
        status: str,
        ocr_confidence: Optional[float] = None,
        document_type: Optional[str] = None
    ) -> bool:
        """Updates document status and OCR quality metrics."""
        client = supabase_client.get_supabase_client()
        if not client or not document_id:
            return False

        update_payload = {
            "status": status,
            "updated_at": _now_iso()
        }
        if ocr_confidence is not None:
            update_payload["ocr_confidence"] = ocr_confidence
        if document_type is not None:
            update_payload["document_type"] = document_type

        try:
            print(f"[SUPABASE DB] Updating document {document_id} status -> {status}...", flush=True)
            self._execute_with_retry(
                lambda: client.table("documents").update(update_payload).eq("id", document_id).execute(),
                description=f"Update document {document_id} status to {status}"
            )
            print(f"[SUPABASE DB] SUCCESS: Document {document_id} status updated to {status}", flush=True)
            return True
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {str(e)}"
            print(f"[SUPABASE DB ERROR] Failed to update document status: {self.last_error}", flush=True)
            logger.warning(f"Failed to update document status: {e}", exc_info=True)
            return False

    # --------------------------------------------------------------------------
    # 3. PURPOSE ANALYSIS PERSISTENCE
    # --------------------------------------------------------------------------

    def create_purpose_analysis(
        self,
        document_id: str,
        purpose_text: str,
        domain: str,
        task: str,
        sub_purpose: Optional[str] = None,
        submission_context: Optional[str] = None,
        intent_confidence: Optional[float] = None,
        ai_model: Optional[str] = None
    ) -> Optional[str]:
        """Persists Phase 4A AI semantic purpose classification results."""
        client = supabase_client.get_supabase_client()
        if not client or not document_id:
            return None

        analysis_id = str(uuid4())
        record = {
            "id": analysis_id,
            "document_id": document_id,
            "purpose_text": purpose_text,
            "domain": domain,
            "task": task,
            "sub_purpose": sub_purpose,
            "submission_context": submission_context,
            "intent_confidence": intent_confidence,
            "ai_model": ai_model,
            "created_at": _now_iso()
        }
        try:
            print(f"[SUPABASE DB] [Step 4/7] Inserting into purpose_analyses table for doc_id={document_id}...", flush=True)
            res = self._execute_with_retry(
                lambda: client.table("purpose_analyses").insert(record).execute(),
                description=f"Insert purpose analysis for {document_id}"
            )
            actual_id = res.data[0]["id"] if res.data else analysis_id
            print(f"[SUPABASE DB] [Step 4/7] SUCCESS: Purpose analysis created with ID: {actual_id}", flush=True)
            return actual_id
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {str(e)}"
            print(f"[SUPABASE DB ERROR] [Step 4/7] Failed to persist purpose analysis: {self.last_error}", flush=True)
            logger.error(f"Failed to persist purpose analysis: {e}", exc_info=True)
            return None

    # --------------------------------------------------------------------------
    # 4. PII ENTITIES & ML RISK PREDICTIONS
    # --------------------------------------------------------------------------

    def create_pii_entities_and_risks(
        self,
        document_id: str,
        requirements: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Persists detected PII metadata and ML risk predictions.
        CRITICAL SECURITY RULE: Raw extracted PII strings (Aadhaar, phone,
        address, DOB) are NEVER written to the database.
        """
        client = supabase_client.get_supabase_client()
        if not client or not document_id or not requirements:
            return []

        print(f"[SUPABASE DB] [Step 5/7] Persisting {len(requirements)} PII entities & risk predictions for doc_id={document_id}...", flush=True)
        created_entity_ids = []
        for req in requirements:
            pii_id = str(uuid4())
            pii_type = req.get("type", "unknown")
            conf = float(req.get("confidence") or 0.90)
            decision = req.get("decision", "UNNECESSARY")
            action = req.get("action", "FULL_MASK")

            risk_info = req.get("risk", {})
            risk_class = risk_info.get("class", req.get("risk_class"))
            risk_prob = risk_info.get("probability", req.get("risk_probability"))

            bbox = req.get("bbox") or {}
            bbox_x = bbox.get("x")
            bbox_y = bbox.get("y")
            bbox_w = bbox.get("width")
            bbox_h = bbox.get("height")

            entity_record = {
                "id": pii_id,
                "document_id": document_id,
                "pii_type": pii_type,
                "confidence": conf,
                "decision": decision,
                "action": action,
                "risk_class": risk_class,
                "risk_probability": risk_prob,
                "bbox_x": bbox_x,
                "bbox_y": bbox_y,
                "bbox_width": bbox_w,
                "bbox_height": bbox_h,
                "created_at": _now_iso()
            }

            try:
                e_res = self._execute_with_retry(
                    lambda: client.table("pii_entities").insert(entity_record).execute(),
                    description=f"Insert PII entity ({pii_type})"
                )
                actual_id = e_res.data[0]["id"] if e_res.data else pii_id
                created_entity_ids.append(actual_id)

                # Persist ML Risk Prediction row
                if risk_class and risk_prob is not None:
                    risk_record = {
                        "id": str(uuid4()),
                        "pii_entity_id": actual_id,
                        "model_name": risk_info.get("model", "RandomForestClassifier"),
                        "model_version": risk_info.get("version", "prototype-1"),
                        "risk_class": risk_class,
                        "risk_probability": float(risk_prob),
                        "created_at": _now_iso()
                    }
                    self._execute_with_retry(
                        lambda: client.table("risk_predictions").insert(risk_record).execute(),
                        description=f"Insert risk prediction for {pii_type}"
                    )

            except Exception as e:
                self.last_error = f"{type(e).__name__}: {str(e)}"
                print(f"[SUPABASE DB ERROR] [Step 5/7] Failed to persist PII entity ({pii_type}): {self.last_error}", flush=True)
                logger.warning(f"Failed to persist PII entity ({pii_type}): {e}", exc_info=True)

        print(f"[SUPABASE DB] [Step 5/7] SUCCESS: Persisted {len(created_entity_ids)}/{len(requirements)} PII entities into Supabase", flush=True)
        return created_entity_ids

    # --------------------------------------------------------------------------
    # 5. PROTECTED DOCUMENT RECORD
    # --------------------------------------------------------------------------

    def create_protected_document(
        self,
        document_id: str,
        protected_filename: str,
        protected_path: str,
        protection_status: str = "PROTECTED",
        total_detected: int = 0,
        fully_redacted: int = 0,
        partially_redacted: int = 0,
        preserved: int = 0,
        protection_summary: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        Records protected document image metadata and file references.
        Pixel data is maintained on disk / Storage, never as DB BLOBs.
        """
        client = supabase_client.get_supabase_client()
        if not client or not document_id:
            return None

        prot_id = str(uuid4())
        record = {
            "id": prot_id,
            "document_id": document_id,
            "protected_filename": protected_filename,
            "protected_path": protected_path,
            "protection_status": protection_status,
            "total_detected": total_detected,
            "fully_redacted": fully_redacted,
            "partially_redacted": partially_redacted,
            "preserved": preserved,
            "protection_summary": protection_summary or {},
            "created_at": _now_iso()
        }
        try:
            print(f"[SUPABASE DB] [Step 6/7] Inserting into protected_documents table for doc_id={document_id}...", flush=True)
            res = self._execute_with_retry(
                lambda: client.table("protected_documents").insert(record).execute(),
                description=f"Insert protected document '{protected_filename}'"
            )
            actual_id = res.data[0]["id"] if res.data else prot_id
            print(f"[SUPABASE DB] [Step 6/7] SUCCESS: Protected document created with ID: {actual_id}", flush=True)
            return actual_id
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {str(e)}"
            print(f"[SUPABASE DB ERROR] [Step 6/7] Failed to persist protected document record: {self.last_error}", flush=True)
            logger.error(f"Failed to persist protected document record: {e}", exc_info=True)
            return None

    # --------------------------------------------------------------------------
    # 6. HASH-CHAIN AUDIT LOGGING
    # --------------------------------------------------------------------------

    def create_audit_log(
        self,
        user_id: Optional[str],
        document_id: Optional[str],
        action: str,
        status: str = "SUCCESS",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        Creates a verifiable, tamper-evident audit log event using SHA-256 hash chaining.
        Formula:
            event_hash = SHA256(previous_hash + action + document_id + timestamp + sanitized_metadata)
        """
        client = supabase_client.get_supabase_client()
        if not client:
            return None

        # Sanitize metadata to guarantee zero raw PII values in audit trail
        clean_meta = _sanitize_metadata(metadata)
        now_ts = _now_iso()
        doc_id_str = str(document_id) if document_id else "GLOBAL"

        # Fetch the previous hash for this document
        prev_hash = GENESIS_HASH
        try:
            query = client.table("audit_logs").select("event_hash").order("created_at", desc=True).limit(1)
            if document_id:
                query = query.eq("document_id", document_id)
            prev_res = self._execute_with_retry(
                lambda: query.execute(),
                description=f"Fetch previous audit hash for {doc_id_str}"
            )
            if prev_res.data and len(prev_res.data) > 0 and prev_res.data[0].get("event_hash"):
                prev_hash = prev_res.data[0]["event_hash"]
        except Exception as e:
            logger.warning(f"Failed to fetch previous audit hash (using genesis default): {e}")

        # Compute deterministic SHA-256 event hash
        serialized_meta = json.dumps(clean_meta, sort_keys=True)
        hash_payload = f"{prev_hash}|{action}|{doc_id_str}|{now_ts}|{serialized_meta}"
        event_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

        audit_id = str(uuid4())
        record = {
            "id": audit_id,
            "user_id": user_id,
            "document_id": document_id,
            "action": action,
            "status": status,
            "metadata": clean_meta,
            "event_hash": event_hash,
            "previous_hash": prev_hash,
            "created_at": now_ts
        }
        try:
            print(f"[SUPABASE DB] [Audit Log] Recording '{action}' (doc_id={doc_id_str}, hash={event_hash[:12]}...)...", flush=True)
            res = self._execute_with_retry(
                lambda: client.table("audit_logs").insert(record).execute(),
                description=f"Insert audit log '{action}'"
            )
            actual_id = res.data[0]["id"] if res.data else audit_id
            print(f"[SUPABASE DB] [Audit Log] SUCCESS: Audit event '{action}' recorded with ID: {actual_id}", flush=True)
            return actual_id
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {str(e)}"
            print(f"[SUPABASE DB ERROR] [Audit Log] Failed to record audit log ({action}): {self.last_error}", flush=True)
            logger.error(f"Failed to record audit log ({action}): {e}", exc_info=True)
            return None

    # --------------------------------------------------------------------------
    # 7. POLICY RULES QUERY (WITH FALLBACK)
    # --------------------------------------------------------------------------

    def get_policy_rule(
        self,
        document_type: str,
        purpose_domain: str,
        purpose_task: str,
        pii_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        Attempts to read policy minimization rules from the database.
        Returns rule dict if found, or None to fall back to hardcoded policies.
        """
        client = supabase_client.get_supabase_client()
        if not client:
            return None

        try:
            res = (
                client.table("policy_rules")
                .select("*")
                .eq("document_type", document_type)
                .eq("purpose_domain", purpose_domain)
                .eq("purpose_task", purpose_task)
                .eq("pii_type", pii_type)
                .limit(1)
                .execute()
            )
            if res.data and len(res.data) > 0:
                return res.data[0]
        except Exception as e:
            logger.warning(f"Database policy query failed; utilizing local fallback: {e}")

        return None

    # --------------------------------------------------------------------------
    # 8. RETRIEVAL ENDPOINTS
    # --------------------------------------------------------------------------

    def get_document_full(self, document_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the complete document lifecycle record:
        - document metadata
        - purpose analysis
        - PII metadata & bounding boxes
        - ML risk predictions
        - protected document details
        - chronological audit trail
        IMPORTANT: Never returns raw PII values.
        """
        client = supabase_client.get_supabase_client()
        if not client or not document_id:
            return None

        try:
            doc_res = client.table("documents").select("*").eq("id", document_id).execute()
            if not doc_res.data or len(doc_res.data) == 0:
                return None
            doc_data = doc_res.data[0]

            # Fetch Purpose Analysis
            p_res = client.table("purpose_analyses").select("*").eq("document_id", document_id).execute()
            purpose_data = p_res.data[0] if p_res.data else None

            # Fetch PII Entities & Risk Predictions
            pii_res = client.table("pii_entities").select("*").eq("document_id", document_id).execute()
            pii_list = []
            for p in (pii_res.data or []):
                # Ensure no raw PII fields exist
                p_item = dict(p)
                p_item.pop("value", None)
                p_item.pop("raw_value", None)

                # Fetch risk prediction for this entity
                r_res = client.table("risk_predictions").select("*").eq("pii_entity_id", p["id"]).execute()
                p_item["risk_prediction"] = r_res.data[0] if r_res.data else None
                pii_list.append(p_item)

            # Fetch Protected Documents
            prot_res = client.table("protected_documents").select("*").eq("document_id", document_id).execute()
            protected_data = prot_res.data[0] if prot_res.data else None

            # Fetch Audit Trail
            audit_res = client.table("audit_logs").select("*").eq("document_id", document_id).order("created_at", desc=False).execute()
            audit_trail = audit_res.data or []

            return {
                "document": doc_data,
                "purpose_analysis": purpose_data,
                "pii_entities": pii_list,
                "protected_document": protected_data,
                "audit_trail": audit_trail
            }
        except Exception as e:
            logger.error(f"Failed to query full document record for {document_id}: {e}")
            return None

    def get_user_documents(self, user_id: str) -> List[Dict[str, Any]]:
        """Returns metadata for all documents uploaded by a user (metadata only)."""
        client = supabase_client.get_supabase_client()
        if not client or not user_id:
            return []

        try:
            res = (
                client.table("documents")
                .select("id, original_filename, document_type, mime_type, file_size, status, created_at, updated_at")
                .eq("user_id", user_id)
                .order("created_at", desc=True)
                .execute()
            )
            return res.data or []
        except Exception as e:
            logger.error(f"Failed to fetch user documents for {user_id}: {e}")
            return []

    def get_document_audit_trail(self, document_id: str) -> List[Dict[str, Any]]:
        """Returns chronological audit trail for a document with hash chain data."""
        client = supabase_client.get_supabase_client()
        if not client or not document_id:
            return []

        try:
            res = (
                client.table("audit_logs")
                .select("id, action, status, metadata, event_hash, previous_hash, created_at")
                .eq("document_id", document_id)
                .order("created_at", desc=False)
                .execute()
            )
            return res.data or []
        except Exception as e:
            logger.error(f"Failed to fetch audit trail for {document_id}: {e}")
            return []


# Global singleton instance
_GLOBAL_DB_SERVICE: Optional[SupabaseService] = None


def get_db_service() -> SupabaseService:
    """Returns the singleton instance of the Supabase service."""
    global _GLOBAL_DB_SERVICE
    if _GLOBAL_DB_SERVICE is None:
        _GLOBAL_DB_SERVICE = SupabaseService()
    return _GLOBAL_DB_SERVICE
