"""
InfoShield AI - Secure Document Sharing Module
Implements cryptographic token-based document sharing with:
- High-entropy access tokens (hashed before storage)
- Configurable expiry
- Revocation support
- Audit trail integration
- Recipient verification
"""

import os
import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from uuid import uuid4

logger = logging.getLogger("infoshield.sharing")

# Default share configuration
DEFAULT_SHARE_EXPIRY_HOURS = int(os.getenv("SHARE_EXPIRY_HOURS", "72"))
SHARE_TOKEN_BYTES = 32  # 256-bit high-entropy token


def generate_share_token() -> str:
    """Generate a cryptographically secure share token."""
    return secrets.token_urlsafe(SHARE_TOKEN_BYTES)


def hash_share_token(token: str) -> str:
    """Hash a share token using SHA-256 for secure storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class ShareService:
    """
    Manages secure document sharing lifecycle:
    - Create share with token, expiry, and recipient constraints
    - Verify share access with token validation
    - Revoke shares
    - Audit share events
    """

    def __init__(self, db_service):
        self.db_service = db_service

    def create_share(
        self,
        document_id: str,
        owner_user_id: str,
        purpose: str,
        recipient_email: Optional[str] = None,
        expiry_hours: Optional[int] = None,
        max_access_count: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Creates a secure share for a document.

        Returns:
            Dict with share_id, raw access_token (shown once), and expiry.
            The raw token is NOT stored — only its SHA-256 hash.
        """
        import supabase_client
        client = supabase_client.get_supabase_client()
        if not client:
            logger.error("Cannot create share: database not available")
            return None

        # Verify document exists and is owned by requester
        try:
            doc_res = client.table("documents").select("id, user_id, status").eq("id", document_id).execute()
            if not doc_res.data or len(doc_res.data) == 0:
                logger.warning(f"Share creation failed: document {document_id} not found")
                return None
            doc = doc_res.data[0]
            if doc["user_id"] != owner_user_id:
                logger.warning(f"Share creation denied: user {owner_user_id} does not own document {document_id}")
                return None
            if doc.get("status") != "PROTECTED":
                logger.warning(f"Share creation denied: document {document_id} is not in PROTECTED status")
                return None
        except Exception as e:
            logger.error(f"Share creation - document lookup failed: {e}")
            return None

        # Generate token and hash
        raw_token = generate_share_token()
        token_hash = hash_share_token(raw_token)

        # Calculate expiry
        hours = expiry_hours or DEFAULT_SHARE_EXPIRY_HOURS
        expiry_at = datetime.now(timezone.utc) + timedelta(hours=hours)

        share_id = str(uuid4())
        share_record = {
            "id": share_id,
            "document_id": document_id,
            "owner_user_id": owner_user_id,
            "recipient_email": recipient_email,
            "token_hash": token_hash,
            "purpose": purpose,
            "expires_at": expiry_at.isoformat(),
            "max_access_count": max_access_count,
            "access_count": 0,
            "is_revoked": False,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        try:
            res = client.table("document_shares").insert(share_record).execute()
            if not res.data:
                logger.error("Share creation failed: no data returned from insert")
                return None

            # Audit log
            self.db_service.create_audit_log(
                user_id=owner_user_id,
                document_id=document_id,
                action="SHARE_CREATED",
                status="SUCCESS",
                metadata={
                    "share_id": share_id,
                    "recipient_email": recipient_email or "bearer_link",
                    "expiry_hours": hours,
                    "max_access_count": max_access_count
                }
            )

            return {
                "share_id": share_id,
                "access_token": raw_token,  # Shown to user ONCE
                "expires_at": expiry_at.isoformat(),
                "recipient_email": recipient_email,
                "max_access_count": max_access_count
            }
        except Exception as e:
            logger.error(f"Share creation failed: {e}")
            return None

    def verify_share_access(self, share_token: str) -> Optional[Dict[str, Any]]:
        """
        Verifies a share access token.

        Returns document access info if valid, None if invalid/expired/revoked.
        Increments access counter on successful verification.
        """
        import supabase_client
        client = supabase_client.get_supabase_client()
        if not client:
            return None

        token_hash = hash_share_token(share_token)

        try:
            res = (
                client.table("document_shares")
                .select("*")
                .eq("token_hash", token_hash)
                .eq("is_revoked", False)
                .execute()
            )
            if not res.data or len(res.data) == 0:
                logger.warning("Share access denied: invalid or revoked token")
                return None

            share = res.data[0]

            # Check expiry
            expires_at = datetime.fromisoformat(share["expires_at"].replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expires_at:
                logger.warning(f"Share access denied: expired at {share['expires_at']}")
                return None

            # Check access count limit
            if share.get("max_access_count") is not None:
                if share.get("access_count", 0) >= share["max_access_count"]:
                    logger.warning(f"Share access denied: max access count reached")
                    return None

            # Increment access count
            new_count = (share.get("access_count", 0) or 0) + 1
            client.table("document_shares").update({
                "access_count": new_count,
                "last_accessed_at": datetime.now(timezone.utc).isoformat()
            }).eq("id", share["id"]).execute()

            # Get protected document info
            doc_res = (
                client.table("protected_documents")
                .select("protected_filename, protected_path")
                .eq("document_id", share["document_id"])
                .execute()
            )
            if not doc_res.data:
                return None

            protected = doc_res.data[0]

            # Audit the access
            self.db_service.create_audit_log(
                user_id=share.get("owner_user_id"),
                document_id=share["document_id"],
                action="SHARE_ACCESSED",
                status="SUCCESS",
                metadata={
                    "share_id": share["id"],
                    "access_count": new_count
                }
            )

            return {
                "document_id": share["document_id"],
                "protected_filename": protected["protected_filename"],
                "protected_path": protected["protected_path"],
                "share_id": share["id"],
                "access_count": new_count,
                "expires_at": share["expires_at"]
            }
        except Exception as e:
            logger.error(f"Share verification failed: {e}")
            return None

    def revoke_share(self, share_id: str, owner_user_id: str) -> bool:
        """Revokes an active share. Only the document owner can revoke."""
        import supabase_client
        client = supabase_client.get_supabase_client()
        if not client:
            return False

        try:
            # Verify ownership
            res = (
                client.table("document_shares")
                .select("id, document_id, owner_user_id")
                .eq("id", share_id)
                .execute()
            )
            if not res.data or len(res.data) == 0:
                return False

            share = res.data[0]
            if share["owner_user_id"] != owner_user_id:
                logger.warning(f"Share revocation denied: user {owner_user_id} does not own share {share_id}")
                return False

            # Revoke
            client.table("document_shares").update({
                "is_revoked": True,
                "revoked_at": datetime.now(timezone.utc).isoformat()
            }).eq("id", share_id).execute()

            # Audit
            self.db_service.create_audit_log(
                user_id=owner_user_id,
                document_id=share["document_id"],
                action="SHARE_REVOKED",
                status="SUCCESS",
                metadata={"share_id": share_id}
            )

            return True
        except Exception as e:
            logger.error(f"Share revocation failed: {e}")
            return False

    def get_document_shares(self, document_id: str, owner_user_id: str) -> List[Dict[str, Any]]:
        """Lists all shares for a document owned by the requesting user."""
        import supabase_client
        client = supabase_client.get_supabase_client()
        if not client:
            return []

        try:
            res = (
                client.table("document_shares")
                .select("id, recipient_email, purpose, expires_at, access_count, max_access_count, is_revoked, created_at")
                .eq("document_id", document_id)
                .eq("owner_user_id", owner_user_id)
                .order("created_at", desc=True)
                .execute()
            )
            return res.data or []
        except Exception as e:
            logger.error(f"Share listing failed: {e}")
            return []
