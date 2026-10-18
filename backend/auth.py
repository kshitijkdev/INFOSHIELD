"""
InfoShield AI - Authentication & Authorization Module
Implements Supabase Auth JWT verification for all protected API routes.

Architecture:
- Verifies Supabase JWTs using the project's JWT secret.
- Extracts authenticated user_id from verified token claims.
- Never trusts client-supplied user_id or arbitrary headers.
- Provides FastAPI dependency injection for route protection.
- Enforces document ownership checks at the service layer.
"""

import os
import logging
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger("infoshield.auth")

# HTTP Bearer token extractor
_bearer_scheme = HTTPBearer(auto_error=False)


def _get_jwt_secret() -> str:
    """Read SUPABASE_JWT_SECRET dynamically from environment."""
    return os.getenv("SUPABASE_JWT_SECRET", "").strip()


def _is_auth_enabled() -> bool:
    """Check if authentication is enabled. Disabled only in explicit dev or test mode when requested."""
    auth_enabled = os.getenv("AUTH_ENABLED", "true").strip().lower()
    env_mode = os.getenv("ENV", "development").strip().lower()
    if auth_enabled == "false" and env_mode in ("development", "dev", "test"):
        return False
    return True


def _verify_jwt(token: str) -> Dict[str, Any]:
    """
    Verifies a Supabase JWT and returns decoded claims.
    Uses PyJWT for verification against the Supabase JWT secret.
    """
    secret = _get_jwt_secret()
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured. Set SUPABASE_JWT_SECRET."
        )

    try:
        import jwt as pyjwt
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication dependency (PyJWT) is not installed."
        )

    try:
        # Supabase uses HS256 by default with the JWT secret
        decoded = pyjwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            audience="authenticated",
            options={
                "require": ["sub", "exp", "iat"],
                "verify_exp": True,
                "verify_aud": True,
            }
        )
        return decoded
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except pyjwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"}
        )


class AuthenticatedUser:
    """Represents a verified authenticated user."""
    def __init__(self, user_id: str, email: Optional[str] = None, role: Optional[str] = None):
        self.user_id = user_id
        self.email = email
        self.role = role


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme)
) -> AuthenticatedUser:
    """
    FastAPI dependency that extracts and verifies the authenticated user.
    Returns AuthenticatedUser on success, raises 401 on failure.
    """
    if not _is_auth_enabled():
        # Dev mode with auth disabled — use demo user but log warning
        demo_id = os.getenv("DEMO_USER_ID", "00000000-0000-0000-0000-000000000001")
        logger.warning("Auth disabled in dev mode — using demo user")
        return AuthenticatedUser(user_id=demo_id, email="demo@infoshield.local", role="demo")

    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = credentials.credentials
    claims = _verify_jwt(token)

    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: missing user identity.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return AuthenticatedUser(
        user_id=user_id,
        email=claims.get("email"),
        role=claims.get("role", "authenticated")
    )


async def get_optional_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme)
) -> Optional[AuthenticatedUser]:
    """
    Optional auth dependency for endpoints that work with or without auth.
    Returns AuthenticatedUser if valid token present, None otherwise.
    Used for health checks and public endpoints.
    """
    if not _is_auth_enabled():
        demo_id = os.getenv("DEMO_USER_ID", "00000000-0000-0000-0000-000000000001")
        return AuthenticatedUser(user_id=demo_id, email="demo@infoshield.local", role="demo")

    if not credentials or not credentials.credentials:
        return None

    try:
        token = credentials.credentials
        claims = _verify_jwt(token)
        user_id = claims.get("sub")
        if not user_id:
            return None
        return AuthenticatedUser(
            user_id=user_id,
            email=claims.get("email"),
            role=claims.get("role", "authenticated")
        )
    except HTTPException:
        return None


def verify_document_ownership(document_user_id: str, requesting_user_id: str) -> None:
    """
    Verifies that the requesting user owns the document.
    Raises 403 if ownership check fails.
    """
    if document_user_id != requesting_user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this document."
        )
