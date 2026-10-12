"""
InfoShield AI - Supabase Client Module (Phase 4B)
Handles connection initialization, environment variable management, and
graceful fallback when credentials are not configured or unreachable.
"""

import os
import logging
from typing import Optional, Tuple
from dotenv import load_dotenv

# Ensure environment variables are loaded from backend/.env or root .env
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_BASE_DIR)
_backend_env = os.path.join(_BASE_DIR, ".env")
_root_env = os.path.join(_PROJECT_ROOT, ".env")
if os.path.isfile(_backend_env):
    load_dotenv(_backend_env)
elif os.path.isfile(_root_env):
    load_dotenv(_root_env)
else:
    load_dotenv()

logger = logging.getLogger("infoshield.supabase_client")

# Environment configurations
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
DEMO_USER_ID = os.getenv("DEMO_USER_ID", "00000000-0000-0000-0000-000000000001").strip()

_CLIENT_INSTANCE = None
_OVERRIDE_CLIENT = None


def is_configured() -> bool:
    """Checks whether valid Supabase connection credentials exist in the environment."""
    if _OVERRIDE_CLIENT is not None:
        return True
    return bool(
        SUPABASE_URL
        and SUPABASE_SERVICE_ROLE_KEY
        and SUPABASE_URL.startswith("http")
        and not SUPABASE_URL.startswith("your_")
        and not SUPABASE_SERVICE_ROLE_KEY.startswith("your_")
    )


def get_supabase_client():
    """
    Returns the Supabase Client singleton.
    Returns None gracefully if credentials are not configured.
    """
    global _CLIENT_INSTANCE
    if _OVERRIDE_CLIENT is not None:
        return _OVERRIDE_CLIENT

    if not is_configured():
        return None

    if _CLIENT_INSTANCE is None:
        try:
            import supabase
            from supabase.lib.client_options import SyncClientOptions
            options = SyncClientOptions(
                postgrest_client_timeout=60.0,
                storage_client_timeout=30.0
            )
            _CLIENT_INSTANCE = supabase.create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, options=options)
            logger.info("Supabase client initialized successfully with 60s timeout.")
        except Exception as e:
            logger.error(f"Failed to initialize Supabase client: {e}")
            _CLIENT_INSTANCE = None

    return _CLIENT_INSTANCE


def set_override_client(client):
    """Allows injecting a mock/test client during automated testing."""
    global _OVERRIDE_CLIENT
    _OVERRIDE_CLIENT = client


def reset_client():
    """Resets client instance state (useful for test isolation)."""
    global _CLIENT_INSTANCE, _OVERRIDE_CLIENT
    _CLIENT_INSTANCE = None
    _OVERRIDE_CLIENT = None


def check_connection() -> Tuple[bool, str]:
    """
    Performs a lightweight probe to test Supabase PostgreSQL connectivity.
    Returns (is_connected: bool, status_message: str).
    """
    if not is_configured():
        return False, "Supabase credentials not configured in environment (.env)"

    client = get_supabase_client()
    if client is None:
        return False, "Failed to instantiate Supabase client"

    try:
        # Lightweight probe query against policy_rules or users
        res = client.table("policy_rules").select("id").limit(1).execute()
        return True, "Connected"
    except Exception as e:
        err_msg = str(e)
        logger.warning(f"Supabase probe query failed: {err_msg}")
        return False, f"Connection failed: {err_msg}"
