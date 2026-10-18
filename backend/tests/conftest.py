"""
InfoShield Pytest Configuration
Configures sys.path so test suites resolve backend modules seamlessly.
"""

import os
import sys

# Add parent directory (backend/) to sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import time
import jwt as pyjwt

# Set predictable testing environment defaults
TEST_JWT_SECRET = "test-secret-key-for-infoshield-testing-purposes-only-32bytes"
DEMO_USER_ID = "00000000-0000-0000-0000-000000000001"

os.environ.setdefault("ENV", "test")
os.environ.setdefault("SUPABASE_JWT_SECRET", TEST_JWT_SECRET)
os.environ.setdefault("DEMO_USER_ID", DEMO_USER_ID)
os.environ.setdefault("AUTH_ENABLED", "true")


def get_test_auth_headers(user_id: str = DEMO_USER_ID, role: str = "authenticated") -> dict:
    """Generate valid test JWT auth headers."""
    payload = {
        "sub": user_id,
        "email": "demo.user@infoshield.ai",
        "role": role,
        "aud": "authenticated",
        "exp": time.time() + 3600,
        "iat": time.time()
    }
    token = pyjwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}
