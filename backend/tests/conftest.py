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

# Set predictable testing environment defaults
os.environ.setdefault("ENV", "test")
os.environ.setdefault("SUPABASE_JWT_SECRET", "test-secret-key-for-infoshield-testing-purposes-only-32bytes")
os.environ.setdefault("DEMO_USER_ID", "00000000-0000-0000-0000-000000000001")
os.environ.setdefault("AUTH_ENABLED", "true")
