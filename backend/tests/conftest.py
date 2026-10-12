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
