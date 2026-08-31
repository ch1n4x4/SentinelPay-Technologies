"""Shared Flask extensions."""

import os

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# ============================================================================
# V-APP-08: SINGLE SHARED RATE-LIMITER
# ============================================================================
#
# FUNCTIONALITY:
# This module owns the application's one Flask-Limiter instance.
#
# REMEDIATION:
# Keeping a single extension prevents route modules from accidentally creating
# independent limiter instances that are never attached to the served Flask
# application.
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.getenv(
        "RATELIMIT_STORAGE_URI",
        "redis://redis:6379/2",
    ),
)