"""Shared Flask extensions."""
import os

# REMEDIATION START: V-APP-08 Shared Extension
# Created a shared Limiter instance to be imported by the main application 
# factory and the blueprints[cite: 21, 22].
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.getenv(
        "RATELIMIT_STORAGE_URI",
        "redis://redis:6379/2",
    ),
)
# REMEDIATION END