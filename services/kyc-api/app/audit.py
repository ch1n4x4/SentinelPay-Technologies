"""Shared audit logging module."""
import json
import logging
from datetime import datetime, timezone

# REMEDIATION START: V-APP-11 Extracted Audit Module
# The audit helper has been extracted into a shared module so it can be 
# imported and executed during sensitive operations across all services[cite: 27].
audit_logger = logging.getLogger("sentinelpay.audit")

def audit_event(event: str, **fields):
    """Write a structured audit event to the application logger."""
    
    # REMEDIATION START: Prevent Sensitive Data Leakage
    # Ensure audit logging cannot accidentally leak passwords, OTPs, 
    # tokens, or document contents[cite: 27].
    sensitive_keys = {"password", "otp", "token", "document_content", "session"}
    sanitized_fields = {
        k: ("***" if k in sensitive_keys else v) 
        for k, v in fields.items()
    }
    # REMEDIATION END

    audit_logger.info(
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **sanitized_fields,
            },
            separators=(",", ":"),
        )
    )