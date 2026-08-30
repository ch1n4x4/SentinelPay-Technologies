"""Shared audit logging."""

import json
import logging
from datetime import datetime, timezone

audit_logger = logging.getLogger("sentinelpay.audit")


def audit_event(event: str, **fields) -> None:
    sensitive_keys = {
        "password",
        "otp",
        "token",
        "document_content",
        "session",
    }

    sanitized_fields = {
        key: "***" if key in sensitive_keys else value
        for key, value in fields.items()
    }

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