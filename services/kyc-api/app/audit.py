"""Shared structured audit logging."""

import json
import logging

from datetime import (
    datetime,
    timezone,
)


audit_logger = logging.getLogger(
    "sentinelpay.audit"
)


def audit_event(
    event: str,
    **fields,
) -> None:
    """
    Emit one structured audit record.

    FUNCTIONALITY:
    All sensitive operations use a common JSON event format.

    REMEDIATION V-APP-11:
    Known credential/secret fields are replaced before logging, preventing
    audit records from becoming a secondary disclosure channel.
    """
    sensitive_keys = {
        "password",
        "otp",
        "token",
        "document_content",
        "session",
    }

    sanitized_fields = {
        key: (
            "***"
            if key in sensitive_keys
            else value
        )
        for key, value in fields.items()
    }

    audit_logger.info(
        json.dumps(
            {
                "timestamp": (
                    datetime.now(
                        timezone.utc
                    ).isoformat()
                ),
                "event": event,
                **sanitized_fields,
            },
            separators=(
                ",",
                ":",
            ),
        )
    )