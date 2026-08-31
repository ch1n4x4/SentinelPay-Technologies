"""Authentication helpers for the KYC API."""

import os

from functools import wraps

import jwt

from flask import (
    request,
    jsonify,
)


# ============================================================================
# V-APP-02: KYC JWT VERIFICATION
# ============================================================================
#
# FUNCTIONALITY:
# KYC only verifies tokens. It therefore receives the public RSA key and never
# needs the private signing key.
#
# REMEDIATION:
# Restrict verification to RS256 and reject unsigned/other-algorithm tokens.
JWT_PUBLIC_KEY = os.environ[
    "JWT_PUBLIC_KEY"
]

JWT_ALGORITHM = "RS256"


def decode_token(
    token: str,
) -> dict:
    """
    Cryptographically verify a KYC API access token.
    """
    header = jwt.get_unverified_header(
        token
    )

    if header.get("alg") != JWT_ALGORITHM:
        raise jwt.InvalidAlgorithmError(
            "unexpected JWT algorithm"
        )

    return jwt.decode(
        token,
        JWT_PUBLIC_KEY,
        algorithms=[
            JWT_ALGORITHM
        ],
        options={
            "verify_signature": True,
            "verify_exp": True,
            "require": [
                "user_id",
                "role",
                "iat",
                "exp",
            ],
        },
    )


def require_auth(f):
    """
    Require a valid KYC JWT.

    REMEDIATION V-APP-09:
    Return generic 401 errors rather than exposing JWT validation internals.
    """
    @wraps(f)
    def wrapper(
        *args,
        **kwargs,
    ):
        auth_header = request.headers.get(
            "Authorization",
            "",
        )

        if not auth_header.startswith(
            "Bearer "
        ):
            return jsonify({
                "error": "unauthorized"
            }), 401

        token = auth_header[
            len("Bearer "):
        ].strip()

        if not token:
            return jsonify({
                "error": "unauthorized"
            }), 401

        try:
            payload = decode_token(
                token
            )

        except jwt.PyJWTError:
            return jsonify({
                "error": "unauthorized"
            }), 401

        request.current_user_id = (
            payload["user_id"]
        )

        request.current_user_role = (
            payload["role"]
        )

        return f(
            *args,
            **kwargs,
        )

    return wrapper