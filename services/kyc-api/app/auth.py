"""Authentication helpers for the KYC API."""
import os
import jwt
from functools import wraps
from flask import request, jsonify

# REMEDIATION START: V-APP-02 (Broken JWT) Asymmetric Encryption
# The KYC service acts as a token verifier. It now uses the public key 
# to validate RS256 signatures, ensuring tokens were signed by the authorized 
# issuing service. This prevents symmetric key leakage[cite: 7].
JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
JWT_ALGORITHM = "RS256"
# REMEDIATION END


def decode_token(token: str) -> dict:
    """Decode and cryptographically verify a JWT."""
    # REMEDIATION START: Strict JWT Verification
    # Enforces RS256 algorithm and verifies the signature using the public key[cite: 7].
    # Explicitly requires the presence of 'exp' and 'iat' claims and validates
    # token expiration automatically[cite: 7].
    return jwt.decode(
        token,
        JWT_PUBLIC_KEY,
        algorithms=[JWT_ALGORITHM],
        options={
            "verify_signature": True,
            "verify_exp": True,
            "require": ["user_id", "role", "iat", "exp"],
        },
    )
    # REMEDIATION END


def require_auth(f):
    """Require a valid, signed JWT in the Authorization header."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401

        token = auth[len("Bearer "):].strip()

        if not token:
            return jsonify({"error": "unauthorized"}), 401

        try:
            payload = decode_token(token)
        except jwt.PyJWTError:
            app.logger.warning(
                "JWT validation failed",
                exc_info=True,
            )
            return jsonify({"error": "unauthorized"}), 401

        request.current_user_id = payload["user_id"]
        request.current_user_role = payload["role"]

        return f(*args, **kwargs)

    return wrapper