"""SentinelPay KYC API — identity verification service."""
import os
import logging
from flask import Flask, jsonify

from app.routes.verify import verify_bp
from app.routes.documents import documents_bp


def create_app():
    app = Flask(__name__)
    app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET", "sentinelpay-dev-secret")

    app.register_blueprint(verify_bp, url_prefix="/v1/verify")
    app.register_blueprint(documents_bp, url_prefix="/v1/documents")

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "kyc-api"})

    # REMEDIATION START: V-APP-09 Secure Error Handling
    # Added a global exception handler to catch unhandled errors.
    # This prevents stack traces or raw exception details from being leaked 
    # to the client, logging them securely on the server instead[cite: 26].
    @app.errorhandler(Exception)
    def handle_exception(exc):
        app.logger.exception("Unhandled KYC application exception")
        return jsonify({"error": "internal server error"}), 500
    # REMEDIATION END

    return app


if __name__ == "__main__":
    app = create_app()
    
    # REMEDIATION START: V-APP-09 Disable Debug Mode
    # Changed debug=True to debug=False to prevent Werkzeug from exposing 
    # the interactive debugger and source code in production responses[cite: 26].
    app.run(host="0.0.0.0", port=8002, debug=False)
    # REMEDIATION END