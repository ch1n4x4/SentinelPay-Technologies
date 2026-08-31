"""SentinelPay KYC API — identity verification service."""

from flask import (
    Flask,
    jsonify,
)

from app.routes.verify import verify_bp
from app.routes.documents import documents_bp


def create_app():
    """
    Build and configure the KYC Flask application.
    """
    app = Flask(__name__)

    # FUNCTIONALITY:
    # Register identity verification and KYC document endpoints.
    app.register_blueprint(
        verify_bp,
        url_prefix="/v1/verify",
    )

    app.register_blueprint(
        documents_bp,
        url_prefix="/v1/documents",
    )

    # FUNCTIONALITY:
    # Lightweight liveness endpoint for deployment/container health checks.
    @app.route("/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": "kyc-api",
        })

    # =========================================================================
    # V-APP-09: GENERIC GLOBAL ERROR HANDLING
    # =========================================================================
    #
    # SECURITY:
    # Log full diagnostics server-side, but do not expose exception messages
    # or tracebacks to clients.
    @app.errorhandler(Exception)
    def handle_exception(exc):
        app.logger.exception(
            "Unhandled KYC application exception"
        )

        return jsonify({
            "error": "internal server error"
        }), 500

    return app


if __name__ == "__main__":
    app = create_app()

    # SECURITY:
    # Debug is disabled to prevent Werkzeug from exposing source and interactive
    # tracebacks.
    app.run(
        host="0.0.0.0",
        port=8002,
        debug=False,
    )