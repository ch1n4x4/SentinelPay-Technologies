"""SentinelPay Payments API — main entrypoint."""

import os

from flask import Flask, jsonify

from app.routes.auth import auth_bp
from app.routes.accounts import accounts_bp
from app.routes.transactions import transactions_bp
from app.routes.wallets import wallets_bp
from app.routes.webhooks import webhooks_bp
from app.routes.admin import admin_bp


# ============================================================================
# V-APP-08: SHARED RATE-LIMITER INITIALIZATION
# ============================================================================
#
# REMEDIATION:
# main did not initialize the shared Flask-Limiter extension on the real
# application instance. The test branch keeps one shared limiter and attaches
# it inside create_app(), where Flask actually constructs the served app.
from app.extensions import limiter


def create_app():
    """
    Build the Payments API Flask application.

    FUNCTIONALITY:
    Register all versioned API blueprints and initialize application-wide
    extensions.
    """
    app = Flask(__name__)

    app.config["ENVIRONMENT"] = os.environ.get(
        "ENVIRONMENT",
        "development",
    )

    # REMEDIATION V-APP-08:
    # Attach the shared limiter to this exact Flask application instance.
    limiter.init_app(app)

    # ------------------------------------------------------------------------
    # API ROUTES
    # ------------------------------------------------------------------------
    app.register_blueprint(
        auth_bp,
        url_prefix="/v1/auth",
    )

    app.register_blueprint(
        accounts_bp,
        url_prefix="/v1/accounts",
    )

    app.register_blueprint(
        transactions_bp,
        url_prefix="/v1/transactions",
    )

    app.register_blueprint(
        wallets_bp,
        url_prefix="/v1/wallets",
    )

    app.register_blueprint(
        webhooks_bp,
        url_prefix="/v1/webhooks",
    )

    app.register_blueprint(
        admin_bp,
        url_prefix="/v1/admin",
    )

    # ------------------------------------------------------------------------
    # HEALTH ENDPOINT
    # ------------------------------------------------------------------------
    #
    # FUNCTIONALITY:
    # Lightweight endpoint for liveness checks and Docker health probes.
    @app.route("/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": "payments-api",
        })

    # ------------------------------------------------------------------------
    # V-APP-09: GENERIC ERROR HANDLING
    # ------------------------------------------------------------------------
    #
    # main previously returned raw exception data. The test branch retains
    # complete diagnostic information in server logs but gives the client only
    # a stable generic response.
    @app.errorhandler(Exception)
    def handle_exception(exc):
        app.logger.exception(
            "Unhandled application exception"
        )

        return jsonify({
            "error": "internal server error"
        }), 500

    return app


if __name__ == "__main__":
    # SECURITY:
    # Disable Flask/Werkzeug debug mode so source code and interactive
    # traceback information cannot be exposed to callers.
    app = create_app()

    # False Positive: Flagged for running Flask on host 0.0.0.0. 
    # Inside a Docker container, binding to 0.0.0.0 is strictly 
    # required to expose the port to the Docker daemon network.
    app.run(               # nosemgrep  # nosec B104
        host="0.0.0.0",    # nosec B104
        port=8001,
        debug=False,
    )