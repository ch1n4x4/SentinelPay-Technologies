"""SentinelPay Payments API — main entrypoint."""
import os
from flask import Flask, jsonify

from app.routes.auth import auth_bp
from app.routes.accounts import accounts_bp
from app.routes.transactions import transactions_bp
from app.routes.wallets import wallets_bp
from app.routes.webhooks import webhooks_bp
from app.routes.admin import admin_bp


def create_app():
    app = Flask(__name__)
    app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET", "sentinelpay-dev-secret")
    app.config["ENVIRONMENT"] = os.environ.get("ENVIRONMENT", "development")

    app.register_blueprint(auth_bp, url_prefix="/v1/auth")
    app.register_blueprint(accounts_bp, url_prefix="/v1/accounts")
    app.register_blueprint(transactions_bp, url_prefix="/v1/transactions")
    app.register_blueprint(wallets_bp, url_prefix="/v1/wallets")
    app.register_blueprint(webhooks_bp, url_prefix="/v1/webhooks")
    app.register_blueprint(admin_bp, url_prefix="/v1/admin")

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "payments-api"})

    # ============================================================
    # REMEDIATION BLOCK: Secure error handling
    #
    # Log the full exception server-side for troubleshooting, but
    # return only a generic error message to the client. This prevents
    # stack traces, database details, file paths, and other internal
    # implementation information from being exposed through API
    # responses.
    # ============================================================
    @app.errorhandler(Exception)
    def handle_exception(e):
        app.logger.exception("Unhandled application exception")
        return jsonify({
            "error": "internal server error"
        }), 500


    return app

# change debug=True to debug=False
if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8001, debug=False)
