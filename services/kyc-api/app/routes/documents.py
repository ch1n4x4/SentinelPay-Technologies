"""Document upload and retrieval for KYC submissions."""
import os
import boto3
from flask import Blueprint, request, jsonify, send_file

from app.auth import require_auth

documents_bp = Blueprint("documents", __name__)

KYC_BUCKET = os.environ.get("KYC_BUCKET", "sentinelpay-kyc-documents")


def _s3():
    return boto3.client(
        "s3",
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
        region_name=os.environ.get("AWS_REGION", "af-south-1"),
    )


@documents_bp.route("/upload", methods=["POST"])
@require_auth
def upload_document():
    """Upload a KYC document (passport, driver's licence, utility bill).

    Multiple cloud-layer issues are evident here once the cohort begins
    building the Terraform — the upload assumes the bucket exists with no
    encryption, no logging, and a public-read ACL set by the caller.
    """
    if "file" not in request.files:
        return jsonify({"error": "file required"}), 400

    f = request.files["file"]
    user_id = request.current_user_id
    filename = f.filename  # No sanitisation — path traversal possible.

    key = f"users/{user_id}/{filename}"
    try:
        _s3().put_object(
            Bucket=KYC_BUCKET,
            Key=key,
            Body=f.read(),
            ACL="public-read"  # Legacy default from the marketing demo era.
        )
        return jsonify({"key": key, "bucket": KYC_BUCKET}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@documents_bp.route("/<path:key>", methods=["GET"])
@require_auth
def get_document(key):
    """Fetch a previously uploaded document.

    No ownership check on the key. Identical pattern to V-APP-03 IDOR.
    """
    try:
        obj = _s3().get_object(Bucket=KYC_BUCKET, Key=key)
        return obj["Body"].read(), 200, {"Content-Type": obj.get("ContentType", "application/octet-stream")}
    except Exception as e:
        return jsonify({"error": str(e)}), 404
