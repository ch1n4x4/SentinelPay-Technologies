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
    
    # Basic sanitization to mitigate path traversal
    filename = os.path.basename(f.filename)

    key = f"users/{user_id}/{filename}"
    try:
        _s3().put_object(
            Bucket=KYC_BUCKET,
            Key=key,
            Body=f.read(),
            # ACL="public-read" removed; relies on bucket policies/IAM instead.
        )
        return jsonify({"key": key, "bucket": KYC_BUCKET}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@documents_bp.route("/<path:key>", methods=["GET"])
@require_auth
def get_document(key):
    """Fetch a previously uploaded document."""
    # REMEDIATION START: V-APP-03 KYC Document Ownership Check
    # Ensure the caller can only retrieve keys within their own designated 
    # S3 prefix (users/<user_id>/) to prevent unauthorized S3 lookups[cite: 12].
    expected_prefix = f"users/{request.current_user_id}/"
    if not key.startswith(expected_prefix):
        return jsonify({"error": "unauthorized access to document"}), 403
    # REMEDIATION END

    try:
        obj = _s3().get_object(Bucket=KYC_BUCKET, Key=key)
        return obj["Body"].read(), 200, {"Content-Type": obj.get("ContentType", "application/octet-stream")}
    except Exception as e:
        return jsonify({"error": str(e)}), 404