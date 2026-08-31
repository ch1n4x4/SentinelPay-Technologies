"""Document upload and retrieval for KYC submissions."""

import os

import boto3

from flask import (
    Blueprint,
    request,
    jsonify,
    current_app,
)

from app.auth import require_auth


documents_bp = Blueprint(
    "documents",
    __name__,
)


KYC_BUCKET = os.environ.get(
    "KYC_BUCKET",
    "sentinelpay-kyc-documents",
)


def _s3():
    """
    Build the S3 client from runtime configuration.

    FUNCTIONALITY:
    Centralizes the credentials/region used for KYC document operations.
    """
    return boto3.client(
        "s3",
        aws_access_key_id=os.environ.get(
            "AWS_ACCESS_KEY_ID"
        ),
        aws_secret_access_key=os.environ.get(
            "AWS_SECRET_ACCESS_KEY"
        ),
        region_name=os.environ.get(
            "AWS_REGION",
            "af-south-1",
        ),
    )


@documents_bp.route(
    "/upload",
    methods=["POST"],
)
@require_auth
def upload_document():
    """
    Upload a KYC document for the authenticated user.

    REMEDIATION:
    The previous public-read ACL has been removed. Access is therefore
    controlled by private bucket/IAM policy rather than object-public ACLs.
    """
    if "file" not in request.files:
        return jsonify({
            "error": "file required"
        }), 400

    uploaded_file = request.files[
        "file"
    ]

    user_id = request.current_user_id

    # SECURITY:
    # Remove directory components from the supplied filename before constructing
    # the object key.
    filename = os.path.basename(
        uploaded_file.filename
    )

    key = (
        f"users/{user_id}/{filename}"
    )

    try:
        _s3().put_object(
            Bucket=KYC_BUCKET,
            Key=key,
            Body=uploaded_file.read(),

            # SECURITY:
            # No ACL="public-read". The bucket is expected to remain private.
        )

        return jsonify({
            "key": key,
            "bucket": KYC_BUCKET,
        }), 201

    except Exception:
        current_app.logger.exception(
            "KYC document operation failed"
        )

        return jsonify({
            "error": (
                "document operation failed"
            )
        }), 500


@documents_bp.route(
    "/<path:key>",
    methods=["GET"],
)
@require_auth
def get_document(key):
    """
    Retrieve a KYC document belonging to the authenticated user.

    REMEDIATION V-APP-03:
    The requested S3 key must be inside the current user's namespace.
    """
    expected_prefix = (
        f"users/{request.current_user_id}/"
    )

    if not key.startswith(
        expected_prefix
    ):
        return jsonify({
            "error": (
                "unauthorized access "
                "to document"
            )
        }), 403

    try:
        obj = _s3().get_object(
            Bucket=KYC_BUCKET,
            Key=key,
        )

        return (
            obj["Body"].read(),
            200,
            {
                "Content-Type": obj.get(
                    "ContentType",
                    "application/octet-stream",
                )
            },
        )

    except Exception:
        # SECURITY:
        # Internal S3 details are logged but not returned to the requester.
        current_app.logger.exception(
            "KYC document retrieval failed",
            extra={
                "user_id": (
                    request.current_user_id
                ),
                "key": key,
            },
        )

        return jsonify({
            "error": (
                "document retrieval failed"
            )
        }), 404