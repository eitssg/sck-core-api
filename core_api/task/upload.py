from os import path
import boto3
from botocore.exceptions import ClientError
import uuid
from datetime import datetime, timedelta

from core_db.exceptions import BadRequestException, UnknownException
from core_framework.models import DeploymentDetails


def upload_package(*, path_params: dict = None, body: dict = None, security: dict = None, **kwargs) -> dict:
    """Generate pre-signed URL for package upload or handle direct upload.

    For large files: Returns pre-signed S3 URL for direct browser upload
    For small files: Accepts base64 encoded file content

    Args:
        path_params: Contains portfolio, app, branch, build
        body: Contains file metadata and optional file content

    Returns:
        Dict containing upload URL or confirmation
    """
    portfolio = path_params.get("portfolio")
    app = path_params.get("app")
    branch = path_params.get("branch")
    build = path_params.get("build")

    deployment_details = DeploymentDetails(**path_params)

    # Extract file info from body
    file_name = body.get("fileName")
    file_size = body.get("fileSize", 0)
    content_type = body.get("contentType", "application/octet-stream")
    file_content = body.get("fileContent")  # Base64 encoded for small files

    if not file_name:
        raise BadRequestException("fileName is required")

    # Determine upload strategy based on file size
    if file_size > 5 * 1024 * 1024:  # 5MB threshold
        # Large file - use pre-signed URL
        return generate_presigned_upload_url(portfolio, app, branch, build, file_name, content_type)
    else:
        # Small file - handle direct upload
        if not file_content:
            raise BadRequestException("fileContent is required for files under 5MB")
        return handle_direct_upload(portfolio, app, branch, build, file_name, file_content, content_type)


def generate_presigned_upload_url(portfolio: str, app: str, branch: str, build: str, file_name: str, content_type: str) -> dict:
    """Generate pre-signed S3 URL for large file uploads."""

    s3_client = boto3.client("s3")

    # Build S3 key using your BuildFilesPrefix pattern
    s3_key = f"files/{portfolio}/{app}/{branch}/{build}/{file_name}"
    bucket_name = f"{portfolio}-{get_region()}"  # Your bucket naming pattern

    # Generate unique upload ID for tracking
    upload_id = str(uuid.uuid4())

    try:
        # Generate pre-signed URL for PUT operation
        presigned_url = s3_client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": bucket_name,
                "Key": s3_key,
                "ContentType": content_type,
                "Metadata": {
                    "upload-id": upload_id,
                    "portfolio": portfolio,
                    "app": app,
                    "branch": branch,
                    "build": build,
                    "uploaded-by": get_current_user(),  # From your auth context
                    "upload-timestamp": datetime.utcnow().isoformat(),
                },
            },
            ExpiresIn=3600,  # 1 hour to complete upload
        )

        return {
            "uploadStrategy": "presigned",
            "uploadUrl": presigned_url,
            "uploadId": upload_id,
            "s3Bucket": bucket_name,
            "s3Key": s3_key,
            "expiresIn": 3600,
            "instructions": {"method": "PUT", "headers": {"Content-Type": content_type}},
        }

    except ClientError as e:
        raise UnknownException(f"Failed to generate upload URL: {str(e)}", exception=e)


def handle_direct_upload(
    portfolio: str, app: str, branch: str, build: str, file_name: str, file_content: str, content_type: str
) -> dict:
    """Handle direct upload for small files via API Gateway."""

    import base64

    try:
        # Decode base64 content
        file_bytes = base64.b64decode(file_content)

        s3_client = boto3.client("s3")
        s3_key = f"files/{portfolio}/{app}/{branch}/{build}/{file_name}"
        bucket_name = f"{portfolio}-{get_region()}"

        # Upload directly to S3
        s3_client.put_object(
            Bucket=bucket_name,
            Key=s3_key,
            Body=file_bytes,
            ContentType=content_type,
            Metadata={
                "portfolio": portfolio,
                "app": app,
                "branch": branch,
                "build": build,
                "uploaded-by": get_current_user(),
                "upload-timestamp": datetime.utcnow().isoformat(),
                "upload-method": "direct",
            },
        )

        return {
            "uploadStrategy": "direct",
            "status": "completed",
            "s3Bucket": bucket_name,
            "s3Key": s3_key,
            "fileSize": len(file_bytes),
            "contentType": content_type,
        }

    except Exception as e:
        raise UnknownException(f"Failed to upload file: {str(e)}", exception=e)


def get_region() -> str:
    """Get current AWS region from context."""
    # Implementation depends on your context setup
    return "ap-southeast-1"  # Your default region


def get_current_user() -> str:
    """Get current authenticated user."""
    # Implementation depends on your auth setup
    return "unknown"  # Placeholder
