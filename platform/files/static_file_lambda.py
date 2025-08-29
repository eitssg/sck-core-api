import json
import boto3
import os
import mimetypes
from botocore.exceptions import ClientError
from urllib.parse import unquote

s3 = boto3.client("s3")


def handler(event, context):
    try:
        bucket = os.environ["REACT_S3_BUCKET"]

        # Get path from event
        path = event.get("pathParameters", {}).get("proxy", "") if event.get("pathParameters") else ""
        if not path:
            path = event.get("path", "/").lstrip("/")

        # URL decode the path
        path = unquote(path)

        # Root path serves index.html
        if not path or path == "/" or path == "":
            s3_key = "index.html"
        else:
            s3_key = path

        print(f"Serving: {s3_key} from bucket: {bucket}")

        try:
            # Get file from S3
            response = s3.get_object(Bucket=bucket, Key=s3_key)
            content = response["Body"].read()

            # Determine content type
            content_type, _ = mimetypes.guess_type(s3_key)
            if not content_type:
                if s3_key.endswith(".js"):
                    content_type = "application/javascript"
                elif s3_key.endswith(".css"):
                    content_type = "text/css"
                elif s3_key.endswith(".html"):
                    content_type = "text/html"
                elif s3_key.endswith(".json"):
                    content_type = "application/json"
                else:
                    content_type = "application/octet-stream"

            # Set cache headers
            cache_control = "public, max-age=31536000" if "/assets/" in s3_key else "no-cache, no-store, must-revalidate"

            # Check if content is binary
            is_binary = not content_type.startswith(("text/", "application/json", "application/javascript"))

            return {
                "statusCode": 200,
                "headers": {"Content-Type": content_type, "Cache-Control": cache_control, "X-Content-Type-Options": "nosniff"},
                "body": content.decode("utf-8") if not is_binary else content,
                "isBase64Encoded": is_binary,
            }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchKey":
                # File not found, serve index.html for SPA routing
                try:
                    print(f"File not found: {s3_key}, serving index.html for SPA routing")
                    response = s3.get_object(Bucket=bucket, Key="index.html")
                    content = response["Body"].read()
                    return {
                        "statusCode": 200,
                        "headers": {"Content-Type": "text/html", "Cache-Control": "no-cache, no-store, must-revalidate"},
                        "body": content.decode("utf-8"),
                        "isBase64Encoded": False,
                    }
                except ClientError:
                    print("index.html not found in S3 bucket")
                    return {
                        "statusCode": 404,
                        "headers": {"Content-Type": "text/html"},
                        "body": "<html><body><h1>React app not deployed yet</h1><p>Upload your React build to the S3 bucket to see your application.</p></body></html>",
                        "isBase64Encoded": False,
                    }
            else:
                raise e

    except Exception as e:
        print(f"Error serving static file: {str(e)}")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Internal server error"}),
            "isBase64Encoded": False,
        }
