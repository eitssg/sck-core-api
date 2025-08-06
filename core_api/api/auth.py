"""Authentication module for AWS STS credential management and JWT token handling.

This module provides authentication functionality for the SCK Core API, including:
- AWS STS credential generation from access keys
- JWT token creation and validation
- Credential extraction from JWT tokens
- Integration with AWS API Gateway proxy events

The authentication flow:
1. Browser sends POST with AWS access key/secret
2. API Gateway → handler.py → proxy.py → authenticate_action()
3. STS generates temporary credentials
4. Credentials embedded in JWT token
5. JWT returned to browser for subsequent requests

Example:
    Authentication request::

        POST /api/v1/login
        {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "access_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        }

    Response::

        {
            "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
            "expires_in": 3600
        }
"""

from typing import Dict, Any, Optional
import os
import boto3
from botocore.exceptions import BotoCoreError, ClientError
import jwt
from datetime import datetime, timedelta, timezone
from collections import ChainMap
from json import JSONDecodeError

import core_logging as log
import core_framework as util

from ..response import Response, ErrorResponse
from ..request import ActionHandlerRoutes
from ..constants import QUERY_STRING_PARAMETERS, PATH_PARAMETERS, BODY_PARAMETER

# JWT Configuration
# FIXED: More robust environment variable handling
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
if JWT_SECRET_KEY == "your-secret-key-here":
    log.warning("Using default JWT secret key - change JWT_SECRET_KEY environment variable for production!")

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
# Validate algorithm is supported
SUPPORTED_ALGORITHMS = ["HS256", "HS384", "HS512"]
if JWT_ALGORITHM not in SUPPORTED_ALGORITHMS:
    log.warning(f"Unsupported JWT algorithm: {JWT_ALGORITHM}, falling back to HS256")
    JWT_ALGORITHM = "HS256"

# Safe integer conversion with better error handling
try:
    JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))
    if JWT_EXPIRATION_HOURS < 1 or JWT_EXPIRATION_HOURS > 168:  # 1 hour to 1 week
        log.warning(f"JWT expiration hours out of range: {JWT_EXPIRATION_HOURS}, using default 24")
        JWT_EXPIRATION_HOURS = 24
except (ValueError, TypeError):
    log.warning("Invalid JWT_EXPIRATION_HOURS environment variable, using default value of 24")
    JWT_EXPIRATION_HOURS = 24


def authenticate_action(**kwargs) -> Response:
    """Handle authentication request from API Gateway proxy.

    This function is called by the proxy handler when a POST request is made to
    /api/v1/login. It extracts parameters from the API Gateway event and calls
    the authentication logic.

    Args:
        **kwargs: API Gateway proxy event parameters including:
            - queryStringParameters: URL query parameters
            - pathParameters: URL path parameters
            - body: POST request body (JSON string)

    Returns:
        Response: Authentication response with JWT token or error details.

    Note:
        The body parameter is expected to be a JSON string that will be parsed
        to extract AWS credentials for STS token generation.
    """
    try:
        # Extract parameters from different sources using ChainMap for precedence
        query_params = kwargs.get(QUERY_STRING_PARAMETERS, {}) or {}
        path_params = kwargs.get(PATH_PARAMETERS, {}) or {}

        # Parse body JSON if present
        body_params = {}
        body_str = kwargs.get(BODY_PARAMETER, "")
        if body_str:
            try:
                # CORRECTED: Use util.from_json() instead of json.loads()
                body_params = util.from_json(body_str)
                if not isinstance(body_params, dict):
                    body_params = {}
            except Exception as e:
                log.error(f"Invalid JSON in request body: {e}")
                return ErrorResponse(message="Invalid JSON in request body", code=400)

        # Combine parameters with body taking precedence over query over path
        all_params = dict(ChainMap(body_params, query_params, path_params))

        # Call the authentication logic
        return _authenticate(**all_params)

    except Exception as e:
        log.error(f"Error in authenticate_action: {e}")
        return ErrorResponse(message="Authentication processing error", code=500)


def _authenticate(**kwargs) -> Response:
    """Authenticate user with AWS credentials and generate JWT token.

    Enhanced for multi-user, multi-region production environment.
    """
    try:
        # Extract AWS credentials from parameters
        access_key = kwargs.get("access_key")
        access_secret = kwargs.get("access_secret")
        session_token = kwargs.get("session_token")

        # FIXED: Enhanced validation for production
        if not access_key or not access_secret:
            log.warning("Missing AWS credentials in authentication request")
            return ErrorResponse(message="Missing required AWS credentials (access_key, access_secret)", code=400)

        # FIXED: Validate access key format (basic sanity check)
        if not access_key.startswith(("AKIA", "ASIA")) or len(access_key) != 20:
            log.warning(f"Invalid access key format for: {access_key[:8]}...")
            return ErrorResponse(message="Invalid AWS access key format", code=400)

        # FIXED: Validate secret key length (basic sanity check)
        if len(access_secret) != 40:
            log.warning("Invalid secret key length")
            return ErrorResponse(message="Invalid AWS secret key format", code=400)

        log.info(f"Attempting AWS STS authentication for access key: {access_key[:8]}...")

        # FIXED: Add region handling for international users
        region = kwargs.get("region", "us-east-1")  # Default to us-east-1

        # Create STS client with provided credentials
        sts_client = boto3.client(
            "sts",
            region_name=region,  # Support different regions
            aws_access_key_id=access_key,
            aws_secret_access_key=access_secret,
            aws_session_token=session_token,
        )

        # FIXED: Enhanced STS call with better error handling
        try:
            response = sts_client.get_session_token(DurationSeconds=86400)  # 24 hours
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code in ["InvalidUserID.NotFound", "SignatureDoesNotMatch"]:
                log.warning(f"Invalid AWS credentials for: {access_key[:8]}...")
                return ErrorResponse(message="Invalid AWS credentials", code=401)
            elif error_code == "TokenRefreshRequired":
                return ErrorResponse(message="AWS credentials require MFA token", code=401)
            else:
                log.error(f"AWS STS error ({error_code}): {e}")
                return ErrorResponse(message="AWS authentication service error", code=503)

        credentials = response["Credentials"]

        # FIXED: Use consistent UTC timezone for all users globally
        now_utc = datetime.now(timezone.utc)
        exp_time_utc = now_utc + timedelta(hours=JWT_EXPIRATION_HOURS)

        # FIXED: Enhanced JWT payload with security improvements
        jwt_payload = {
            "Credentials": {
                "AccessKeyId": credentials["AccessKeyId"],
                "SecretAccessKey": credentials["SecretAccessKey"],
                "SessionToken": credentials["SessionToken"],
                "Expiration": credentials["Expiration"].isoformat(),  # AWS returns timezone-aware datetime
            },
            "OriginalAccessKey": access_key[:8] + "...",  # Truncated for security
            "region": region,  # Store region for later use
            "iat": now_utc.timestamp(),  # Issued at (UTC)
            "exp": exp_time_utc.timestamp(),  # Expires at (UTC)
            "iss": "sck-core-api",  # Issuer
            "jti": f"{access_key[:8]}-{int(now_utc.timestamp())}",  # Unique token ID for tracking
        }

        # Generate JWT token
        jwt_token = jwt.encode(jwt_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        log.info(f"Authentication successful for access key: {access_key[:8]}... in region: {region}")

        return Response(
            data={
                "token": jwt_token,
                "expires_in": int(JWT_EXPIRATION_HOURS * 3600),
                "token_type": "Bearer",
                "region": region,  # Return region info
            },
            code=200,
        )

    except (BotoCoreError, ClientError) as e:
        log.error(f"AWS STS error: {e}")
        return ErrorResponse(message="Invalid AWS credentials or STS service error", code=401)

    except Exception as e:
        log.error(f"Unexpected error in authentication: {e}")
        return ErrorResponse(message="Authentication processing error", code=500)


def validate_token(token: str) -> bool:
    """Validate JWT token with enhanced security checks.

    Enhanced validation for production use with multiple security checks.

    Args:
        token (str): JWT token string to validate.

    Returns:
        bool: True if token is valid and secure, False otherwise.
    """
    try:
        # FIXED: Add additional validation options for security
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "require": ["exp", "iat", "iss"],  # Require these claims
            },
            issuer="sck-core-api",  # Verify issuer matches
        )

        # Additional validation: Check token age (prevent very old tokens)
        iat = payload.get("iat")
        if iat:
            issued_time = datetime.fromtimestamp(iat, tz=timezone.utc)
            max_age = timedelta(days=30)  # Reject tokens older than 30 days
            if datetime.now(timezone.utc) - issued_time > max_age:
                log.debug("Token is too old")
                return False

        return True
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, jwt.InvalidIssuerError) as e:
        log.debug(f"Token validation failed: {e}")
        return False


# Route configuration for authentication endpoints
auth_actions: ActionHandlerRoutes = {
    "POST:/v1/login": authenticate_action,  # Note: removed /api prefix for router
}


def get_credentials(**kwargs) -> Optional[Dict[str, Any]]:
    """Extract AWS credentials from JWT token with enhanced international support."""
    try:
        # Extract headers from AWS API Gateway event
        headers = kwargs.get("headers", {})
        if not headers:
            return None

        # FIXED: More robust header handling for international characters
        authorization_header = None
        for header_name, header_value in headers.items():
            if header_name.lower() == "authorization":
                authorization_header = str(header_value).strip()  # Ensure string and trim
                break

        if not authorization_header:
            return None

        # FIXED: More robust Bearer token parsing
        if not authorization_header.lower().startswith("bearer "):
            log.debug("Authorization header does not contain Bearer token")
            return None

        # Split and validate token
        parts = authorization_header.split(" ", 1)  # Split only on first space
        if len(parts) != 2 or not parts[1].strip():
            log.debug("Malformed Authorization header format")
            return None

        token = parts[1].strip()

        # FIXED: Enhanced JWT decoding with better error messages
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                },
            )
        except jwt.ExpiredSignatureError:
            log.debug("JWT token has expired")
            return None
        except jwt.InvalidTokenError as e:
            log.debug(f"Invalid JWT token: {e}")
            return None

        # Extract credentials from payload
        credentials = payload.get("Credentials")
        if not credentials:
            log.debug("No credentials found in JWT payload")
            return None

        # Validate required credential fields
        required_fields = ["AccessKeyId", "SecretAccessKey", "SessionToken"]
        if not all(field in credentials for field in required_fields):
            log.debug("Incomplete credentials in JWT payload")
            return None

        # Check if STS credentials have expired
        expiration_str = credentials.get("Expiration")
        if expiration_str:
            try:
                # FIXED: Robust timezone parsing for international users
                if expiration_str.endswith("Z"):
                    # UTC timezone indicator
                    expiration = datetime.fromisoformat(expiration_str.replace("Z", "+00:00"))
                elif expiration_str.endswith("+00:00"):
                    # Already has UTC offset
                    expiration = datetime.fromisoformat(expiration_str)
                elif "+" in expiration_str or expiration_str.count("-") > 2:
                    # Has timezone offset (like +05:30 for India)
                    expiration = datetime.fromisoformat(expiration_str)
                else:
                    # No timezone info - assume UTC (AWS STS default)
                    expiration = datetime.fromisoformat(expiration_str).replace(tzinfo=timezone.utc)

                # Always compare in UTC to avoid timezone confusion
                now_utc = datetime.now(timezone.utc)
                if now_utc > expiration:
                    log.debug("STS credentials have expired")
                    return None

            except (ValueError, TypeError) as e:
                log.debug(f"Invalid expiration format in credentials: {e}")
                return None

        log.debug("Successfully extracted credentials from JWT token")
        return credentials

    except Exception as e:
        # Log error but still return None quietly
        log.debug(f"Error extracting credentials from token: {e}")
        return None
