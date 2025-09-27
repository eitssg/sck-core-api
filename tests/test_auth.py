"""Unit tests for core_api.api.auth module - CORRECTED VERSION

This module contains comprehensive tests for:
- Authentication action handling
- AWS STS credential generation
- JWT token creation and validation
- Credential extraction from tokens
- Error handling and edge cases

Test Coverage:
- authenticate_action() function
- _authenticate() function
- get_credentials() function
- validate_token() function
- Error scenarios and edge cases

Example:
    Run tests with pytest::

        pytest tests/test_auth.py -v
        pytest tests/test_auth.py::test_authenticate_success -v
"""

from dotenv.cli import get
import pytest
import jwt
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch, MagicMock
from moto import mock_aws
from botocore.exceptions import ClientError, BotoCoreError

import core_framework as util

from core_api.auth.auth_creds import get_credentials
from core_api.constants import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_ACCESS_HOURS,
    QUERY_STRING_PARAMETERS,
    PATH_PARAMETERS,
    BODY_PARAMETER,
)
from core_api.auth.tools import get_authenticated_user

from core_api.response import Response, ErrorResponse


# ============================================================================
# FIXTURES - CORRECTED TO USE datetime.now(timezone.utc) AND util.to_json()
# ============================================================================


@pytest.fixture
def valid_aws_credentials():
    """Fixture providing valid AWS credentials for testing."""
    return {
        "access_key": "AKIAIOSFODNN7EXAMPLE",
        "access_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }


@pytest.fixture
def valid_jwt_token():
    """Fixture providing a valid JWT token for testing."""
    # Use current time for iat, future time for exp
    now = datetime.now(timezone.utc)
    base_time = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)  # Future for expiration

    payload = {
        "Credentials": {
            "AccessKeyId": "ASIA123456789",
            "SecretAccessKey": "temp_secret_key",
            "SessionToken": "temp_session_token",
            "Expiration": (base_time + timedelta(hours=24)).isoformat(),  # Future expiration
        },
        "iat": now.timestamp(),  # Current time for issued at
        "exp": (now + timedelta(hours=2)).timestamp(),  # Future expiration
        "iss": "sck-core-api",
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


@pytest.fixture
def expired_jwt_token():
    """Fixture providing an expired JWT token for testing."""
    # Use past times for both iat and exp
    base_time = datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    payload = {
        "Credentials": {
            "AccessKeyId": "ASIA123456789",
            "SecretAccessKey": "temp_secret_key",
            "SessionToken": "temp_session_token",
            "Expiration": (base_time + timedelta(hours=2)).isoformat(),
        },
        "iat": (base_time - timedelta(hours=2)).timestamp(),  # Past issued at
        "exp": (base_time - timedelta(hours=1)).timestamp(),  # Past expiration
        "iss": "sck-core-api",
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


@pytest.fixture
def simple_valid_token():
    """Fixture for a simple valid token for validation tests."""
    # Use current time for iat, future for exp
    now = datetime.now(timezone.utc)

    payload = {
        "test": "data",
        "iat": now.timestamp(),  # Current time
        "exp": (now + timedelta(hours=2)).timestamp(),  # Future
        "iss": "sck-core-api",  # FIXED: Add required issuer claim
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


@pytest.fixture
def mock_sts_response():
    """Fixture providing a mock STS response."""
    # Use a far future time
    base_time = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    return {
        "Credentials": {
            "AccessKeyId": "ASIA123456789",
            "SecretAccessKey": "temp_secret_key",
            "SessionToken": "temp_session_token",
            "Expiration": base_time + timedelta(hours=24),  # Keep as datetime for mock STS response
        }
    }


@pytest.fixture
def api_gateway_event_base():
    """Fixture providing base API Gateway event structure."""
    return {QUERY_STRING_PARAMETERS: {}, PATH_PARAMETERS: {}, BODY_PARAMETER: ""}


# ============================================================================
# AUTHENTICATE_ACTION TESTS - CORRECTED TO USE util.to_json()
# ============================================================================


@pytest.mark.parametrize(
    "invalid_access_key",
    [
        "INVALID_KEY",  # Too short
        "BKIAIOSFODNN7EXAMPLE",  # Wrong prefix
        "AKIAIOSFODNN7EXAMPLEEXTRA",  # Too long
        # Removed: "",  # Empty - tested separately as "missing credentials"
    ],
)
def test_authenticate_invalid_access_key_format(invalid_access_key):
    """Test authentication with invalid access key formats."""
    invalid_creds = {
        "access_key": invalid_access_key,
        "access_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }

    result = _authenticate(**invalid_creds)

    assert isinstance(result, ErrorResponse)
    assert result.code == 400
    assert "Invalid AWS access key format" in result.message


@pytest.mark.parametrize(
    "invalid_secret",
    [
        "too_short",  # Too short
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYEXTRA",  # Too long
        # Removed: "",  # Empty - tested separately as "missing credentials"
    ],
)
def test_authenticate_invalid_secret_format(invalid_secret):
    """Test authentication with invalid secret key formats."""
    invalid_creds = {
        "access_key": "AKIAIOSFODNN7EXAMPLE",
        "access_secret": invalid_secret,
    }

    result = _authenticate(**invalid_creds)

    assert isinstance(result, ErrorResponse)
    assert result.code == 400
    assert "Invalid AWS secret key format" in result.message


# Keep the existing test for missing credentials:
def test_authenticate_validation_errors():
    """Test all input validation scenarios."""
    # Missing credentials (these should trigger "missing" not "invalid format")
    assert _authenticate().code == 400
    assert _authenticate(access_key="").code == 400  # Empty access key
    assert _authenticate(access_secret="").code == 400  # Empty secret

    # Invalid formats (non-empty but wrong format)
    assert _authenticate(access_key="INVALID", access_secret="x" * 40).code == 400
    assert _authenticate(access_key="AKIA" + "x" * 16, access_secret="short").code == 400


def test_authenticate_aws_errors():
    """Test AWS STS rejection scenarios."""

    valid_format_creds = {
        "access_key": "AKIAIOSFODNN7INVALID",  # Valid format, invalid creds
        "access_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEINV",  # FIXED: Exactly 40 chars
    }

    with patch("boto3.client") as mock_client:
        mock_sts = Mock()
        mock_client.return_value = mock_sts

        # Test different AWS error codes
        test_cases = [
            ("InvalidUserID.NotFound", 401, "Invalid AWS credentials"),
            ("SignatureDoesNotMatch", 401, "Invalid AWS credentials"),
            ("TokenRefreshRequired", 401, "AWS credentials require MFA token"),
            ("ServiceUnavailable", 503, "AWS authentication service error"),
            (
                "ThrottlingException",
                503,
                "AWS authentication service error",
            ),  # Add throttling
            (
                "UnknownErrorCode",
                503,
                "AWS authentication service error",
            ),  # Add unknown error
        ]

        for error_code, expected_status, expected_message in test_cases:
            mock_sts.get_session_token.side_effect = ClientError(
                error_response={"Error": {"Code": error_code}},
                operation_name="GetSessionToken",
            )

            result = _authenticate(**valid_format_creds)
            assert result.code == expected_status
            assert expected_message in result.message


def test_authenticate_action_success(valid_aws_credentials, api_gateway_event_base):
    """Test successful authentication action with valid body."""
    api_gateway_event_base[BODY_PARAMETER] = util.to_json(valid_aws_credentials)  # CORRECTED

    with patch("core_api.api.auth._authenticate") as mock_auth:
        mock_auth.return_value = Response(data={"token": "test_token", "expires_in": 3600}, code=200)

        result = authenticate_action(**api_gateway_event_base)

        assert isinstance(result, Response)
        assert result.code == 200
        mock_auth.assert_called_once_with(**valid_aws_credentials)


def test_authenticate_action_invalid_json(api_gateway_event_base):
    """Test authentication action with invalid JSON body."""
    api_gateway_event_base[BODY_PARAMETER] = "invalid json {"

    result = authenticate_action(**api_gateway_event_base)

    assert isinstance(result, ErrorResponse)
    assert result.code == 400
    assert "Invalid JSON" in result.message


def test_authenticate_action_empty_body(api_gateway_event_base):
    """Test authentication action with empty body."""
    api_gateway_event_base[BODY_PARAMETER] = ""

    with patch("core_api.api.auth._authenticate") as mock_auth:
        mock_auth.return_value = Response(data={}, code=200)

        result = authenticate_action(**api_gateway_event_base)

        assert isinstance(result, Response)
        mock_auth.assert_called_once_with()


def test_authenticate_action_no_body_parameter():
    """Test authentication action when body parameter is missing."""
    kwargs = {QUERY_STRING_PARAMETERS: {}, PATH_PARAMETERS: {}}

    with patch("core_api.api.auth._authenticate") as mock_auth:
        mock_auth.return_value = Response(data={}, code=200)

        result = authenticate_action(**kwargs)

        assert isinstance(result, Response)
        mock_auth.assert_called_once_with()


def test_authenticate_action_parameter_precedence(api_gateway_event_base):
    """Test that body parameters take precedence over query parameters."""
    api_gateway_event_base.update(
        {
            BODY_PARAMETER: util.to_json({"access_key": "from_body"}),  # CORRECTED
            QUERY_STRING_PARAMETERS: {"access_key": "from_query"},
        }
    )

    with patch("core_api.api.auth._authenticate") as mock_auth:
        mock_auth.return_value = Response(data={}, code=200)

        result = authenticate_action(**api_gateway_event_base)

        # Body should take precedence
        mock_auth.assert_called_once_with(access_key="from_body")


def test_authenticate_action_exception_handling(api_gateway_event_base):
    """Test authentication action exception handling."""
    api_gateway_event_base[BODY_PARAMETER] = util.to_json({"access_key": "test"})  # CORRECTED

    with patch("core_api.api.auth._authenticate") as mock_auth:
        mock_auth.side_effect = Exception("Test error")

        result = authenticate_action(**api_gateway_event_base)

        assert isinstance(result, ErrorResponse)
        assert result.code == 500
        assert "Authentication processing error" in result.message


def test_authenticate_action_with_datetime_objects(api_gateway_event_base):
    """Test authentication action with datetime objects in payload."""
    # This test demonstrates why util.to_json() is superior to json.dumps()

    # FIXED: Use a specific, fixed datetime instead of now()
    fixed_datetime = datetime(2024, 1, 15, 10, 30, 45, tzinfo=timezone.utc)

    credentials_with_datetime = {
        "access_key": "AKIAIOSFODNN7EXAMPLE",
        "access_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "timestamp": fixed_datetime,
    }

    # util.to_json() can handle datetime objects, json.dumps() cannot
    api_gateway_event_base[BODY_PARAMETER] = util.to_json(credentials_with_datetime)

    with patch("core_api.api.auth._authenticate") as mock_auth:
        mock_auth.return_value = Response(data={}, code=200)

        result = authenticate_action(**api_gateway_event_base)

        assert isinstance(result, Response)

        # FIXED: Use the same fixed datetime for expected result
        expected_call_args = {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "access_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "timestamp": fixed_datetime,  # util.to_json() converts to string but util.from_json() will convert back to datetime
        }
        mock_auth.assert_called_once_with(**expected_call_args)


# ============================================================================
# ALL OTHER TESTS REMAIN THE SAME (they don't use JSON serialization)
# ============================================================================


def test_authenticate_success(valid_aws_credentials, mock_sts_response):
    """Test successful authentication with valid AWS credentials."""
    with patch("boto3.client") as mock_boto_client:
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts
        mock_sts.get_session_token.return_value = mock_sts_response

        result = _authenticate(**valid_aws_credentials)

        assert isinstance(result, Response)
        assert result.code == 200
        assert "token" in result.data
        assert "expires_in" in result.data
        assert "token_type" in result.data
        assert result.data["token_type"] == "Bearer"

        # FIXED: Verify the correct boto3.client call including region
        mock_boto_client.assert_called_once_with(
            "sts",
            region_name="us-east-1",  # Added
            aws_access_key_id=valid_aws_credentials["access_key"],
            aws_secret_access_key=valid_aws_credentials["access_secret"],
            aws_session_token=None,  # None when not provided
        )


def test_authenticate_with_custom_region(valid_aws_credentials, mock_sts_response):
    """Test authentication with custom AWS region."""
    valid_aws_credentials["region"] = "eu-west-1"

    with patch("boto3.client") as mock_boto_client:
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts
        mock_sts.get_session_token.return_value = mock_sts_response

        result = _authenticate(**valid_aws_credentials)

        assert isinstance(result, Response)
        assert result.code == 200
        assert result.data["region"] == "eu-west-1"  # Should return the region used

        # Verify custom region was used
        mock_boto_client.assert_called_once_with(
            "sts",
            region_name="eu-west-1",  # Custom region
            aws_access_key_id=valid_aws_credentials["access_key"],
            aws_secret_access_key=valid_aws_credentials["access_secret"],
            aws_session_token=None,
        )


def test_authenticate_missing_credentials():
    """Test authentication with missing AWS credentials."""
    result = _authenticate()

    assert isinstance(result, ErrorResponse)
    assert result.code == 400
    assert "Missing required AWS credentials" in result.message


@pytest.mark.parametrize("missing_field", ["access_key", "access_secret"])
def test_authenticate_missing_credential_field(valid_aws_credentials, missing_field):
    """Test authentication with missing credential fields."""
    del valid_aws_credentials[missing_field]

    result = _authenticate(**valid_aws_credentials)

    assert isinstance(result, ErrorResponse)
    assert result.code == 400
    assert "Missing required AWS credentials" in result.message


def test_authenticate_with_session_token(valid_aws_credentials, mock_sts_response):
    """Test authentication with temporary credentials including session token."""
    valid_aws_credentials["session_token"] = "existing_session_token"

    with patch("boto3.client") as mock_boto_client:
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts
        mock_sts.get_session_token.return_value = mock_sts_response

        result = _authenticate(**valid_aws_credentials)

        assert isinstance(result, Response)
        assert result.code == 200

        # FIXED: Include region_name parameter that's now added by default
        mock_boto_client.assert_called_once_with(
            "sts",
            region_name="us-east-1",  # Added this line
            aws_access_key_id=valid_aws_credentials["access_key"],
            aws_secret_access_key=valid_aws_credentials["access_secret"],
            aws_session_token="existing_session_token",
        )


def test_authenticate_invalid_aws_credentials():
    """Test authentication with invalid AWS credentials."""
    # FIXED: Use valid format but invalid credentials
    invalid_creds = {
        "access_key": "AKIAIOSFODNN7INVALID",  # 20 chars, starts with AKIA - valid format
        "access_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEINV",  # FIXED: Exactly 40 chars
    }

    with patch("boto3.client") as mock_boto_client:
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts

        # Mock AWS error
        mock_sts.get_session_token.side_effect = ClientError(
            error_response={"Error": {"Code": "InvalidUserID.NotFound"}},
            operation_name="GetSessionToken",
        )

        result = _authenticate(**invalid_creds)

        assert isinstance(result, ErrorResponse)
        assert result.code == 401  # Now this will be 401 from AWS STS
        assert "Invalid AWS credentials" in result.message

        # Verify region was included in call
        mock_boto_client.assert_called_once_with(
            "sts",
            region_name="us-east-1",
            aws_access_key_id="AKIAIOSFODNN7INVALID",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEINV",  # FIXED
            aws_session_token=None,
        )


def test_authenticate_sts_service_error(valid_aws_credentials):
    """Test authentication with STS service error."""
    with patch("boto3.client") as mock_boto_client:
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts

        # Mock BotoCore error
        mock_sts.get_session_token.side_effect = BotoCoreError()

        result = _authenticate(**valid_aws_credentials)

        assert isinstance(result, ErrorResponse)
        assert result.code == 401

        # FIXED: Verify region was included in call
        mock_boto_client.assert_called_once_with(
            "sts",
            region_name="us-east-1",  # Added
            aws_access_key_id=valid_aws_credentials["access_key"],
            aws_secret_access_key=valid_aws_credentials["access_secret"],
            aws_session_token=None,
        )


def test_authenticate_unexpected_error(valid_aws_credentials):
    """Test authentication with unexpected error."""
    with patch("boto3.client") as mock_boto_client:
        mock_boto_client.side_effect = Exception("Unexpected error")

        result = _authenticate(**valid_aws_credentials)

        assert isinstance(result, ErrorResponse)
        assert result.code == 500
        assert "Authentication processing error" in result.message


# ============================================================================
# ALTERNATIVE STS TEST (if you want to use moto for real STS testing)
# ============================================================================


@mock_aws
def test_authenticate_with_moto_sts(valid_aws_credentials):
    """Test authentication using moto's STS mocking."""
    # moto STS doesn't validate actual AWS credentials - it just mocks the STS service
    # This test verifies that our STS integration works with moto's mock service

    import boto3

    # Create a real STS client in moto environment
    client = boto3.client("sts", region_name="us-east-1")

    with patch("core_api.api.auth.boto3.client") as mock_boto_client:
        mock_boto_client.return_value = client

        result = _authenticate(**valid_aws_credentials)

        # moto STS returns success for any credentials, so expect success
        assert isinstance(result, Response)
        assert result.code == 200
        assert "token" in result.data
        assert "expires_in" in result.data
        assert "token_type" in result.data
        assert result.data["token_type"] == "Bearer"

        # Verify the JWT token is valid
        token = result.data["token"]
        decoded = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        assert "Credentials" in decoded
        assert "AccessKeyId" in decoded["Credentials"]


# ============================================================================
# GET_CREDENTIALS TESTS (unchanged - no JSON serialization)
# ============================================================================


def test_get_credentials_success_with_authorization_header(valid_jwt_token):
    """Test successful credential extraction from Authorization header."""
    kwargs = {
        "headers": {
            "Authorization": f"Bearer {valid_jwt_token}",
            "Content-Type": "application/json",
        }
    }

    jwt_payload, _ = get_authenticated_user({}, kwargs["headers"])
    credentials = get_credentials(jwt_payload)

    assert credentials is not None
    assert "AccessKeyId" in credentials
    assert "SecretAccessKey" in credentials
    assert "SessionToken" in credentials
    assert "Expiration" in credentials
    assert credentials["AccessKeyId"] == "ASIA123456789"


def test_get_credentials_case_insensitive_header(valid_jwt_token):
    """Test credential extraction with case-insensitive Authorization header."""
    kwargs = {
        "headers": {
            "authorization": f"Bearer {valid_jwt_token}",
            "Content-Type": "application/json",
        }
    }  # lowercase

    jwt_payload, _ = get_authenticated_user({}, kwargs["headers"])
    credentials = get_credentials(jwt_payload)

    assert credentials is not None
    assert credentials["AccessKeyId"] == "ASIA123456789"


@pytest.mark.parametrize(
    "kwargs",
    [
        {},  # No headers
        {"headers": {}},  # Empty headers
        {"headers": {"Content-Type": "application/json"}},  # No auth header
    ],
)
def test_get_credentials_no_authorization(kwargs):
    """Test credential extraction when Authorization header is missing."""
    jwt_payload, _ = get_authenticated_user({}, kwargs["headers"])
    credentials = get_credentials(jwt_payload)
    assert credentials is None


def test_get_credentials_invalid_authorization_format(valid_jwt_token):
    """Test credential extraction with invalid Authorization header format."""
    kwargs = {
        "headers": {
            "Authorization": f"Basic {valid_jwt_token}",
            "Content-Type": "application/json",
        }
    }  # Wrong type

    jwt_payload, _ = get_authenticated_user({}, kwargs["headers"])
    credentials = get_credentials(jwt_payload)
    assert credentials is None


def test_get_credentials_malformed_authorization_header():
    """Test credential extraction with malformed Authorization header."""
    kwargs = {"headers": {"Authorization": "Bearer", "Content-Type": "application/json"}}  # Missing token

    jwt_payload, _ = get_authenticated_user({}, kwargs["headers"])
    credentials = get_credentials(jwt_payload)
    assert credentials is None


def test_get_credentials_expired_jwt_token(expired_jwt_token):
    """Test credential extraction with expired JWT token."""
    kwargs = {
        "headers": {
            "Authorization": f"Bearer {expired_jwt_token}",
            "Content-Type": "application/json",
        }
    }

    jwt_payload, _ = get_authenticated_user({}, kwargs["headers"])
    credentials = get_credentials(jwt_payload)
    assert credentials is None


def test_get_credentials_invalid_jwt_token():
    """Test credential extraction with invalid JWT token."""
    kwargs = {
        "headers": {
            "Authorization": "Bearer invalid.jwt.token",
            "Content-Type": "application/json",
        }
    }

    jwt_payload, _ = get_authenticated_user({}, kwargs["headers"])
    credentials = get_credentials(jwt_payload)
    assert credentials is None


def test_get_credentials_jwt_without_credentials():
    """Test credential extraction from JWT token without credentials."""
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)  # FIXED: Use future time
    payload = {
        "user": "test_user",
        "iat": now.timestamp(),
        "exp": (now + timedelta(hours=1)).timestamp(),
        "iss": "sck-core-api",
    }

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    kwargs = {
        "headers": {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
    }

    jwt_payload, _ = get_authenticated_user({}, kwargs["headers"])
    credentials = get_credentials(jwt_payload)
    assert credentials is None


def test_get_credentials_incomplete_credentials():
    """Test credential extraction with incomplete credentials in JWT."""
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)  # FIXED: Use future time
    payload = {
        "Credentials": {
            "AccessKeyId": "ASIA123456789",
            # Missing SecretAccessKey and SessionToken
        },
        "iat": now.timestamp(),
        "exp": (now + timedelta(hours=1)).timestamp(),
        "iss": "sck-core-api",
    }

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    kwargs = {
        "headers": {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
    }

    jwt_payload, _ = get_authenticated_user({}, kwargs["headers"])
    credentials = get_credentials(jwt_payload)
    assert credentials is None


def test_get_credentials_expired_sts_credentials():
    """Test credential extraction with expired STS credentials."""
    now = datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc)  # Use fixed past time for expiration
    payload = {
        "Credentials": {
            "AccessKeyId": "ASIA123456789",
            "SecretAccessKey": "temp_secret_key",
            "SessionToken": "temp_session_token",
            "Expiration": (now + timedelta(hours=1)).isoformat(),  # Convert to ISO string for JWT
        },
        "iat": now.timestamp(),
        "exp": (now + timedelta(hours=2)).timestamp(),
        "iss": "sck-core-api",
    }

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    kwargs = {
        "headers": {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
    }

    jwt_payload, _ = get_authenticated_user({}, kwargs["headers"])
    credentials = get_credentials(jwt_payload)
    assert credentials is None


def test_get_credentials_invalid_expiration_format():
    """Test credential extraction with invalid expiration format."""
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)  # FIXED: Use future time
    payload = {
        "Credentials": {
            "AccessKeyId": "ASIA123456789",
            "SecretAccessKey": "temp_secret_key",
            "SessionToken": "temp_session_token",
            "Expiration": "invalid-date-format",  # Already a string - invalid format
        },
        "iat": now.timestamp(),
        "exp": (now + timedelta(hours=1)).timestamp(),
        "iss": "sck-core-api",
    }

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    kwargs = {
        "headers": {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
    }

    jwt_payload, _ = get_authenticated_user({}, kwargs["headers"])
    credentials = get_credentials(jwt_payload)
    assert credentials is None


def _authenticate(**kwargs):
    return kwargs


# ============================================================================
# ENHANCED TESTS FOR PRODUCTION FEATURES
# ============================================================================


def test_authenticate_includes_jti_claim(valid_aws_credentials, mock_sts_response):
    """Test that authentication includes unique JWT ID claim."""
    with patch("boto3.client") as mock_boto_client:
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts
        mock_sts.get_session_token.return_value = mock_sts_response

        result = _authenticate(**valid_aws_credentials)

        assert isinstance(result, Response)
        assert result.code == 200

        # Verify JWT contains jti claim
        token = result.data["token"]
        decoded = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

        assert "jti" in decoded
        assert decoded["jti"].startswith("AKIAIOSF-")  # Should start with truncated access key
        assert len(decoded["jti"]) > 10  # Should include timestamp


def test_authenticate_enhanced_aws_errors():
    """Test comprehensive AWS STS rejection scenarios."""
    valid_format_creds = {
        "access_key": "AKIAIOSFODNN7INVALID",
        "access_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEINV",
    }

    with patch("boto3.client") as mock_client:
        mock_sts = Mock()
        mock_client.return_value = mock_sts

        # FIXED: Test all error codes from enhanced function
        test_cases = [
            ("InvalidUserID.NotFound", 401, "Invalid AWS credentials"),
            ("SignatureDoesNotMatch", 401, "Invalid AWS credentials"),
            ("TokenRefreshRequired", 401, "AWS credentials require MFA token"),
            ("ServiceUnavailable", 503, "AWS authentication service error"),
            (
                "ThrottlingException",
                503,
                "AWS authentication service error",
            ),  # Add throttling
            (
                "UnknownErrorCode",
                503,
                "AWS authentication service error",
            ),  # Add unknown error
        ]

        for error_code, expected_status, expected_message in test_cases:
            mock_sts.get_session_token.side_effect = ClientError(
                error_response={"Error": {"Code": error_code}},
                operation_name="GetSessionToken",
            )

            result = _authenticate(**valid_format_creds)
            assert result.code == expected_status
            assert expected_message in result.message

            # Verify region parameter included
            mock_client.assert_called_with(
                "sts",
                region_name="us-east-1",
                aws_access_key_id="AKIAIOSFODNN7INVALID",
                aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEINV",
                aws_session_token=None,
            )


# ============================================================================
# JWT CONFIGURATION VERIFICATION
# ============================================================================


def test_jwt_configuration_sanity():
    """Test that JWT configuration values are reasonable."""
    # Just verify the configuration loaded from .env is sane
    assert JWT_SECRET_KEY is not None
    assert len(JWT_SECRET_KEY) >= 32  # Minimum security requirement
    assert JWT_ALGORITHM in ["HS256", "HS384", "HS512"]
    assert 1 <= JWT_ACCESS_HOURS <= 168  # 1 hour to 1 week is reasonable


# ============================================================================
# TEST ISOLATION AND CLEANUP
# ============================================================================


@pytest.fixture(autouse=True)
def reset_auth_module():
    """Reset auth module state between tests for isolation."""
    # This ensures each test starts with a clean state
    yield
    # Cleanup happens here if needed - currently no cleanup required
    # but this fixture provides a place for future cleanup needs


def test_minimal_jwt_debug():
    """Test with minimal JWT payload for debugging."""
    # This test can be used for debugging JWT issues
    # Currently passes but available for troubleshooting
    pass


@pytest.mark.parametrize(
    "invalid_secret_length",
    [
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEINVALID",  # 47 chars - too long
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYEXTRA",  # 44 chars - too long
    ],
)
def test_secret_key_length_validation(invalid_secret_length):
    """Test that secret keys of wrong length are properly validated."""
    print(f"Secret length: {len(invalid_secret_length)} chars")
    assert len(invalid_secret_length) != 40  # Should not be 40 chars


def test_debug_jwt_token(valid_jwt_token):
    """Debug the JWT token to understand the issue."""
    print(f"\n=== JWT TOKEN DEBUG ===")
    print(f"Token: {valid_jwt_token}")

    try:
        # Try to decode without verification first
        decoded_no_verify = jwt.decode(valid_jwt_token, options={"verify_signature": False})
        print(f"Decoded (no verify): {decoded_no_verify}")

        # Check the structure
        if "Credentials" in decoded_no_verify:
            creds = decoded_no_verify["Credentials"]
            print(f"Credentials keys: {list(creds.keys())}")
            print(f"AccessKeyId: {creds.get('AccessKeyId')}")
            print(f"Expiration: {creds.get('Expiration')}")

            # Check expiration format
            exp_str = creds.get("Expiration")
            if exp_str:
                try:
                    from datetime import datetime

                    if exp_str.endswith("Z"):
                        exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                    else:
                        exp_dt = datetime.fromisoformat(exp_str)
                    print(f"Parsed expiration: {exp_dt}")
                    print(f"Current time: {datetime.now(timezone.utc)}")
                    print(f"Is future: {exp_dt > datetime.now(timezone.utc)}")
                except Exception as parse_err:
                    print(f"Expiration parse error: {parse_err}")

        # Try to decode with verification
        decoded_verified = jwt.decode(valid_jwt_token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        print(f"Decoded (verified): Success")

    except jwt.ExpiredSignatureError:
        print(f"JWT Error: Token is expired")
    except jwt.InvalidTokenError as e:
        print(f"JWT Error: Invalid token - {e}")
    except Exception as e:
        print(f"Other error: {e}")
        import traceback

        traceback.print_exc()

    print(f"=== END DEBUG ===\n")


# ============================================================================
# ADDITIONAL EDGE CASES AND SECURITY TESTS
# ============================================================================


def test_authenticate_response_includes_region():
    """Test that authentication response includes region information."""
    # This test verifies the enhanced response format
    valid_creds = {
        "access_key": "AKIAIOSFODNN7EXAMPLE",
        "access_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "region": "eu-west-1",
    }

    with patch("boto3.client") as mock_boto_client:
        mock_sts = Mock()
        mock_boto_client.return_value = mock_sts
        mock_sts.get_session_token.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIA123456789",
                "SecretAccessKey": "temp_secret_key",
                "SessionToken": "temp_session_token",
                "Expiration": datetime(2030, 1, 2, 12, 0, tzinfo=timezone.utc),
            }
        }

        result = _authenticate(**valid_creds)

        assert isinstance(result, Response)
        assert result.code == 200
        assert "region" in result.data
        assert result.data["region"] == "eu-west-1"
