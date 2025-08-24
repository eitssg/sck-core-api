from datetime import datetime, timezone
from typing import Any, Dict, Optional

import jwt
import core_logging as log


from ..request import ProxyEvent
from .constants import JWT_SECRET_KEY, JWT_ALGORITHM
from .tools import decrypt_creds


def get_credentials(event: ProxyEvent) -> Optional[Dict[str, Any]]:
    """Extract and decrypt AWS credentials from a Bearer JWT in an API Gateway proxy event.

    Args:
        event (ProxyEvent): API Gateway event carrying HTTP headers.

    Returns:
        Optional[Dict[str, Any]]: Decrypted STS credentials if present and valid; otherwise None.
    """
    try:
        headers = event.headers
        if not headers:
            return None

        authorization_header = None
        for header_name, header_value in headers.items():
            if header_name.lower() == "authorization":
                authorization_header = str(header_value).strip()
                break

        if not authorization_header:
            return None

        if not authorization_header.lower().startswith("bearer "):
            log.debug("Authorization header does not contain Bearer token")
            return None

        parts = authorization_header.split(" ", 1)
        if len(parts) != 2 or not parts[1].strip():
            log.debug("Malformed Authorization header format")
            return None

        log.debug("Received bearer token: %s", parts[1][:8] + "...")
        token = parts[1].strip()

        secret_key = JWT_SECRET_KEY
        try:
            payload = jwt.decode(
                token,
                secret_key,
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

        enc = payload.get("enc_credentials")
        if not enc:
            log.debug("No credentials found in JWT payload")
            return None

        try:
            credentials = decrypt_creds(enc)
        except Exception as e:
            log.debug(f"Error decrypting credentials: {e}")
            return None

        required_fields = ["AccessKeyId", "SecretAccessKey", "SessionToken"]
        if not all(field in credentials for field in required_fields):
            log.debug("Incomplete credentials in JWT payload")
            return None

        expiration_str = credentials.get("Expiration")
        if expiration_str:
            try:
                if expiration_str.endswith("Z"):
                    expiration = datetime.fromisoformat(
                        expiration_str.replace("Z", "+00:00")
                    )
                elif expiration_str.endswith("+00:00"):
                    expiration = datetime.fromisoformat(expiration_str)
                elif "+" in expiration_str or expiration_str.count("-") > 2:
                    expiration = datetime.fromisoformat(expiration_str)
                else:
                    expiration = datetime.fromisoformat(expiration_str).replace(
                        tzinfo=timezone.utc
                    )

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
        log.debug(f"Error extracting credentials from token: {e}")
        return None
