from datetime import datetime, timezone
from typing import Any, Dict, Optional

import core_logging as log


from .tools import JwtPayload, decrypt_creds


def get_credentials(jwt_payload: JwtPayload) -> Optional[Dict[str, Any]]:
    """Extract and decrypt AWS credentials from a Bearer JWT in an API Gateway proxy event.

    Args:
        event (ProxyEvent): API Gateway event carrying HTTP headers.

    Returns:
        Optional[Dict[str, Any]]: Decrypted STS credentials if present and valid; otherwise None.
    """
    try:
        if not jwt_payload:
            log.debug("No JWT payload found in request")
            return None

        enc = jwt_payload.enc
        if not enc:
            log.warn("No credentials found in JWT payload")
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
                    expiration = datetime.fromisoformat(expiration_str.replace("Z", "+00:00"))
                elif expiration_str.endswith("+00:00"):
                    expiration = datetime.fromisoformat(expiration_str)
                elif "+" in expiration_str or expiration_str.count("-") > 2:
                    expiration = datetime.fromisoformat(expiration_str)
                else:
                    expiration = datetime.fromisoformat(expiration_str).replace(tzinfo=timezone.utc)

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
