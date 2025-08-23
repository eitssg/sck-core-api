from typing import Optional, Tuple, Dict
import time
import base64
import os
import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Request

import jwt
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import core_logging as log

from core_db.response import SuccessResponse
from core_db.profile.model import UserProfile
from core_db.profile.actions import ProfileActions
from core_db.oauth.actions import RateLimitActions

from .constants import KDF_ITERATIONS, JWT_SECRET_KEY, JWT_ALGORITHM, CRED_ENC_KEY_B64


def _derive_fernet_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """
    Derive a Fernet key from a user password using PBKDF2-HMAC-SHA256.

    Args:
        password (str): User-provided password.
        salt (bytes): Random salt used for derivation.
        iterations (int): PBKDF2 iteration count.

    Returns:
        bytes: Base64url-encoded 32-byte key suitable for Fernet.
    """
    if not password:
        raise ValueError("Password required for key derivation")
    pwd_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    raw = kdf.derive(pwd_bytes)
    return base64.urlsafe_b64encode(raw)


def encrypt_credentials(credentials: Dict, password: str) -> dict:
    """
    Encrypt profile credentials with a user-supplied password using PBKDF2 + Fernet.

    Args:
        credentials (dict): Dict containing at least AccessKeyId and SecretAccessKey.
        password (str): User password used to derive the encryption key.

    Returns:
        dict: JSON envelope with KDF parameters and ciphertext.
    """
    salt = os.urandom(16)
    key = _derive_fernet_key(password, salt)
    f = Fernet(key)
    ct = f.encrypt(json.dumps(credentials).encode("utf-8"))
    envelope = {
        "v": 1,
        "mode": "user",
        "kdf": "pbkdf2-sha256",
        "iterations": KDF_ITERATIONS,
        "salt": base64.urlsafe_b64encode(salt).decode().rstrip("="),
        "ct": ct.decode("utf-8"),
    }
    return envelope


def _b64pad(v: str) -> str:
    """Pad a base64url string to a valid length for decoding.

    Args:
        v (str): Base64url string without padding.

    Returns:
        str: Padded base64 string safe to decode.
    """
    return v + "=" * (-len(v) % 4)


_CRED_JWK = None
if CRED_ENC_KEY_B64:
    key_bytes = base64.urlsafe_b64decode(_b64pad(CRED_ENC_KEY_B64))
    if len(key_bytes) != 32:
        raise ValueError("CRED_ENC_KEY must be 32 bytes (base64url-decoded)")
    _CRED_JWK = JWK(kty="oct", k=base64.urlsafe_b64encode(key_bytes).decode())


def encrypt_creds(creds: Dict) -> str:
    """Encrypt AWS STS credentials using JWE (dir + A256GCM).

    Args:
        creds (dict): AWS STS credential fields to encrypt.

    Returns:
        str: Compact JWE string containing the encrypted credentials.
    """
    if not _CRED_JWK:
        raise RuntimeError("CRED_ENC_KEY not set")
    jwe = JWE(plaintext=json.dumps(creds).encode("utf-8"), protected={"alg": "dir", "enc": "A256GCM"})
    jwe.add_recipient(_CRED_JWK)
    return jwe.serialize(compact=True)


def decrypt_creds(enc: str) -> dict:
    """Decrypt a compact JWE string and return the AWS STS credential dict.

    Args:
        enc (str): Compact JWE produced by encrypt_creds().

    Returns:
        dict: Decrypted AWS STS credential fields.
    """
    if not _CRED_JWK:
        raise RuntimeError("CRED_ENC_KEY not set")
    jwe = JWE()
    jwe.deserialize(enc, key=_CRED_JWK)
    return json.loads(jwe.payload.decode("utf-8"))


def decrypt_credentials(env: Dict, password: str) -> dict:
    """
    Decrypt profile credentials previously encrypted with encrypt_credentials().

    Args:
        env (dict): JSON envelope from encrypt_credentials().
        password (str): User password used to derive the decryption key.

    Returns:
        dict: Decrypted credential dict.

    Raises:
        RuntimeError: If decryption fails.
    """
    try:
        if not isinstance(env, dict) or env.get("mode") != "user" or env.get("v") != 1:
            raise ValueError("Unsupported credential envelope")

        salt = base64.urlsafe_b64decode(_b64pad(env["salt"]))

        iters = int(env.get("iterations", KDF_ITERATIONS))

        key = _derive_fernet_key(password, salt, iters)

        f = Fernet(key)
        pt = f.decrypt(env["ct"].encode("utf-8"))

        data = pt.decode("utf-8")

        return json.loads(data)
    except Exception as e:
        raise RuntimeError(f"Credential decryption failed: {e}")


def _is_jwe_compact(s: str) -> bool:
    """
    Heuristic to detect JWE compact serialization (five segments).

    Args:
        s (str): Candidate token string.

    Returns:
        bool: True if token looks like JWE compact, else False.
    """
    return isinstance(s, str) and s.count(".") == 4


def _decrypt_profile_credentials(cred_str: str, password: Optional[str]) -> Optional[dict]:
    """
    Decrypt stored profile credentials.

    - If JWE compact, use server key (no password).
    - Else assume user-mode envelope and require password.

    Args:
        cred_str (str): Stored credential blob.
        password (Optional[str]): Password if user-encrypted.

    Returns:
        Optional[dict]: Decrypted credentials or None on failure.
    """
    try:
        if _is_jwe_compact(cred_str):
            return decrypt_creds(cred_str)
        if not password:
            return None
        return decrypt_credentials(cred_str, password)
    except Exception:
        return None


def get_user_access_key(user_id: str, password: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """Load and decrypt default profile, returning AWS access keys.

    Args:
        user_id (str): Profile owner identifier (email).
        password (Optional[str]): Required only if profile was encrypted with user password.

    Returns:
        Tuple[Optional[str], Optional[str]]: (AccessKeyId, SecretAccessKey) on success; otherwise (None, None).
    """
    try:
        response: SuccessResponse = ProfileActions.get(user_id=user_id, profile_name="default")
    except Exception as e:
        log.debug(f"Error retrieving profile for user {user_id}: {e}")
        return None, None

    profile = UserProfile(**response.data)
    enc = profile.credentials
    if not enc:
        return None, None

    creds = _decrypt_profile_credentials(enc, password=password)
    if not creds:
        return None, None

    return creds.get("AccessKeyId"), creds.get("SecretAccessKey")


def create_session_jwt(user_id: str, cred_jwe: str, minutes: int | None = None) -> str:
    """Create a short-lived session JWT (no enc_credentials)."""
    ttl = minutes if isinstance(minutes, int) and minutes > 0 else int(os.getenv("SESSION_JWT_MINUTES", "30"))
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ttl)
    payload = {
        "sub": user_id,
        "typ": "session",
        "iss": "sck-core-api",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": uuid.uuid4().hex,
        # JWE of long-term access keys (server-only decrypt)
        "cred_jwe": cred_jwe,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_client_identifier(request: Request) -> str:
    """Generate server-controlled client identifier."""
    ip = request.client.host if request.client else "unknown"

    # Optional: Include forwarded IP if behind proxy
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    real_ip = forwarded if forwarded and forwarded != ip else ip

    # Include user agent for fingerprinting
    ua = request.headers.get("user-agent", "unknown")[:50]

    return f"{real_ip}#{ua}"


def _get_rate_limit_key(identifier: str, endpoint: str) -> str:
    """Generate DDB key for rate limiting."""
    return f"rate#{endpoint}#{identifier}"


def check_rate_limit(request: Request, endpoint: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
    """Check if identifier is rate limited for endpoint.

    Returns:
        bool: True if allowed, False if rate limited.
    """

    identifier = get_client_identifier(request)
    key = _get_rate_limit_key(identifier, endpoint)
    now = int(time.time())
    window_start = now - (window_minutes * 60)

    try:
        # Get current attempts
        response: SuccessResponse = RateLimitActions.get(**{"code": key})

    except Exception as e:

        # No record exists (probably)
        RateLimitActions.create(
            **{
                "code": key,
                "attempts": [now],
                "ttl": now + (window_minutes * 60),
            }
        )  # Auto-expire
        return True

    try:
        # Filter recent attempts
        attempts = [ts for ts in response.get("attempts", []) if ts > window_start]

        if len(attempts) >= max_attempts:
            return False  # Rate limited

        # Add current attempt
        attempts.append(now)
        RateLimitActions.update(
            **{
                "code": key,
                "attempts": attempts,
                "ttl": now + (window_minutes * 60),
            }
        )
        return True

    except Exception as e:
        log.warning(f"Rate limit check failed: {e}")
        return True  # Fail open to avoid blocking legitimate users


def cookie_opts():
    """Cookie attributes; set SECURE_COOKIES=true in prod."""
    secure = os.getenv("SECURE_COOKIES", "false").lower() in ("1", "true", "yes")
    same_site = os.getenv("COOKIE_SAMESITE", "lax").capitalize()  # Lax, None, Strict
    domain = os.getenv("COOKIE_DOMAIN")  # optional
    opts = dict(httponly=True, secure=secure, samesite=same_site, path="/")
    if domain:
        opts["domain"] = domain
    return opts
