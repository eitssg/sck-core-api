"""
Provide HTTP endpoints for Passkey (WebAuthn) registration and authentication.

Design notes:
- Begin endpoints generate a challenge and options only. We do NOT write to DB here.
- Complete endpoints persist verified credential facts to PassKeys table.
- Response.code remains an int. We surface ephemeral states like "challenge_issued"
    via Response.message.
"""

import os
import base64
from datetime import datetime, timedelta, timezone

from webauthn import base64url_to_bytes, verify_authentication_response, verify_registration_response
from webauthn.helpers.structs import (
    CredentialDeviceType,
    PublicKeyCredentialType,
    RegistrationCredential,
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
)
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication
from webauthn.registration.verify_registration_response import VerifiedRegistration

import core_logging as log

from core_db.passkey import PassKeyActions, PassKey
from core_db.profile import ProfileActions, UserProfile

from ..security import get_authenticated_user
from ..request import RouteEndpoint
from ..response import Response, SuccessResponse, ErrorResponse, RedirectResponse, cookie_opts
from ..auth.tools import JwtPayload, check_rate_limit, emit_session_cookie

PASSKEY_CHALLENGE_COOKIE = "sck_passkey_challenge"
AUTH_CLIENT = "core"
AUTH_CLIENT_ID = ""

###########################################################
#
# THIS FILE IS RUN INSIDE A LAMBDA FUNCTION IT IS NOT A
# FASTAPI ASYNC HANDLER
#
###########################################################


def _merge_params(query_params: dict, body: dict) -> dict:
    """Merge query, path, and body parameters into a single dictionary."""
    merged = {}
    if query_params:
        merged.update(query_params)
    if body:
        merged.update(body)
    return merged


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _generate_challenge(length: int = 32) -> str:
    return _b64url(os.urandom(length))


def _register_begin(**kwargs) -> dict:
    """Build PublicKeyCredentialCreationOptions for WebAuthn registration.

    Input (kwargs): may include user_id, user_name, display_name, rp_id, rp_name.
    Returns: SuccessResponse with options and message="challenge_issued".
    """
    user_id = kwargs.get("user_id")
    user_name = kwargs.get("user_name") or user_id
    display_name = kwargs.get("display_name") or user_name
    rp_id = kwargs.get("rp_id")
    rp_name = kwargs.get("rp_name") or "Simple Cloud Kit"

    # Exclude already-registered credential ids for this user
    exclude_credentials = []
    if user_id:
        try:
            existing = PassKeyActions.list(user_id=user_id)
            if existing and existing.data:
                for item in existing.data:
                    cid = item.get("key_id")
                    if cid:
                        exclude_credentials.append({"type": "public-key", "id": cid})
        except Exception:
            # Non-fatal: proceed without exclude list
            pass

    options = {
        "challenge": _generate_challenge(),
        "timeout": 60000,
        "attestation": "none",
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},  # ES256
            {"type": "public-key", "alg": -257},  # RS256
        ],
        "authenticatorSelection": {
            "residentKey": "preferred",
            "requireResidentKey": False,
            "userVerification": "preferred",
            # Prefer external authenticators (password manager apps/extensions, security keys)
            "authenticatorAttachment": "cross-platform",
        },
        "excludeCredentials": exclude_credentials,
        "user": {
            "id": _b64url((user_id or "").encode("utf-8")),
            "name": user_name or "",
            "displayName": display_name or "",
        },
    }
    # Always include rp with at least a name; id is optional
    rp = {"name": rp_name}
    if rp_id:
        rp["id"] = rp_id
    options["rp"] = rp

    return options


def _register_end(**kwargs) -> dict:
    """Create a PassKey dict from a verified attestation result.

    Expected kwargs (normalized keys):
    - user_id (str)
    - key_id (str) credentialId (base64url)
    - public_key (str) PEM/SPKI or base64 COSE-encoded public key
    - name (str|None)
    - aaguid (str|None)
    - fmt (str|None)
    - att_stmt (dict|None)
    - transports (list[str]|None)
    - sign_count|counter (int|None)
    - cred_protect (str|None)
    - rk (bool|None)
    - uv (bool|None)  # if available from registration
    - extensions (dict|None)
    - device_type (str|None)
    - authenticator_version (int|None)
    """
    # Map common alternate keys from client libraries
    public_key = kwargs.get("public_key") or kwargs.get("publicKey")
    sign_count = kwargs.get("sign_count") or kwargs.get("signCount") or kwargs.get("counter")
    att_stmt = kwargs.get("att_stmt") or kwargs.get("attStmt")

    data = {
        "user_id": kwargs.get("user_id"),
        "key_id": kwargs.get("key_id"),
        "public_key": public_key,
        "name": kwargs.get("name"),
        "aaguid": kwargs.get("aaguid"),
        "fmt": kwargs.get("fmt"),
        "att_stmt": att_stmt,
        "transports": kwargs.get("transports"),
        "sign_count": sign_count,
        "counter": kwargs.get("counter", sign_count),
        "cred_protect": kwargs.get("cred_protect") or kwargs.get("credProtect"),
        "rk": kwargs.get("rk"),
        "uv": kwargs.get("uv"),
        "extensions": kwargs.get("extensions"),
        "device_type": kwargs.get("device_type"),
        "authenticator_version": kwargs.get("authenticator_version"),
        "deleted": False,
    }

    # Drop None values to avoid overwriting
    return {k: v for k, v in data.items() if v is not None}


def _authenticate_begin(**kwargs) -> dict:
    """Build PublicKeyCredentialRequestOptions for WebAuthn authentication.

    Input (kwargs): may include user_id, rp_id, allow_credentials (optional override).
    Returns: SuccessResponse with options and message="challenge_issued".
    """
    user_id = kwargs.get("user_id")
    rp_id = kwargs.get("rp_id")

    allow_credentials = []
    if kwargs.get("allow_credentials"):
        allow_credentials = kwargs["allow_credentials"]
    elif user_id:
        try:
            existing = PassKeyActions.list(user_id=user_id)
            if existing and existing.data:
                for item in existing.data:
                    cid = item.get("key_id")
                    if cid:
                        transports = item.get("transports") or None
                        entry = {"type": "public-key", "id": cid}
                        if transports:
                            entry["transports"] = transports
                        allow_credentials.append(entry)
        except Exception:
            pass

    options = {
        "challenge": _generate_challenge(),
        "timeout": 60000,
        "userVerification": "preferred",
        "allowCredentials": allow_credentials,
        # Hint to browsers to prefer external authenticators (Chrome supports this)
        "hints": ["security-key"],
    }
    if rp_id:
        options["rpId"] = rp_id

    return options


def _authenticate_complete(**kwargs) -> dict:
    """Update fields after a verified WebAuthn assertion.

    Expected kwargs:
    - user_id, key_id
    - uv (bool|None)
    - newSignCount|sign_count|counter (int|None)
    - clone_warning|cloneWarning (bool|None)
    - device_type, authenticator_version (optional)
    """
    new_sign_count = kwargs.get("newSignCount") or kwargs.get("sign_count") or kwargs.get("counter")

    device_type = kwargs.get("device_type")
    if isinstance(device_type, CredentialDeviceType):
        device_type = device_type.value

    data = {
        "user_id": kwargs.get("user_id"),
        "key_id": kwargs.get("key_id"),
        "uv": kwargs.get("uv"),
        "clone_warning": kwargs.get("clone_warning") or kwargs.get("cloneWarning"),
        "sign_count": new_sign_count,
        "counter": kwargs.get("counter", new_sign_count),
        "last_used_at": datetime.now(timezone.utc),
        "device_type": device_type,
        "authenticator_version": kwargs.get("authenticator_version"),
    }
    return {k: v for k, v in data.items() if v is not None}


def register_begin(*, headers: dict | None = None, cookies: dict, query_params: dict, body: dict, **kwargs) -> Response:

    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if not jwt_payload:
        return ErrorResponse(code=401, message="Unauthorized")

    # Rate-limit early to avoid generating excessive challenges/cookies
    if not check_rate_limit(headers, "passkey_auth", max_attempts=10, window_minutes=15):
        log.warn("Rate limit exceeded for Passkey register")
        return RedirectResponse(url="/error?error=rle&redirect=/login")

    merged = _merge_params(query_params, body)
    # Force user_id from authenticated session; ignore any provided body value
    merged["user_id"] = jwt_payload.sub

    # We only generate options + challenge; don't write to DB here.
    # If client didn't provide a key_id, we still return options - key is created on complete.
    try:
        options = _register_begin(**merged)

        user_id = merged.get("user_id")
        challenge = options.get("challenge")

        token = JwtPayload(
            sub=user_id,
            cnm=merged.get("client"),
            cid=merged.get("client_id"),
            typ="passkey_challenge",
            exp=int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
            iat=int(datetime.now(timezone.utc).timestamp()),
            jti=_generate_challenge(16),
            cch=challenge,
        ).encode()

        response = SuccessResponse(data=options, message="challenge_issued")
        response.set_cookie(PASSKEY_CHALLENGE_COOKIE, token, max_age=300, **cookie_opts())
        return response

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def register_complete(*, headers: dict | None = None, cookies: dict, query_params: dict, body: dict, **kwargs) -> Response:

    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if not jwt_payload:
        return ErrorResponse(code=401, message="Unauthorized")

    challenge_token = cookies.get(PASSKEY_CHALLENGE_COOKIE)
    if not challenge_token:
        return ErrorResponse(code=400, message="Missing challenge cookie")

    try:
        tok = JwtPayload.decode(challenge_token)
    except Exception as e:
        return ErrorResponse(code=400, message="Invalid challenge cookie")

    if tok.typ != "passkey_challenge":
        return ErrorResponse(code=400, message="Invalid challenge cookie")

    if tok.sub != jwt_payload.sub:
        return ErrorResponse(code=400, message="You cannot register a passkey for another user")

    merged = _merge_params(query_params, body)

    # Verify the client used the same challenge we issued
    client_challenge = (
        merged.get("challenge")
        or merged.get("client_data_challenge")
        or merged.get("clientDataJSON_challenge")
        or merged.get("clientDataChallenge")
    )
    if not client_challenge or client_challenge != tok.cch:
        return ErrorResponse(code=400, message="challenge_mismatch")

    # Rate-limit after validating the issued challenge, before any DB or crypto
    if not check_rate_limit(headers, "passkey_auth", max_attempts=10, window_minutes=15):
        log.warn("Rate limit exceeded for Passkey register")
        return RedirectResponse(url="/error?error=rle&redirect=/login")

    key_id_b64 = merged.get("key_id") or merged.get("keyId") or merged.get("id")
    if not key_id_b64:
        return ErrorResponse(code=400, message="key_id is required")

    key_id = base64url_to_bytes(key_id_b64)
    # Decode base64url-encoded WebAuthn fields to bytes for verification
    attestation_b64 = merged.get("attestation") or merged.get("attestationObject")
    client_data_b64 = merged.get("client_data_json") or merged.get("clientDataJSON")
    missing = []
    if not attestation_b64:
        missing.append("attestationObject")
    if not client_data_b64:
        missing.append("clientDataJSON")
    if missing:
        return ErrorResponse(code=400, message="missing_fields: " + ", ".join(missing))
    try:
        attestation_data = base64url_to_bytes(attestation_b64) if isinstance(attestation_b64, str) else attestation_b64
        client_data_json = base64url_to_bytes(client_data_b64) if isinstance(client_data_b64, str) else client_data_b64
    except Exception as e:
        return ErrorResponse(code=400, message=f"Invalid attestation payload: {str(e)}")
    transports = merged.get("transports")

    register_credential = RegistrationCredential(
        id=key_id_b64,
        raw_id=key_id,
        response=AuthenticatorAttestationResponse(
            client_data_json=client_data_json,
            attestation_object=attestation_data,
            transports=transports,
        ),
        type=PublicKeyCredentialType.PUBLIC_KEY,
    )

    try:
        verification: VerifiedRegistration = verify_registration_response(
            credential=register_credential,
            # Compare using raw bytes of the original challenge
            expected_challenge=base64url_to_bytes(tok.cch),
            expected_rp_id=os.getenv("CLIENT_DOMAIN") or "localhost",
            expected_origin=os.getenv("CLIENT_HOST") or "http://localhost:8080",
            require_user_verification=True,
        )
    except Exception as e:
        return ErrorResponse(code=400, message=f"Registration verification failed: {str(e)}")

    # Build PassKey model from verified attestation and persist
    try:
        # Normalize values from verification to our PassKey schema
        verified_key_id_bytes = getattr(verification, "credential_id", None)
        verified_pub_key = getattr(verification, "credential_public_key", None)
        verified_sign_count = getattr(verification, "sign_count", None)
        verified_fmt = getattr(verification, "fmt", None)
        verified_aaguid = getattr(verification, "aaguid", None)
        verified_device_type = getattr(verification, "credential_device_type", None)

        # key_id: store as base64url string
        key_id_str = _b64url(verified_key_id_bytes) if isinstance(verified_key_id_bytes, (bytes, bytearray)) else key_id_b64

        # public_key: ensure string; base64url-encode bytes if needed
        if isinstance(verified_pub_key, (bytes, bytearray)):
            public_key_str = _b64url(verified_pub_key)
        else:
            public_key_str = verified_pub_key

        # aaguid: bytes -> canonical hex with dashes if bytes, else pass-through
        def _format_aaguid(val):
            try:
                if isinstance(val, (bytes, bytearray)) and len(val) == 16:
                    import uuid

                    return str(uuid.UUID(bytes=bytes(val)))
            except Exception:
                pass
            return val

        aaguid_str = _format_aaguid(verified_aaguid)

        # device type: map enum -> value string
        if isinstance(verified_device_type, CredentialDeviceType):
            device_type_str = verified_device_type.value
        else:
            device_type_str = str(verified_device_type) if verified_device_type is not None else None

        # default name if none provided
        default_name = f"Passkey ({device_type_str})" if device_type_str else "Passkey"
        name_val = merged.get("name") or default_name

        # Persist with string device_type for consistency
        pass_key = _register_end(
            user_id=jwt_payload.sub,
            key_id=key_id_str,
            public_key=public_key_str,
            name=name_val,
            aaguid=aaguid_str,
            fmt=verified_fmt,
            sign_count=verified_sign_count,
            transports=transports,
            device_type=device_type_str,
        )
        response = PassKeyActions.create(**pass_key)
        # Surface a friendly message; code remains int
        response.message = "registered"
        response.delete_cookie(PASSKEY_CHALLENGE_COOKIE, path="/")
        return response

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def webauthn_authenticate_begin(*, query_params: dict, body: dict, **kwargs) -> Response:

    merged = _merge_params(query_params, body)

    try:
        # Rate-limit before issuing a new challenge/cookie
        headers = kwargs.get("headers") if isinstance(kwargs, dict) else None
        if not check_rate_limit(headers, "passkey_auth", max_attempts=10, window_minutes=15):
            log.warn("Rate limit exceeded for Passkey auth begin")
            return RedirectResponse(url="/error?error=rle&redirect=/login")
        # Build options. This may include allowCredentials if user_id is known and
        # passkeys exist; otherwise it will be empty to support discoverable credentials.
        # We intentionally avoid returning 404/401 here to prevent user enumeration.
        options = _authenticate_begin(**merged)

        challenge = options.get("challenge")
        token = JwtPayload(
            sub=merged.get("user_id", ""),
            cnm=merged.get("client"),
            cid=merged.get("client_id"),
            typ="passkey_challenge",
            exp=int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
            iat=int(datetime.now(timezone.utc).timestamp()),
            jti=_generate_challenge(16),
            cch=challenge,
        ).encode()

        response = SuccessResponse(data=options, message="challenge_issued")
        response.set_cookie(PASSKEY_CHALLENGE_COOKIE, token, max_age=300, **cookie_opts())
        return response
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def webauthn_authenticate_complete(
    *, headers: dict | None = None, cookies: dict | None = None, query_params: dict, body: dict, **kwargs
) -> Response:

    merged = _merge_params(query_params, body)

    challenge_token = (cookies or {}).get(PASSKEY_CHALLENGE_COOKIE)
    if not challenge_token:
        return ErrorResponse(code=400, message="Missing challenge cookie")

    try:
        tok = JwtPayload.decode(challenge_token)
    except Exception:
        return ErrorResponse(code=400, message="Invalid challenge cookie")

    if tok.typ != "passkey_challenge":
        return ErrorResponse(code=400, message="Invalid challenge cookie")

    # Optional user binding: if tok.sub provided and request includes user_id, enforce equality
    req_user = merged.get("user_id")
    if tok.sub and req_user and tok.sub != req_user:
        return ErrorResponse(code=400, message="Invalid user ID")

    # Verify the client used the same challenge we issued
    client_challenge = (
        merged.get("challenge")
        or merged.get("client_data_challenge")
        or merged.get("clientDataJSON_challenge")
        or merged.get("clientDataChallenge")
    )
    if not client_challenge or client_challenge != tok.cch:
        return ErrorResponse(code=400, message="challenge_mismatch")

    # Rate-limit after validating the issued challenge, before any DB or crypto
    if not check_rate_limit(headers, "passkey_auth", max_attempts=10, window_minutes=15):
        log.warn("Rate limit exceeded for Passkey auth complete")
        return RedirectResponse(url="/error?error=rle&redirect=/login")

    user_id = merged.get("user_id")
    key_id = merged.get("key_id")

    if not user_id or not key_id:
        return ErrorResponse(code=400, message="user_id and key_id are required")

    # Load stored passkey to supply public key and current counter into verification
    try:
        stored_pk_resp = PassKeyActions.get(user_id=user_id, key_id=key_id)
        stored_pk = PassKey(**stored_pk_resp.data)
        # public_key may be base64url string; decode to bytes if so
        pk_bytes = None
        if isinstance(stored_pk.public_key, (bytes, bytearray)):
            pk_bytes = bytes(stored_pk.public_key)
        elif isinstance(stored_pk.public_key, str):
            try:
                pk_bytes = base64url_to_bytes(stored_pk.public_key)
            except Exception:
                # If not base64url, leave as None and let verification fail fast if required
                pk_bytes = None
        current_count = stored_pk.sign_count or stored_pk.counter or 0
    except Exception:
        return ErrorResponse(code=404, message="Passkey not found")

    # Validate required assertion fields

    # Validate required assertion fields
    client_data_b64 = merged.get("client_data_json") or merged.get("clientDataJSON")
    authenticator_data_b64 = merged.get("authenticator_data") or merged.get("authenticatorData")
    signature_b64 = merged.get("signature")
    missing_auth = []
    if not client_data_b64:
        missing_auth.append("clientDataJSON")
    if not authenticator_data_b64:
        missing_auth.append("authenticatorData")
    if not signature_b64:
        missing_auth.append("signature")
    if missing_auth:
        return ErrorResponse(code=400, message="missing_fields: " + ", ".join(missing_auth))

    # Build AuthenticationCredential from client payload and verify
    auth_credential = AuthenticationCredential(
        id=key_id,
        raw_id=base64url_to_bytes(key_id),
        type=PublicKeyCredentialType.PUBLIC_KEY,
        response=AuthenticatorAssertionResponse(
            client_data_json=base64url_to_bytes(client_data_b64 or ""),
            authenticator_data=base64url_to_bytes(authenticator_data_b64 or ""),
            signature=base64url_to_bytes(signature_b64 or ""),
            user_handle=(
                base64url_to_bytes(merged.get("user_handle"))
                if isinstance(merged.get("user_handle"), str)
                else merged.get("user_handle")
            ),
        ),
    )

    verification: VerifiedAuthentication = verify_authentication_response(
        credential=auth_credential,
        expected_challenge=base64url_to_bytes(tok.cch),
        expected_rp_id=os.getenv("CLIENT_DOMAIN") or "localhost",
        expected_origin=os.getenv("CLIENT_HOST") or "http://localhost:8080",
        credential_public_key=pk_bytes,
        credential_current_sign_count=current_count,
        require_user_verification=True,
    )

    try:
        # Prefer client from challenge token
        client_slug = tok.cnm or AUTH_CLIENT
        response = ProfileActions.get(client=client_slug, user_id=user_id, profile_name="default")
        profile: UserProfile = UserProfile(**response.data)
        if not profile.is_active:
            return ErrorResponse(code=403, message="User account is disabled")
    except Exception:
        return ErrorResponse(code=500, message="Failed to verify user profile")

    credential_id_bytes = verification.credential_id
    new_sign_count = verification.new_sign_count
    credential_device_type = verification.credential_device_type
    credential_backed_up = verification.credential_backed_up
    user_verified = verification.user_verified

    # Ensure the verified credential id matches the requested key_id
    try:
        verified_key_id = (
            _b64url(credential_id_bytes) if isinstance(credential_id_bytes, (bytes, bytearray)) else str(credential_id_bytes)
        )
    except Exception:
        verified_key_id = None
    if not verified_key_id or verified_key_id != key_id:
        return ErrorResponse(code=400, message="credential_id_mismatch")

    try:
        ProfileActions.patch(
            client=client_slug,
            user_id=user_id,
            profile_name="default",
            last_login=datetime.now(timezone.utc),
            session_count=profile.session_count + 1,
        )
    except Exception:
        return ErrorResponse(code=500, message="Failed to update user profile")

    try:
        # Patch with latest usage facts from verification
        clone_warning = False
        try:
            if isinstance(new_sign_count, int) and isinstance(current_count, int) and new_sign_count <= current_count:
                clone_warning = True
        except Exception:
            pass

        update_data = _authenticate_complete(
            user_id=user_id,
            key_id=key_id,
            uv=bool(user_verified),
            sign_count=new_sign_count,
            counter=new_sign_count,
            clone_warning=clone_warning,
            device_type=credential_device_type,
        )
        # Optional: last_uv_at and credential_backed_up
        try:
            if user_verified:
                update_data["last_uv_at"] = datetime.now(timezone.utc)
            if credential_backed_up is not None:
                update_data["credential_backed_up"] = bool(credential_backed_up)
        except Exception:
            pass

        PassKeyActions.patch(**update_data)

        # Issue session cookie and delete the one-time challenge cookie
        client_id = tok.cid or AUTH_CLIENT_ID
        resp: Response = emit_session_cookie(SuccessResponse(), client_id=client_id, user_id=user_id, client=client_slug)
        resp.delete_cookie(PASSKEY_CHALLENGE_COOKIE, path="/")
        return resp

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def delete_passkey(*, headers: dict | None = None, cookies: dict | None = None, path_params: dict, **kwargs) -> Response:

    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if not jwt_payload:
        return ErrorResponse(code=401, message="Unauthorized")

    # Rate-limit early for destructive action
    if not check_rate_limit(headers, "passkey_auth", max_attempts=10, window_minutes=15):
        log.warn("Rate limit exceeded for Passkey delete")
        return RedirectResponse(url="/error?error=rle&redirect=/login")

    user_id = jwt_payload.sub
    key_id = path_params.get("key_id")

    if not key_id:
        return ErrorResponse(code=400, message="key_id is required")

    try:
        response = PassKeyActions.delete(user_id=user_id, key_id=key_id)
        return response

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def update_passkey(*, cookies: dict | None = None, query_params: dict, path_params: dict, body: dict, **kwargs) -> Response:

    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if not jwt_payload:
        return ErrorResponse(code=401, message="Unauthorized")

    user_id = jwt_payload.sub
    key_id = path_params.get("key_id")

    if not key_id:
        return ErrorResponse(code=400, message="key_id is required")

    merged = _merge_params(query_params, body)
    if "user_id" in merged:
        del merged["user_id"]
    if "key_id" in merged:
        del merged["key_id"]

    try:

        response = PassKeyActions.patch(user_id=user_id, key_id=key_id, **merged)
        return response

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def get_passkeys(*, cookies: dict | None = None, query_params: dict, path_params: dict, body: dict, **kwargs) -> Response:

    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if not jwt_payload:
        return ErrorResponse(code=401, message="Unauthorized")

    user_id = jwt_payload.sub

    try:
        response = PassKeyActions.list(user_id=user_id)
        return response

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


auth_passkey_endpoints: dict[str, RouteEndpoint] = {
    "POST:/auth/v1/webauthn/register/begin": RouteEndpoint(
        register_begin,
        permissions=["user:sigpasskey:register"],
        required_token_type="session",
        allow_anonymous=False,
        client_isolation=False,
    ),
    "POST:/auth/v1/webauthn/register/complete": RouteEndpoint(
        register_complete,
        permissions=["user:passkey:register"],
        required_token_type="session",
        allow_anonymous=False,
        client_isolation=False,
    ),
    "POST:/auth/v1/webauthn/authenticate/begin": RouteEndpoint(
        webauthn_authenticate_begin,
        permissions=["user:sigpasskey:authenticate"],
        allow_anonymous=True,
        client_isolation=False,
    ),
    "POST:/auth/v1/webauthn/authenticate/complete": RouteEndpoint(
        webauthn_authenticate_complete,
        permissions=["user:sigpasskey:authenticate"],
        allow_anonymous=True,
        client_isolation=False,
    ),
    "DELETE:/auth/v1/passkey/{key_id}": RouteEndpoint(
        delete_passkey,
        permissions=["user:passkey:delete"],
        required_token_type="session",
        allow_anonymous=False,
        client_isolation=False,
    ),
    "PATCH:/auth/v1/passkey/{key_id}": RouteEndpoint(
        update_passkey,
        permissions=["user:passkey:update"],
        required_token_type="session",
        allow_anonymous=False,
        client_isolation=False,
    ),
    "GET:/auth/v1/passkeys": RouteEndpoint(
        get_passkeys,
        permissions=["user:passkey:list"],
        required_token_type="session",
        allow_anonymous=False,
        client_isolation=False,
    ),
}
