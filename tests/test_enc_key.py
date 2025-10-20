import base64
import secrets


def test_enc_key():
    # Generate exactly 32 bytes
    key_bytes = secrets.token_bytes(32)
    key_b64url = base64.urlsafe_b64encode(key_bytes).decode().rstrip("=")
    print(f"CRED_ENC_KEY={key_b64url}")
    print(f"Length when decoded: {len(base64.urlsafe_b64decode(key_b64url + '==='))}")

    assert len(base64.urlsafe_b64decode(key_b64url + '===')) == 32
    assert len(key_b64url) == 43
