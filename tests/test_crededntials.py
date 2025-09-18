from core_api.auth.tools import encrypt_credentials, decrypt_credentials


def test_encrypt_decrypt_credentials():

    password = "test_password"

    creds = {
        "access_key": "test_access_key",
        "secret_key": "test_secret_key",
        "session_token": "test_session_token",
    }

    encrypted = encrypt_credentials(creds, password)

    decrypted = decrypt_credentials(encrypted, password)

    assert decrypted == creds
