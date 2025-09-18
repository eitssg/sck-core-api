from core_api.auth.tools import encrypt_creds, decrypt_creds


# Add this test function temporarily to verify
def test_encrypt_decrypt_roundtrip():
    test_creds = {
        "AccessKeyId": "AKIATEST123456789",
        "SecretAccessKey": "test-secret-key-12345",
    }

    try:
        # Test encrypt
        encrypted = encrypt_creds(test_creds)
        print(f"✅ Encryption successful: {encrypted[:50]}...")

        # Test decrypt
        decrypted = decrypt_creds(encrypted)
        print(f"✅ Decryption successful: {decrypted}")

        # Verify round-trip
        if test_creds == decrypted:
            print("✅ Round-trip verification PASSED")
            return True
        else:
            print(f"❌ Round-trip verification FAILED")
            print(f"Original:  {test_creds}")
            print(f"Decrypted: {decrypted}")
            return False

    except Exception as e:
        print(f"❌ Round-trip test FAILED with error: {e}")
        return False
