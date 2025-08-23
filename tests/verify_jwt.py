import jwt
from datetime import datetime, timezone, timedelta

# Test basic JWT functionality
try:
    print(f"JWT module location: {jwt.__file__}")
    print(f"JWT version: {getattr(jwt, '__version__', 'Unknown')}")

    # Test encoding
    test_payload = {
        "test": "data",
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    token = jwt.encode(test_payload, "secret", algorithm="HS256")
    print(f"✅ JWT encode works: {type(token)} - {token[:50]}...")

    # Test decoding
    decoded = jwt.decode(token, "secret", algorithms=["HS256"])
    print(f"✅ JWT decode works: {decoded}")

except Exception as e:
    print(f"❌ JWT Error: {e}")
    import traceback

    traceback.print_exc()
