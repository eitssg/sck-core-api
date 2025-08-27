import sys
import os
import subprocess


def test_environment_debug():
    """Debug which Python environment is actually being used."""

    print("=" * 60)
    print("PYTHON ENVIRONMENT DEBUG")
    print("=" * 60)

    # Check Python executable
    print(f"Python executable: {sys.executable}")
    print(f"Python version: {sys.version}")

    # Check if we're in the expected environment
    expected_python = "D:\\Development\\simple-cloud-kit-oss\\simple-cloud-kit\\sck-core-api\\.venv\\Scripts\\python.exe"
    print(f"Expected Python: {expected_python}")
    print(f"Match: {'✅' if expected_python.lower() in sys.executable.lower() else '❌'}")

    # Check environment variables
    print(f"VIRTUAL_ENV: {os.environ.get('VIRTUAL_ENV', 'Not set')}")
    print(f"PYTHONPATH: {os.environ.get('PYTHONPATH', 'Not set')}")

    # Check PyJWT specifically
    try:
        import jwt

        print(f"JWT module path: {jwt.__file__}")
        print(f"JWT version: {getattr(jwt, '__version__', 'Unknown')}")
        print(f"JWT has encode: {hasattr(jwt, 'encode')}")

        # Try to use encode
        test_token = jwt.encode({"test": "data"}, "secret", algorithm="HS256")
        print(f"JWT encode test: ✅ {type(test_token)}")

    except Exception as e:
        print(f"JWT error: ❌ {e}")
        import traceback

        traceback.print_exc()

    # List JWT packages
    try:
        result = subprocess.run([sys.executable, "-m", "pip", "list"], capture_output=True, text=True)
        lines = result.stdout.split("\n")
        jwt_lines = [line for line in lines if "jwt" in line.lower()]
        print(f"JWT-related packages: {jwt_lines}")
    except Exception as e:
        print(f"Pip list error: {e}")

    print("=" * 60)


if __name__ == "__main__":
    test_environment_debug()
    print("Environment debug complete.")
