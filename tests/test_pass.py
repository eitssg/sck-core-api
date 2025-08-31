import bcrypt

# Test with your actual hash
stored_hash = "$2b$12$NXJAURKqMANxKNu1F8Z.6u7RPFBcDSDD476S.0ny9KNFfqaRs9y7."
test_password = "mJk7432hmnpQvX!"

# Test the verification
result = bcrypt.checkpw(test_password.encode("utf-8"), stored_hash.encode("utf-8"))
print(f"Password match: {result}")
