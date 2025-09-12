import unittest
import admin
import base64
import hashlib
import os


class TestAdmin(unittest.TestCase):

    def test_password_hash(self):
        """Test that password_hash generates a base64 encoded string."""
        password = "test_password"
        hashed_password = admin.password_hash(password)

        # Check if the returned value is a string
        self.assertIsInstance(hashed_password, str)

        # Check if the returned value is base64 encoded
        try:
            base64.b64decode(hashed_password)
        except Exception:
            self.fail("password_hash did not return a base64 encoded string.")

        # Check if the hash is correct length
        decoded_hash = base64.b64decode(hashed_password)
        self.assertEqual(len(decoded_hash), 80)

    def test_password_verify(self):
        """Test that password_verify correctly verifies a password against its hash."""
        password = "test_password"
        hashed_password = admin.password_hash(password)

        # Test successful verification
        self.assertTrue(admin.password_verify(password, hashed_password))

        # Test failed verification with an incorrect password
        incorrect_password = "wrong_password"
        self.assertFalse(admin.password_verify(
            incorrect_password, hashed_password))

        # Test with an empty password
        empty_password = ""
        empty_hash = admin.password_hash(empty_password)
        self.assertTrue(admin.password_verify(empty_password, empty_hash))


if __name__ == '__main__':
    unittest.main()
