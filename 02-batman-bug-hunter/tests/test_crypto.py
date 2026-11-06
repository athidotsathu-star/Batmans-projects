"""Regression tests for the existing Crypto Lab."""
import unittest

from batman_hunter.crypto import (
    CryptoError,
    decrypt_text,
    encrypt_text,
    generate_password,
    sha256_text,
)


class CryptoLabTests(unittest.TestCase):
    def test_encrypt_decrypt_round_trip(self):
        message = "BATMAN BUG HUNTER X — packaging test"
        token = encrypt_text(message, "correct horse battery staple")
        self.assertTrue(token.startswith("BBH1."))
        self.assertEqual(decrypt_text(token, "correct horse battery staple"), message)

    def test_wrong_passphrase_is_rejected(self):
        token = encrypt_text("classified", "correct horse battery staple")
        with self.assertRaises(CryptoError):
            decrypt_text(token, "incorrect horse battery staple")

    def test_tampered_payload_is_rejected(self):
        token = encrypt_text("classified", "correct horse battery staple")
        altered = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
        with self.assertRaises(CryptoError):
            decrypt_text(altered, "correct horse battery staple")

    def test_sha256_known_vector(self):
        self.assertEqual(
            sha256_text("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_password_length_and_character_classes(self):
        password = generate_password(24)
        self.assertEqual(len(password), 24)
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))


if __name__ == "__main__":
    unittest.main()
