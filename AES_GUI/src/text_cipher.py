# -*- coding: utf-8 -*-
"""
TextCipher — plaintext encryption / decryption wrapper.
"""

from .aes_adapter import AesDllAdapter, AesDllError


class TextCipher:
    """Encrypt and decrypt strings via AES DLL."""

    def __init__(self, adapter: AesDllAdapter):
        self._adapter = adapter

    def encrypt(self, plaintext: str, key: bytes) -> str:
        """Encrypt plaintext → hex ciphertext string. Empty string is supported."""
        return self._adapter.encrypt_string(plaintext, key)

    def decrypt(self, hex_cipher: str, key: bytes) -> str:
        """Decrypt hex ciphertext string → plaintext."""
        if not hex_cipher:
            raise ValueError("Ciphertext must not be empty")
        return self._adapter.decrypt_string(hex_cipher, key)

    @staticmethod
    def extract_iv(hex_cipher: str) -> str:
        """Extract the IV (first 32 hex chars) from a ciphertext."""
        return hex_cipher[:32] if len(hex_cipher) >= 32 else ""

    @staticmethod
    def extract_cipher_body(hex_cipher: str) -> str:
        """Extract the cipher body (after the first 32 hex chars)."""
        return hex_cipher[32:] if len(hex_cipher) > 32 else ""
