# -*- coding: utf-8 -*-
"""
FileCipher — file encryption / decryption wrapper.
"""

import os
from .aes_adapter import AesDllAdapter


class FileCipher:
    """Encrypt and decrypt files via AES DLL."""

    ENC_EXT = ".enc"

    def __init__(self, adapter: AesDllAdapter):
        self._adapter = adapter

    @classmethod
    def is_encrypted_file(cls, path: str) -> bool:
        return path.lower().endswith(cls.ENC_EXT)

    @classmethod
    def can_encrypt(cls, path: str) -> bool:
        return not cls.is_encrypted_file(path)

    @classmethod
    def can_decrypt(cls, path: str) -> bool:
        return cls.is_encrypted_file(path)

    def encrypt(self, in_path: str, out_path: str, key: bytes) -> bool:
        if not os.path.isfile(in_path):
            raise FileNotFoundError(f"File not found: {in_path}")
        if not self.can_encrypt(in_path) or not self.is_encrypted_file(out_path):
            raise ValueError("Unsupported file format for encryption")
        return self._adapter.encrypt_file(in_path, out_path, key)

    def decrypt(self, in_path: str, out_path: str, key: bytes) -> bool:
        if not os.path.isfile(in_path):
            raise FileNotFoundError(f"File not found: {in_path}")
        if not self.can_decrypt(in_path):
            raise ValueError("Unsupported file format for decryption")
        return self._adapter.decrypt_file(in_path, out_path, key)

    @classmethod
    def suggest_output_path(cls, input_path: str, for_encrypt: bool) -> str:
        """Generate a default output path."""
        if for_encrypt:
            return input_path + cls.ENC_EXT
        base = input_path
        if base.lower().endswith(cls.ENC_EXT):
            base = base[: -len(cls.ENC_EXT)]
        return base + ".dec" if base == input_path else base
