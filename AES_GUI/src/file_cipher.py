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

    def encrypt(self, in_path: str, out_path: str, key: bytes) -> bool:
        if not os.path.isfile(in_path):
            raise FileNotFoundError(f"File not found: {in_path}")
        return self._adapter.encrypt_file(in_path, out_path, key)

    def decrypt(self, in_path: str, out_path: str, key: bytes) -> bool:
        if not os.path.isfile(in_path):
            raise FileNotFoundError(f"File not found: {in_path}")
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
