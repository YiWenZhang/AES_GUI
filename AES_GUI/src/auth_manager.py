# -*- coding: utf-8 -*-
"""
AuthManager — software registration and user login management.
Stores credentials in HKEY_LOCAL_MACHINE\\SOFTWARE\\AES_Tool, encrypted via AES DLL.
"""

import hashlib
import winreg
from typing import Optional

from .aes_adapter import AesDllAdapter


REG_ROOT = winreg.HKEY_CURRENT_USER
REG_KEY = r"SOFTWARE\AES_Tool"


class AuthManager:
    """Handles software registration and user authentication."""

    def __init__(self, adapter: AesDllAdapter):
        self._adapter = adapter
        self._ensure_key()

    # ── registry helpers ────────────────────────────────────

    def _ensure_key(self):
        """Create the registry key if it doesn't exist."""
        try:
            winreg.CreateKey(REG_ROOT, REG_KEY)
        except OSError:
            pass

    def _read_value(self, name: str) -> Optional[str]:
        try:
            with winreg.OpenKey(REG_ROOT, REG_KEY) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return str(value)
        except FileNotFoundError:
            return None

    def _write_value(self, name: str, value: str) -> bool:
        try:
            with winreg.OpenKey(REG_ROOT, REG_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
            return True
        except OSError:
            return False

    # ── registration ────────────────────────────────────────

    def generate_registration_code(self) -> str:
        """Generate a registration code from hardware features."""
        try:
            mac = self._adapter.get_mac_address()
            h = hashlib.sha256(mac.encode()).hexdigest()[:32].upper()
            return "-".join([h[i : i + 8] for i in range(0, 32, 8)])
        except Exception:
            return ""

    def validate_registration(self, code: str) -> bool:
        """Check whether the given registration code matches the hardware."""
        expected = self.generate_registration_code()
        if not expected:
            return False
        return code.replace("-", "").upper() == expected.replace("-", "").upper()

    def is_registered(self) -> bool:
        """Check if the software is already registered."""
        stored = self._read_value("RegistrationCode")
        if not stored:
            return False
        return self.validate_registration(stored)

    def register(self, code: str) -> bool:
        """Validate and persist a registration code."""
        if not self.validate_registration(code):
            return False
        self._write_value("RegistrationCode", code)
        return True

    # ── user account ────────────────────────────────────────

    def user_exists(self, username: str) -> bool:
        """Check if a user account already exists."""
        return self._read_value(f"User_{username}") is not None

    def register_user(self, username: str, password: str, key: bytes) -> bool:
        """Store username and encrypted-password in registry."""
        try:
            enc_pwd = self._adapter.encrypt_string(password, key)
            self._write_value(f"User_{username}", enc_pwd)
            return True
        except Exception:
            return False

    def login(self, username: str, password: str, key: bytes) -> bool:
        """Verify username and password against registry storage."""
        stored = self._read_value(f"User_{username}")
        if not stored:
            return False
        try:
            decrypted = self._adapter.decrypt_string(stored, key)
            return decrypted == password
        except Exception:
            return False
