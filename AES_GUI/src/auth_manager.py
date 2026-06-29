# -*- coding: utf-8 -*-
"""
AuthManager — software registration and user login management.
Stores credentials in HKEY_LOCAL_MACHINE\\SOFTWARE\\AES_Tool, encrypted via AES DLL.
"""

import hashlib
import winreg
from typing import Optional

from .aes_adapter import AesDllAdapter
from .remember_login import RememberLoginStore


REG_ROOT = winreg.HKEY_LOCAL_MACHINE
REG_KEY = r"SOFTWARE\AES_Tool"


class AuthManager:
    """Handles software registration and user authentication."""

    def __init__(self, adapter: AesDllAdapter):
        self._adapter = adapter
        self._remember_login = RememberLoginStore()

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
            self._ensure_key()
            with winreg.OpenKey(REG_ROOT, REG_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
            return True
        except OSError:
            return False

    def factory_reset(self) -> bool:
        self.clear_login_token()
        try:
            parent_path, key_name = REG_KEY.rsplit("\\", 1)
            with winreg.OpenKey(REG_ROOT, parent_path, 0, winreg.KEY_WRITE) as parent:
                winreg.DeleteKey(parent, key_name)
            return True
        except FileNotFoundError:
            return True
        except OSError:
            return False

    def _machine_binding(self) -> str:
        return self.generate_registration_code()

    def save_login_token(self, username: str) -> bool:
        if not self.user_exists(username):
            return False
        binding = self._machine_binding()
        if not binding:
            return False
        return self._remember_login.save(username, binding)

    def get_saved_login_user(self) -> str | None:
        binding = self._machine_binding()
        if not binding:
            return None
        username = self._remember_login.load(binding)
        if not username or not self.user_exists(username):
            return None
        return username

    def login_with_token(self, username: str | None = None) -> str | None:
        saved_user = self.get_saved_login_user()
        if not saved_user:
            return None
        if username and username != saved_user:
            return None
        return saved_user

    def clear_login_token(self) -> None:
        self._remember_login.clear()

    # ── registration ────────────────────────────────────────

    def generate_registration_code(self) -> str:
        """Generate a registration code from hardware features."""
        try:
            mac = self._adapter.get_mac_address()
            key = self._adapter.generate_key_from_machine()
            seed = f"{mac}:{key.hex()}"
            h = hashlib.sha256(seed.encode()).hexdigest()[:32].upper()
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
        return self._write_value("RegistrationCode", code)

    # ── user account ────────────────────────────────────────

    def user_exists(self, username: str) -> bool:
        """Check if a user account already exists."""
        return self._read_value(f"User_{username}") is not None

    def register_user(self, username: str, password: str, key: bytes) -> bool:
        """Store username and encrypted-password in registry."""
        try:
            enc_pwd = self._adapter.encrypt_string(password, key)
            return self._write_value(f"User_{username}", enc_pwd)
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
