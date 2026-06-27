# -*- coding: utf-8 -*-
"""
AesDllAdapter — ctypes wrapper for AES_DLL.dll
Provides a Pythonic interface to all 10 exported DLL functions.
"""

import ctypes
import os
import sys
from pathlib import Path
from typing import Optional


def _find_dll() -> str:
    """Locate AES_DLL.dll in known search paths."""
    here = Path(__file__).resolve().parent.parent
    candidates = [
        here / "AES_DLL.dll",
        here / ".venv" / "Lib" / "site-packages" / "aesdll" / "AES_DLL.dll",
        Path(sys.prefix) / "aesdll" / "AES_DLL.dll",
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    raise FileNotFoundError(
        f"AES_DLL.dll not found. Searched: {[str(c) for c in candidates]}"
    )


class AesDllError(RuntimeError):
    """Raised when a DLL operation fails."""


class AesDllAdapter:
    """Singleton-style adapter for AES_DLL.dll."""

    def __init__(self):
        self._dll = None
        self._loaded = False

    def load(self) -> bool:
        """Load the DLL and configure ctypes signatures."""
        if self._loaded:
            return True
        try:
            dll_path = _find_dll()
            self._dll = ctypes.WinDLL(dll_path)

            # ---------- configure signatures (7 core exports) ----------
            self._dll.GetMacAddress.argtypes = []
            self._dll.GetMacAddress.restype = ctypes.c_void_p

            self._dll.GenerateKeyFromMachine.argtypes = [
                ctypes.POINTER(ctypes.c_uint8 * 32)
            ]
            self._dll.GenerateKeyFromMachine.restype = ctypes.c_int

            self._dll.GenerateKeyFromHardware.argtypes = [
                ctypes.POINTER(ctypes.c_uint8 * 32)
            ]
            self._dll.GenerateKeyFromHardware.restype = ctypes.c_int

            self._dll.EncryptString.argtypes = [
                ctypes.c_char_p,
                ctypes.POINTER(ctypes.c_uint8 * 32),
            ]
            self._dll.EncryptString.restype = ctypes.c_void_p

            self._dll.DecryptString.argtypes = [
                ctypes.c_char_p,
                ctypes.POINTER(ctypes.c_uint8 * 32),
            ]
            self._dll.DecryptString.restype = ctypes.c_void_p

            self._dll.FreeString.argtypes = [ctypes.c_void_p]
            self._dll.FreeString.restype = None

            self._dll.AES_EncryptFile.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_uint8 * 32),
            ]
            self._dll.AES_EncryptFile.restype = ctypes.c_int

            self._dll.AES_DecryptFile.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_uint8 * 32),
            ]
            self._dll.AES_DecryptFile.restype = ctypes.c_int

            self._dll.EncryptKeyWithPassword.argtypes = [
                ctypes.POINTER(ctypes.c_uint8 * 32),
                ctypes.c_char_p,
                ctypes.POINTER(ctypes.c_uint8 * 64),
            ]
            self._dll.EncryptKeyWithPassword.restype = ctypes.c_int

            self._dll.DecryptKeyWithPassword.argtypes = [
                ctypes.POINTER(ctypes.c_uint8 * 64),
                ctypes.c_char_p,
                ctypes.POINTER(ctypes.c_uint8 * 32),
            ]
            self._dll.DecryptKeyWithPassword.restype = ctypes.c_int

            self._loaded = True
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    # ── public API ──────────────────────────────────────────

    def get_mac_address(self) -> str:
        self._ensure_loaded()
        ptr = self._dll.GetMacAddress()
        if not ptr:
            raise AesDllError("GetMacAddress returned NULL")
        result = ctypes.cast(ptr, ctypes.c_char_p).value.decode()
        self._dll.FreeString(ptr)
        return result

    def generate_key_from_machine(self) -> bytes:
        self._ensure_loaded()
        buf = (ctypes.c_uint8 * 32)()
        if self._dll.GenerateKeyFromMachine(buf) != 0:
            raise AesDllError("GenerateKeyFromMachine failed")
        return bytes(buf)

    def generate_key_from_hardware(self) -> bytes:
        self._ensure_loaded()
        buf = (ctypes.c_uint8 * 32)()
        if self._dll.GenerateKeyFromHardware(buf) != 0:
            raise AesDllError("GenerateKeyFromHardware failed")
        return bytes(buf)

    def encrypt_string(self, text: str, key: bytes) -> str:
        self._ensure_loaded()
        key_arr = (ctypes.c_uint8 * 32)(*key)
        ptr = self._dll.EncryptString(text.encode("utf-8"), key_arr)
        if not ptr:
            raise AesDllError("EncryptString returned NULL")
        result = ctypes.cast(ptr, ctypes.c_char_p).value.decode()
        self._dll.FreeString(ptr)
        return result

    def decrypt_string(self, hex_cipher: str, key: bytes) -> str:
        self._ensure_loaded()
        key_arr = (ctypes.c_uint8 * 32)(*key)
        ptr = self._dll.DecryptString(hex_cipher.encode(), key_arr)
        if not ptr:
            raise AesDllError("DecryptString returned NULL")
        result = ctypes.cast(ptr, ctypes.c_char_p).value.decode()
        self._dll.FreeString(ptr)
        return result

    def encrypt_file(self, in_path: str, out_path: str, key: bytes) -> bool:
        self._ensure_loaded()
        key_arr = (ctypes.c_uint8 * 32)(*key)
        return self._dll.AES_EncryptFile(in_path, out_path, key_arr) == 0

    def decrypt_file(self, in_path: str, out_path: str, key: bytes) -> bool:
        self._ensure_loaded()
        key_arr = (ctypes.c_uint8 * 32)(*key)
        return self._dll.AES_DecryptFile(in_path, out_path, key_arr) == 0

    def encrypt_key_with_password(self, key: bytes, password: str) -> bytes:
        self._ensure_loaded()
        key_arr = (ctypes.c_uint8 * 32)(*key)
        out_buf = (ctypes.c_uint8 * 64)()
        if self._dll.EncryptKeyWithPassword(key_arr, password.encode(), out_buf) != 0:
            raise AesDllError("EncryptKeyWithPassword failed")
        return bytes(out_buf)

    def decrypt_key_with_password(self, enc_key: bytes, password: str) -> bytes:
        self._ensure_loaded()
        enc_arr = (ctypes.c_uint8 * 64)(*enc_key)
        out_buf = (ctypes.c_uint8 * 32)()
        if self._dll.DecryptKeyWithPassword(enc_arr, password.encode(), out_buf) != 0:
            raise AesDllError("DecryptKeyWithPassword failed — wrong password?")
        return bytes(out_buf)

    def _ensure_loaded(self):
        if not self._loaded or not self._dll:
            raise AesDllError("DLL not loaded — call load() first")


# module-level convenience singleton
_adapter: Optional[AesDllAdapter] = None


def get_adapter() -> AesDllAdapter:
    global _adapter
    if _adapter is None:
        _adapter = AesDllAdapter()
        _adapter.load()
    return _adapter
