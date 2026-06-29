# -*- coding: utf-8 -*-
"""
RememberLoginStore — current-user DPAPI protected login token storage.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any


TOKEN_VERSION = 1
APP_PURPOSE = "AES_GUI_REMEMBER_LOGIN"


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class RememberLoginStore:
    def __init__(self, token_path: Path | None = None):
        self._token_path = token_path or self._default_token_path()

    def save(self, username: str, machine_binding: str) -> bool:
        if not username or not machine_binding:
            return False
        payload = {
            "version": TOKEN_VERSION,
            "username": username,
            "issued_at": int(time.time()),
            "machine_hash": self._machine_hash(machine_binding),
        }
        payload["signature"] = self._signature(payload, machine_binding)
        try:
            data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            protected = self._protect(data)
            self._token_path.parent.mkdir(parents=True, exist_ok=True)
            self._token_path.write_bytes(protected)
            return True
        except Exception:
            return False

    def load(self, machine_binding: str) -> str | None:
        if not machine_binding or not self._token_path.exists():
            return None
        try:
            data = self._unprotect(self._token_path.read_bytes())
            payload = json.loads(data.decode("utf-8"))
            if not self._is_valid_payload(payload, machine_binding):
                return None
            return str(payload["username"])
        except Exception:
            return None

    def clear(self) -> None:
        try:
            self._token_path.unlink(missing_ok=True)
        except Exception:
            pass

    def has_token(self) -> bool:
        return self._token_path.exists()

    @staticmethod
    def _default_token_path() -> Path:
        base = os.getenv("APPDATA")
        if base:
            return Path(base) / "AES_Tool" / "remember_login.dat"
        return Path.home() / ".AES_Tool" / "remember_login.dat"

    def _is_valid_payload(self, payload: Any, machine_binding: str) -> bool:
        if not isinstance(payload, dict):
            return False
        if payload.get("version") != TOKEN_VERSION:
            return False
        username = payload.get("username")
        issued_at = payload.get("issued_at")
        machine_hash = payload.get("machine_hash")
        signature = payload.get("signature")
        if not isinstance(username, str) or not username:
            return False
        if not isinstance(issued_at, int):
            return False
        if machine_hash != self._machine_hash(machine_binding):
            return False
        expected = self._signature(payload, machine_binding)
        return isinstance(signature, str) and hmac.compare_digest(signature, expected)

    @staticmethod
    def _machine_hash(machine_binding: str) -> str:
        return hashlib.sha256(machine_binding.encode("utf-8")).hexdigest()

    def _signature(self, payload: dict[str, Any], machine_binding: str) -> str:
        message = f"{payload.get('version')}|{payload.get('username')}|{payload.get('issued_at')}|{payload.get('machine_hash')}"
        secret = hashlib.sha256(f"{APP_PURPOSE}|{machine_binding}".encode("utf-8")).digest()
        return hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _blob_from_bytes(data: bytes) -> tuple[DATA_BLOB, ctypes.Array]:
        buffer = ctypes.create_string_buffer(data)
        blob = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
        return blob, buffer

    def _protect(self, data: bytes) -> bytes:
        in_blob, in_buffer = self._blob_from_bytes(data)
        out_blob = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(out_blob),
        ):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
            _ = in_buffer

    def _unprotect(self, data: bytes) -> bytes:
        in_blob, in_buffer = self._blob_from_bytes(data)
        out_blob = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(out_blob),
        ):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
            _ = in_buffer
