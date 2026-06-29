# -*- coding: utf-8 -*-
"""
Admin registry helper — elevated HKLM writes for activation and user registration.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.aes_adapter import AesDllAdapter
    from src.auth_manager import AuthManager
else:
    from .aes_adapter import AesDllAdapter
    from .auth_manager import AuthManager


EXIT_OK = 0
EXIT_INVALID_CODE = 2
EXIT_WRITE_FAILED = 3
EXIT_DLL_FAILED = 4
EXIT_INVALID_ARGS = 5
EXIT_UNEXPECTED = 10

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_一-鿿-]{3,20}$")
_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _build_auth() -> AuthManager | None:
    adapter = AesDllAdapter()
    if not adapter.load():
        return None
    return AuthManager(adapter)


def _activate(code: str) -> int:
    auth = _build_auth()
    if auth is None:
        return EXIT_DLL_FAILED
    if not auth.validate_registration(code):
        return EXIT_INVALID_CODE
    if not auth.register(code):
        return EXIT_WRITE_FAILED
    return EXIT_OK


def _create_user(username: str, encrypted_password: str) -> int:
    if not _USERNAME_RE.match(username):
        return EXIT_INVALID_ARGS
    if not encrypted_password or not _HEX_RE.match(encrypted_password):
        return EXIT_INVALID_ARGS

    auth = _build_auth()
    if auth is None:
        return EXIT_DLL_FAILED
    if not auth._write_value(f"User_{username}", encrypted_password):
        return EXIT_WRITE_FAILED
    return EXIT_OK


def _factory_reset() -> int:
    auth = _build_auth()
    if auth is None:
        return EXIT_DLL_FAILED
    if not auth.factory_reset():
        return EXIT_WRITE_FAILED
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AES GUI admin registry helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    activate = subparsers.add_parser("activate")
    activate.add_argument("--code", required=True)

    create_user = subparsers.add_parser("create-user")
    create_user.add_argument("--username", required=True)
    create_user.add_argument("--encrypted-password", required=True)

    subparsers.add_parser("factory-reset")

    try:
        args = parser.parse_args(argv)
        if args.command == "activate":
            return _activate(args.code.strip())
        if args.command == "create-user":
            return _create_user(args.username.strip(), args.encrypted_password.strip())
        if args.command == "factory-reset":
            return _factory_reset()
        return EXIT_INVALID_ARGS
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_INVALID_ARGS
    except Exception:
        return EXIT_UNEXPECTED


if __name__ == "__main__":
    sys.exit(main())
