# -*- coding: utf-8 -*-
"""
AdminRegistryService — launches a narrow elevated helper for HKLM writes.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .admin_registry_helper import (
    EXIT_DLL_FAILED,
    EXIT_INVALID_ARGS,
    EXIT_INVALID_CODE,
    EXIT_OK,
    EXIT_UNEXPECTED,
    EXIT_WRITE_FAILED,
)
from .app_paths import PROJECT_ROOT
from .auth_manager import AuthManager


ERROR_CANCELLED = 1223
SEE_MASK_NOCLOSEPROCESS = 0x00000040
SW_SHOWNORMAL = 1
INFINITE = 0xFFFFFFFF


@dataclass
class AdminRegistryResult:
    success: bool
    message: str
    cancelled: bool = False
    invalid_code: bool = False
    write_failed: bool = False
    exit_code: int | None = None


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("fMask", ctypes.c_ulong),
        ("hwnd", ctypes.c_void_p),
        ("lpVerb", ctypes.c_wchar_p),
        ("lpFile", ctypes.c_wchar_p),
        ("lpParameters", ctypes.c_wchar_p),
        ("lpDirectory", ctypes.c_wchar_p),
        ("nShow", ctypes.c_int),
        ("hInstApp", ctypes.c_void_p),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", ctypes.c_wchar_p),
        ("hkeyClass", ctypes.c_void_p),
        ("dwHotKey", ctypes.c_ulong),
        ("hIcon", ctypes.c_void_p),
        ("hProcess", ctypes.c_void_p),
    ]


class AdminRegistryService:
    def __init__(self, auth: AuthManager):
        self._auth = auth

    def activate_with_admin(self, code: str) -> AdminRegistryResult:
        if not self._auth.validate_registration(code):
            return AdminRegistryResult(False, "注册码无效，请检查后重试", invalid_code=True, exit_code=EXIT_INVALID_CODE)

        result = self._run_helper(["activate", "--code", code])
        if not result.success:
            return result
        if not self._auth.is_registered():
            return AdminRegistryResult(False, "注册表写入后验证失败，请重试", write_failed=True, exit_code=result.exit_code)
        return AdminRegistryResult(True, "注册成功 — 软件已激活", exit_code=result.exit_code)

    def create_user_with_admin(self, username: str, encrypted_password: str) -> AdminRegistryResult:
        return self._run_helper([
            "create-user",
            "--username",
            username,
            "--encrypted-password",
            encrypted_password,
        ])

    def factory_reset_with_admin(self) -> AdminRegistryResult:
        return self._run_helper(["factory-reset"])

    def _run_helper(self, args: list[str]) -> AdminRegistryResult:
        try:
            exit_code = self._run_elevated(args)
        except OSError as exc:
            if getattr(exc, "winerror", None) == ERROR_CANCELLED:
                return AdminRegistryResult(False, "已取消管理员授权，操作未完成", cancelled=True)
            return AdminRegistryResult(False, f"管理员助手启动失败：{exc}")

        return self._result_from_exit_code(exit_code)

    def _run_elevated(self, args: list[str]) -> int:
        file, parameters, directory = self._helper_command(args)
        info = SHELLEXECUTEINFOW()
        info.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
        info.fMask = SEE_MASK_NOCLOSEPROCESS
        info.hwnd = None
        info.lpVerb = "runas"
        info.lpFile = file
        info.lpParameters = parameters
        info.lpDirectory = directory
        info.nShow = SW_SHOWNORMAL

        if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
            raise ctypes.WinError()

        ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, INFINITE)
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(info.hProcess)
        return int(code.value)

    def _helper_command(self, args: list[str]) -> tuple[str, str, str]:
        if getattr(sys, "frozen", False):
            app_dir = Path(sys.executable).resolve().parent
            candidates = [
                app_dir / "AES_Admin_Helper.exe",
                app_dir / "_internal" / "AES_Admin_Helper.exe",
            ]
            helper = next((path for path in candidates if path.exists()), candidates[0])
            return str(helper), subprocess.list2cmdline(args), str(helper.parent)

        params = subprocess.list2cmdline(["-m", "src.admin_registry_helper", *args])
        return sys.executable, params, str(PROJECT_ROOT)

    def _result_from_exit_code(self, exit_code: int) -> AdminRegistryResult:
        if exit_code == EXIT_OK:
            return AdminRegistryResult(True, "操作成功", exit_code=exit_code)
        if exit_code == EXIT_INVALID_CODE:
            return AdminRegistryResult(False, "注册码无效，请检查后重试", invalid_code=True, exit_code=exit_code)
        if exit_code == EXIT_WRITE_FAILED:
            return AdminRegistryResult(False, "管理员写入注册表失败，请确认权限或重试", write_failed=True, exit_code=exit_code)
        if exit_code == EXIT_DLL_FAILED:
            return AdminRegistryResult(False, "激活助手无法加载 AES DLL，请检查运行环境", exit_code=exit_code)
        if exit_code == EXIT_INVALID_ARGS:
            return AdminRegistryResult(False, "管理员助手参数无效", exit_code=exit_code)
        if exit_code == EXIT_UNEXPECTED:
            return AdminRegistryResult(False, "管理员助手运行异常", exit_code=exit_code)
        return AdminRegistryResult(False, f"管理员助手返回未知错误：{exit_code}", exit_code=exit_code)
