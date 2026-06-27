# -*- coding: utf-8 -*-
"""
MainWindow — PySide6 QMainWindow with four tab modules.
"""

from PySide6.QtWidgets import (
    QMainWindow, QTabWidget, QStatusBar, QMenuBar, QMenu,
    QMessageBox, QWidget, QVBoxLayout, QToolBar,
)
from PySide6.QtGui import QAction
from PySide6.QtCore import Qt, QSize

from .aes_adapter import AesDllAdapter, get_adapter
from .auth_manager import AuthManager
from .text_cipher import TextCipher
from .file_cipher import FileCipher

from .ui_register import RegisterTab
from .ui_login import LoginTab
from .ui_text import TextCipherTab
from .ui_file import FileCipherTab


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self._adapter: AesDllAdapter = get_adapter()
        self._auth = AuthManager(self._adapter)
        self._text_cipher = TextCipher(self._adapter)
        self._file_cipher = FileCipher(self._adapter)

        self._key: bytes | None = None
        self._logged_in_user: str | None = None

        self._init_ui()

    # ── UI setup ────────────────────────────────────────────

    def _init_ui(self):
        self.setWindowTitle("AES 加密工具 — 加密动态链接库应用系统")
        self.resize(1060, 700)
        self.setMinimumSize(900, 600)

        self._init_menu_bar()
        self._init_toolbar()
        self._init_central_tabs()
        self._init_status_bar()

        if self._adapter.is_loaded:
            self._on_dll_loaded()
        else:
            self._log_status("DLL 未加载 — 请检查 AES_DLL.dll 文件")

    def _init_menu_bar(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("文件(&F)")
        load_dll_action = QAction("加载 DLL", self)
        load_dll_action.triggered.connect(self._on_load_dll)
        file_menu.addAction(load_dll_action)
        file_menu.addSeparator()
        exit_action = QAction("退出(&X)", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        tools_menu = menubar.addMenu("工具(&T)")
        gen_key_action = QAction("生成密钥 (硬件)", self)
        gen_key_action.triggered.connect(self._on_generate_key)
        tools_menu.addAction(gen_key_action)

        help_menu = menubar.addMenu("帮助(&H)")
        about_action = QAction("关于", self)
        about_action.triggered.connect(self._on_about)
        help_menu.addAction(about_action)

    def _init_toolbar(self):
        toolbar = self.addToolBar("主工具栏")
        toolbar.setIconSize(QSize(16, 16))
        toolbar.setToolButtonStyle(Qt.ToolButtonTextOnly)

        act_load = QAction("加载DLL", self)
        act_load.triggered.connect(self._on_load_dll)
        toolbar.addAction(act_load)

        act_key = QAction("生成密钥", self)
        act_key.triggered.connect(self._on_generate_key)
        toolbar.addAction(act_key)

        toolbar.addSeparator()

        act_enc = QAction("文本加解密", self)
        act_enc.triggered.connect(lambda: self._tabs.setCurrentIndex(2))
        toolbar.addAction(act_enc)

        act_encf = QAction("文件加解密", self)
        act_encf.triggered.connect(lambda: self._tabs.setCurrentIndex(3))
        toolbar.addAction(act_encf)

    def _init_central_tabs(self):
        self._tabs = QTabWidget()
        self.setCentralWidget(self._tabs)

        self._register_tab = RegisterTab(self._adapter, self._auth)
        self._login_tab = LoginTab(
            self._adapter, self._auth, self._get_key,
            on_login_success=self._on_login_success,
            on_logout=self._on_logout,
        )
        self._text_tab = TextCipherTab(self._text_cipher, self._get_key)
        self._file_tab = FileCipherTab(self._file_cipher, self._get_key)

        self._tabs.addTab(self._register_tab, "🔑 软件注册")
        self._tabs.addTab(self._login_tab, "👤 用户登录")
        self._tabs.addTab(self._text_tab, "📝 文本加解密")
        self._tabs.addTab(self._file_tab, "📁 文件加解密")

        self._tabs.currentChanged.connect(self._on_tab_changed)

    def _init_status_bar(self):
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._update_status_bar()

    # ── event handlers ──────────────────────────────────────

    def _on_load_dll(self):
        ok = self._adapter.load()
        if ok:
            self._on_dll_loaded()
            QMessageBox.information(self, "DLL 加载", "AES_DLL.dll 加载成功！")
        else:
            QMessageBox.warning(self, "DLL 加载失败",
                                "未找到 AES_DLL.dll，请将其放置到程序目录。")
        self._update_status_bar()

    def _on_dll_loaded(self):
        self._log_status("DLL 已加载 — AES-256-CBC 加密引擎就绪")
        if self._key is None:
            try:
                self._key = self._adapter.generate_key_from_hardware()
                self._log_status("密钥已从硬件特征生成 (AES-256, 32 字节)")
            except Exception:
                self._log_status("密钥生成失败，请手动点击'生成密钥'")

    def _on_generate_key(self):
        if not self._adapter.is_loaded:
            QMessageBox.warning(self, "错误", "请先加载 DLL")
            return
        try:
            self._key = self._adapter.generate_key_from_hardware()
            self._log_status("密钥已重新生成 (多源硬件特征 + SHA-256)")
            QMessageBox.information(self, "密钥生成", f"密钥 (hex): {self._key.hex()}")
        except Exception as e:
            QMessageBox.warning(self, "密钥生成失败", str(e))
        self._update_status_bar()

    def _on_about(self):
        QMessageBox.about(
            self,
            "关于 AES 加密工具",
            "AES 加密工具 v2.0\n\n"
            "加密动态链接库设计与应用 — 实训项目\n"
            "技术栈: C++20 AES-256-CBC DLL + Python PySide6 GUI\n"
            "开发者: 张译文\n"
            "仓库: https://github.com/YiWenZhang/AES_DLL",
        )

    def _on_tab_changed(self, index: int):
        names = ["软件注册", "用户登录", "文本加解密", "文件加解密"]
        self._log_status(f"已切换到: {names[index]}")
        # refresh key display when switching to text or file tab
        if index == 2:
            self._text_tab.refresh_key_display()
        elif index == 3:
            self._file_tab.refresh_key_display()
        self._update_status_bar()

    def _on_login_success(self, username: str):
        self._logged_in_user = username
        self._update_status_bar()

    def _on_logout(self):
        self._logged_in_user = None
        self._update_status_bar()

    # ── key accessor (pass to tabs) ─────────────────────────

    def _get_key(self) -> bytes | None:
        return self._key

    # ── helpers ─────────────────────────────────────────────

    def _log_status(self, msg: str):
        self._status.showMessage(msg)

    def _update_status_bar(self):
        dll_text = "✓ 已加载" if self._adapter.is_loaded else "✗ 未加载"
        key_text = "已生成" if self._key else "—"
        reg_text = "已注册" if self._auth.is_registered() else "未注册"
        parts = [f"DLL: {dll_text}", f"密钥: {key_text}", f"注册: {reg_text}"]
        if self._logged_in_user:
            parts.append(f"当前用户: {self._logged_in_user}")
        self._log_status("  |  ".join(parts))
