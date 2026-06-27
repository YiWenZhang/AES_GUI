# -*- coding: utf-8 -*-
"""
MainWindow — left-sidebar navigation + QStackedWidget page flow.
"""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QStackedWidget, QListWidget, QListWidgetItem,
    QStatusBar, QLabel, QFrame, QMessageBox,
)
from PySide6.QtGui import QAction, QFont
from PySide6.QtCore import Qt, QSize, Signal

from .aes_adapter import AesDllAdapter, get_adapter
from .auth_manager import AuthManager
from .text_cipher import TextCipher
from .file_cipher import FileCipher

from .ui_register import RegisterPage
from .ui_login import LoginPage
from .ui_text import TextCipherPage
from .ui_file import FileCipherPage


# ── Global stylesheet ─────────────────────────────────────
STYLESHEET = """
/* ── 全局 ── */
QMainWindow {
    background-color: #f0f2f5;
}
QWidget {
    font-family: "Microsoft YaHei", "PingFang SC", "Segoe UI", sans-serif;
    font-size: 13px;
    color: #2c3e50;
}

/* ── 左侧导航 ── */
#navPanel {
    background-color: #2c3e50;
    min-width: 180px;
    max-width: 180px;
}
#navList {
    background-color: #2c3e50;
    border: none;
    outline: none;
    color: #bdc3c7;
    font-size: 13px;
    padding: 8px 0;
}
#navList::item {
    height: 44px;
    padding: 10px 20px;
    border-left: 3px solid transparent;
    color: #bdc3c7;
}
#navList::item:hover {
    background-color: #34495e;
    color: #ecf0f1;
}
#navList::item:selected {
    background-color: #34495e;
    border-left: 3px solid #3498db;
    color: #ecf0f1;
    font-weight: bold;
}
#navList::item:disabled {
    color: #7f8c8d;
    background-color: transparent;
}

/* ── Header ── */
#headerBar {
    background-color: #ffffff;
    border-bottom: 1px solid #dcdfe6;
    padding: 0 24px;
    min-height: 52px;
    max-height: 52px;
}
#headerTitle {
    font-size: 16px;
    font-weight: bold;
    color: #2c3e50;
}
#headerSub {
    font-size: 12px;
    color: #909399;
}

/* ── Card ── */
.card {
    background-color: #ffffff;
    border: 1px solid #e8eaed;
    border-radius: 8px;
    padding: 24px;
}

/* ── 按钮 ── */
QPushButton {
    border-radius: 4px;
    padding: 7px 20px;
    font-size: 13px;
}
QPushButton:hover {
    opacity: 0.9;
}
QPushButton#primaryBtn {
    background-color: #3498db;
    color: #ffffff;
    border: none;
    font-weight: bold;
}
QPushButton#primaryBtn:hover {
    background-color: #2980b9;
}
QPushButton#primaryBtn:pressed {
    background-color: #2471a3;
}
QPushButton#successBtn {
    background-color: #27ae60;
    color: #ffffff;
    border: none;
    font-weight: bold;
}
QPushButton#successBtn:hover {
    background-color: #219a52;
}
QPushButton#normalBtn {
    background-color: #ffffff;
    color: #2c3e50;
    border: 1px solid #dcdfe6;
}
QPushButton#normalBtn:hover {
    border-color: #3498db;
    color: #3498db;
}
QPushButton#dangerBtn {
    background-color: #e74c3c;
    color: #ffffff;
    border: none;
}
QPushButton#dangerBtn:hover {
    background-color: #c0392b;
}

/* ── 输入框 ── */
QLineEdit, QTextEdit, QPlainTextEdit {
    border: 1px solid #dcdfe6;
    border-radius: 4px;
    padding: 6px 10px;
    background-color: #ffffff;
    selection-background-color: #3498db;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #3498db;
}
QLineEdit:read-only {
    background-color: #f5f7fa;
}

/* ── GroupBox ── */
QGroupBox {
    font-weight: bold;
    border: 1px solid #e8eaed;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 16px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: #2c3e50;
}

/* ── 进度条 ── */
QProgressBar {
    border: none;
    border-radius: 4px;
    text-align: center;
    background-color: #e8eaed;
    height: 6px;
}
QProgressBar::chunk {
    background-color: #3498db;
    border-radius: 4px;
}

/* ── 状态栏 ── */
QStatusBar {
    background-color: #2c3e50;
    color: #bdc3c7;
    font-size: 12px;
    min-height: 28px;
    padding: 0 12px;
}
QStatusBar::item {
    border: none;
}

/* ── 分割线 ── */
#separator {
    color: #e8eaed;
}
"""


NAV_ITEMS = [
    ("🔑  软件注册", "验证硬件注册码"),
    ("👤  用户登录", "登录或创建账号"),
    ("📝  文本加解密", "加密 / 解密文本内容"),
    ("📁  文件加解密", "加密 / 解密任意文件"),
]


class MainWindow(QMainWindow):
    page_changed = Signal(int)

    def __init__(self):
        super().__init__()
        self._adapter: AesDllAdapter = get_adapter()
        self._auth = AuthManager(self._adapter)
        self._text_cipher = TextCipher(self._adapter)
        self._file_cipher = FileCipher(self._adapter)

        self._key: bytes | None = None
        self._logged_in_user: str | None = None

        self._init_ui()
        self._apply_theme()
        self._update_nav()

        if self._adapter.is_loaded:
            self._auto_init_dll()

    # ── UI ─────────────────────────────────────────────────

    def _init_ui(self):
        self.setWindowTitle("AES 加密工具")
        self.resize(1000, 660)
        self.setMinimumSize(860, 540)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ──
        header = QFrame()
        header.setObjectName("headerBar")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 0, 20, 0)

        title_grp = QVBoxLayout()
        self._header_title = QLabel("AES 加密工具")
        self._header_title.setObjectName("headerTitle")
        self._header_sub = QLabel("加密动态链接库设计与应用")
        self._header_sub.setObjectName("headerSub")
        title_grp.addWidget(self._header_title)
        title_grp.addWidget(self._header_sub)
        hl.addLayout(title_grp)
        hl.addStretch()

        self._header_info = QLabel("")
        self._header_info.setStyleSheet(
            "font-size:12px; color:#909399; padding-right: 8px;")
        hl.addWidget(self._header_info)

        root.addWidget(header)

        # ── Body: sidebar + stack ──
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        # 左侧导航
        nav_panel = QFrame()
        nav_panel.setObjectName("navPanel")
        nav_layout = QVBoxLayout(nav_panel)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(0)

        self._nav_list = QListWidget()
        self._nav_list.setObjectName("navList")
        self._nav_list.setIconSize(QSize(18, 18))
        self._nav_list.setSpacing(2)
        for i, (label, tip) in enumerate(NAV_ITEMS):
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, i)
            item.setToolTip(tip)
            if i >= 1:
                item.setFlags(Qt.NoItemFlags)  # disabled initially
            self._nav_list.addItem(item)
        self._nav_list.setCurrentRow(0)
        self._nav_list.currentRowChanged.connect(self._on_nav_changed)
        nav_layout.addWidget(self._nav_list)
        nav_layout.addStretch()

        # 底部版本号
        ver = QLabel("v2.1")
        ver.setStyleSheet("color:#7f8c8d; font-size:11px; padding:12px 20px;")
        ver.setAlignment(Qt.AlignCenter)
        nav_layout.addWidget(ver)

        body.addWidget(nav_panel)

        # 右侧内容区
        self._stack = QStackedWidget()
        self._stack.setContentsMargins(0, 0, 0, 0)

        self._register_page = RegisterPage(
            self._adapter, self._auth,
            on_registered=self._on_software_registered,
        )
        self._login_page = LoginPage(
            self._adapter, self._auth, self._get_key_fn,
            on_login_success=self._on_user_logged_in,
            on_logout=self._on_user_logged_out,
        )
        self._text_page = TextCipherPage(self._text_cipher, self._get_key_fn)
        self._file_page = FileCipherPage(self._file_cipher, self._get_key_fn)

        self._stack.addWidget(self._register_page)
        self._stack.addWidget(self._login_page)
        self._stack.addWidget(self._text_page)
        self._stack.addWidget(self._file_page)

        body.addWidget(self._stack, 1)
        root.addLayout(body, 1)

        # ── Status bar ──
        self._status = QStatusBar()
        self._status_bar_widgets = {
            "dll": QLabel("DLL: —"),
            "key": QLabel("密钥: —"),
            "reg": QLabel("注册: —"),
            "user": QLabel("用户: 未登录"),
        }
        for w in self._status_bar_widgets.values():
            self._status.addPermanentWidget(w)
        self.setStatusBar(self._status)
        self._refresh_status_bar()

    def _apply_theme(self):
        self.setStyleSheet(STYLESHEET)

    # ── Navigation ─────────────────────────────────────────

    def _on_nav_changed(self, row: int):
        """Check access permission before switching page."""
        if row < 0:
            return
        if not self._can_access(row):
            QMessageBox.warning(
                self, "访问受限",
                "当前无权限访问该页面。\n请先完成前序步骤后再试。"
            )
            current = self._stack.currentIndex()
            self._nav_list.blockSignals(True)
            self._nav_list.setCurrentRow(current)
            self._nav_list.blockSignals(False)
            return
        self._stack.setCurrentIndex(row)
        if row == 2:
            self._text_page.refresh_key_display()
        elif row == 3:
            self._file_page.refresh_key_display()

    def _can_access(self, page: int) -> bool:
        if page == 0:
            return True  # register always accessible
        if page == 1:
            return self._auth.is_registered()
        if page in (2, 3):
            return self._auth.is_registered() and self._logged_in_user is not None
        return False

    def _update_nav(self):
        """Enable/disable nav items based on current state."""
        registered = self._auth.is_registered()
        logged_in = self._logged_in_user is not None

        for row in range(self._nav_list.count()):
            item = self._nav_list.item(row)
            if row == 0:
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                continue
            if row == 1:
                ok = registered
            else:
                ok = registered and logged_in

            if ok:
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                item.setText(NAV_ITEMS[row][0])  # remove lock prefix
            else:
                item.setFlags(Qt.NoItemFlags)
                name = NAV_ITEMS[row][0].replace("  ", " 🔒 ")
                item.setText(name)

    def _swipe_to(self, page: int):
        """Programmatically switch to a page."""
        if not self._can_access(page):
            return
        self._nav_list.setCurrentRow(page)
        self._stack.setCurrentIndex(page)

    # ── DLL / Key auto-init ────────────────────────────────

    def _auto_init_dll(self):
        try:
            self._key = self._adapter.generate_key_from_hardware()
            self._header_info.setText("加密引擎已就绪")
        except Exception:
            self._header_info.setText("DLL 已加载，密钥待生成")

    def _on_generate_key(self):
        if not self._adapter.is_loaded:
            QMessageBox.warning(self, "错误", "请先加载 DLL")
            return
        try:
            self._key = self._adapter.generate_key_from_hardware()
            QMessageBox.information(self, "密钥生成", f"密钥 (hex):\n{self._key.hex()}")
        except Exception as e:
            QMessageBox.warning(self, "密钥生成失败", str(e))
        self._refresh_status_bar()

    # ── Callbacks ──────────────────────────────────────────

    def _on_software_registered(self):
        self._update_nav()
        self._refresh_status_bar()
        QMessageBox.information(
            self, "注册成功",
            "软件已成功激活！\n现在您可以登录或创建用户账号。"
        )
        self._swipe_to(1)  # → login page

    def _on_user_logged_in(self, username: str):
        self._logged_in_user = username
        self._header_info.setText(f"登录用户: {username}")
        self._update_nav()
        self._refresh_status_bar()
        self._swipe_to(2)  # → text cipher page

    def _on_user_logged_out(self):
        self._logged_in_user = None
        self._header_info.setText("")
        self._update_nav()
        self._refresh_status_bar()
        self._swipe_to(1)  # → login page

    def _get_key_fn(self) -> bytes | None:
        return self._key

    def _refresh_status_bar(self):
        dll_txt = "✓ 已加载" if self._adapter.is_loaded else "✗ 未加载"
        key_txt = "已生成" if self._key else "—"
        reg_txt = "已激活" if self._auth.is_registered() else "未激活"
        user_txt = self._logged_in_user or "未登录"

        self._status_bar_widgets["dll"].setText(f"DLL: {dll_txt}")
        self._status_bar_widgets["key"].setText(f"密钥: {key_txt}")
        self._status_bar_widgets["reg"].setText(f"注册: {reg_txt}")
        self._status_bar_widgets["user"].setText(f"用户: {user_txt}")
