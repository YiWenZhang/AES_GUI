# -*- coding: utf-8 -*-
"""
LoginTab — user registration & login UI.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLineEdit, QPushButton, QLabel, QMessageBox,
)
from PySide6.QtCore import Qt
from typing import Callable

from .aes_adapter import AesDllAdapter
from .auth_manager import AuthManager


class LoginTab(QWidget):
    def __init__(
        self,
        adapter: AesDllAdapter,
        auth: AuthManager,
        key_getter: Callable[[], bytes | None],
        on_login_success: Callable[[str], None] = None,
        on_logout: Callable[[], None] = None,
    ):
        super().__init__()
        self._adapter = adapter
        self._auth = auth
        self._get_key = key_getter
        self._on_login_success = on_login_success
        self._on_logout = on_logout
        self._logged_in_user: str | None = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        # ── Current session status ──
        self._session_label = QLabel("当前未登录")
        self._session_label.setStyleSheet("font-size: 13px; color: gray; padding: 4px;")
        layout.addWidget(self._session_label)

        # ── Login group ──
        grp_login = QGroupBox("用户登录")
        login_layout = QVBoxLayout(grp_login)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("用户名:"))
        self._login_user = QLineEdit()
        self._login_user.setPlaceholderText("请输入用户名")
        self._login_user.setFixedWidth(240)
        row1.addWidget(self._login_user)
        row1.addStretch()
        login_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("密  码:"))
        self._login_pwd = QLineEdit()
        self._login_pwd.setPlaceholderText("请输入密码")
        self._login_pwd.setEchoMode(QLineEdit.Password)
        self._login_pwd.setFixedWidth(240)
        row2.addWidget(self._login_pwd)
        row2.addStretch()
        login_layout.addLayout(row2)

        row3 = QHBoxLayout()
        btn_login = QPushButton("登录")
        btn_login.clicked.connect(self._on_login)
        btn_login.setDefault(True)
        row3.addWidget(btn_login)

        self._btn_logout = QPushButton("退出登录")
        self._btn_logout.clicked.connect(self._on_logout_clicked)
        self._btn_logout.setEnabled(False)
        row3.addWidget(self._btn_logout)

        row3.addStretch()
        login_layout.addLayout(row3)

        self._login_status = QLabel()
        login_layout.addWidget(self._login_status)

        layout.addWidget(grp_login)

        # ── Register group ──
        grp_reg = QGroupBox("注册新用户")
        reg_layout = QVBoxLayout(grp_reg)

        row4 = QHBoxLayout()
        row4.addWidget(QLabel("用户名:"))
        self._reg_user = QLineEdit()
        self._reg_user.setPlaceholderText("请设置用户名 (3-20 字符)")
        self._reg_user.setFixedWidth(240)
        row4.addWidget(self._reg_user)
        row4.addStretch()
        reg_layout.addLayout(row4)

        row5 = QHBoxLayout()
        row5.addWidget(QLabel("密  码:"))
        self._reg_pwd = QLineEdit()
        self._reg_pwd.setPlaceholderText("请设置密码 (至少4位)")
        self._reg_pwd.setEchoMode(QLineEdit.Password)
        self._reg_pwd.setFixedWidth(240)
        row5.addWidget(self._reg_pwd)
        row5.addStretch()
        reg_layout.addLayout(row5)

        row6 = QHBoxLayout()
        row6.addWidget(QLabel("确认密码:"))
        self._reg_pwd2 = QLineEdit()
        self._reg_pwd2.setPlaceholderText("请再次输入密码")
        self._reg_pwd2.setEchoMode(QLineEdit.Password)
        self._reg_pwd2.setFixedWidth(240)
        row6.addWidget(self._reg_pwd2)
        row6.addStretch()
        reg_layout.addLayout(row6)

        row7 = QHBoxLayout()
        btn_register = QPushButton("注册")
        btn_register.clicked.connect(self._on_register)
        row7.addWidget(btn_register)
        row7.addStretch()
        reg_layout.addLayout(row7)

        self._reg_status = QLabel()
        reg_layout.addWidget(self._reg_status)

        layout.addWidget(grp_reg)

        layout.addStretch()

    # ── login ────────────────────────────────────────────────

    def _on_login(self):
        key = self._get_key()
        if key is None:
            self._login_status.setText("⚠ 请先生成密钥（在工具栏点击'生成密钥'）")
            self._login_status.setStyleSheet("color: orange;")
            return

        username = self._login_user.text().strip()
        password = self._login_pwd.text()
        if not username or not password:
            self._login_status.setText("⚠ 请输入用户名和密码")
            self._login_status.setStyleSheet("color: orange;")
            return

        try:
            if self._auth.login(username, password, key):
                self._logged_in_user = username
                self._login_status.setText(f"✓ 登录成功 — 欢迎回来, {username}!")
                self._login_status.setStyleSheet("color: green; font-weight: bold;")
                self._update_session_label()
                self._btn_logout.setEnabled(True)
                if self._on_login_success:
                    self._on_login_success(username)
            else:
                self._login_status.setText("✗ 用户名或密码错误，或用户不存在")
                self._login_status.setStyleSheet("color: red;")
        except Exception as e:
            self._login_status.setText(f"✗ 登录失败: {e}")
            self._login_status.setStyleSheet("color: red;")

    def _on_logout_clicked(self):
        self._logged_in_user = None
        self._btn_logout.setEnabled(False)
        self._update_session_label()
        self._login_status.setText("已退出登录")
        self._login_status.setStyleSheet("color: gray;")
        self._login_user.clear()
        self._login_pwd.clear()
        if self._on_logout:
            self._on_logout()

    # ── register ─────────────────────────────────────────────

    def _on_register(self):
        key = self._get_key()
        if key is None:
            self._reg_status.setText("⚠ 请先生成密钥")
            self._reg_status.setStyleSheet("color: orange;")
            return

        username = self._reg_user.text().strip()
        pwd1 = self._reg_pwd.text()
        pwd2 = self._reg_pwd2.text()

        if not username:
            self._reg_status.setText("⚠ 请输入用户名")
            self._reg_status.setStyleSheet("color: orange;")
            return
        if len(username) < 3 or len(username) > 20:
            self._reg_status.setText("⚠ 用户名长度需在 3-20 字符之间")
            self._reg_status.setStyleSheet("color: orange;")
            return
        if not pwd1:
            self._reg_status.setText("⚠ 请输入密码")
            self._reg_status.setStyleSheet("color: orange;")
            return
        if len(pwd1) < 4:
            self._reg_status.setText("⚠ 密码至少需要 4 位")
            self._reg_status.setStyleSheet("color: orange;")
            return
        if pwd1 != pwd2:
            self._reg_status.setText("⚠ 两次输入的密码不一致")
            self._reg_status.setStyleSheet("color: orange;")
            return

        if self._auth.user_exists(username):
            self._reg_status.setText("⚠ 该用户名已被注册，请更换")
            self._reg_status.setStyleSheet("color: orange;")
            return

        try:
            if self._auth.register_user(username, pwd1, key):
                self._reg_status.setText(f"✓ 用户 '{username}' 注册成功！请切换到登录")
                self._reg_status.setStyleSheet("color: green; font-weight: bold;")
                QMessageBox.information(
                    self, "注册成功",
                    f"用户 '{username}' 注册成功！\n请切换到登录面板进行登录。"
                )
                self._reg_user.clear()
                self._reg_pwd.clear()
                self._reg_pwd2.clear()
            else:
                self._reg_status.setText("✗ 注册失败")
                self._reg_status.setStyleSheet("color: red;")
        except Exception as e:
            self._reg_status.setText(f"✗ 注册失败: {e}")
            self._reg_status.setStyleSheet("color: red;")

    # ── helpers ──────────────────────────────────────────────

    def _update_session_label(self):
        if self._logged_in_user:
            self._session_label.setText(f"当前登录用户: {self._logged_in_user}")
            self._session_label.setStyleSheet(
                "font-size: 13px; color: green; font-weight: bold; padding: 4px;"
            )
        else:
            self._session_label.setText("当前未登录")
            self._session_label.setStyleSheet(
                "font-size: 13px; color: gray; padding: 4px;"
            )
