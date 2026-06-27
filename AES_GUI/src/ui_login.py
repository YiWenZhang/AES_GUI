# -*- coding: utf-8 -*-
"""
LoginPage — login / register combined page with auto-redirect.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QLabel, QFrame, QStackedWidget,
    QMessageBox,
)
from PySide6.QtCore import Qt
from typing import Callable

from .aes_adapter import AesDllAdapter
from .auth_manager import AuthManager


class LoginPage(QWidget):
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
        outer = QVBoxLayout(self)
        outer.setContentsMargins(32, 28, 32, 28)
        outer.addStretch()

        card = QFrame()
        card.setProperty("class", "card")
        card.setMaximumWidth(440)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(40, 32, 40, 32)
        card_layout.setSpacing(16)

        # ── Session hint ──
        self._session_label = QLabel("当前状态: 未登录")
        self._session_label.setAlignment(Qt.AlignCenter)
        self._session_label.setStyleSheet("font-size:12px; color:#909399;")
        card_layout.addWidget(self._session_label)

        # ── Inner stack: login / register forms ──
        self._form_stack = QStackedWidget()

        # --- Login form ---
        login_widget = QWidget()
        login_form = QVBoxLayout(login_widget)
        login_form.setContentsMargins(0, 0, 0, 0)
        login_form.setSpacing(12)

        login_title = QLabel("用户登录")
        login_title.setAlignment(Qt.AlignCenter)
        login_title.setStyleSheet("font-size:20px; font-weight:bold; color:#2c3e50;")
        login_form.addWidget(login_title)

        login_form.addWidget(QLabel("用户名"))
        self._login_user = QLineEdit()
        self._login_user.setPlaceholderText("请输入用户名")
        login_form.addWidget(self._login_user)

        login_form.addWidget(QLabel("密码"))
        self._login_pwd = QLineEdit()
        self._login_pwd.setPlaceholderText("请输入密码")
        self._login_pwd.setEchoMode(QLineEdit.Password)
        login_form.addWidget(self._login_pwd)

        btn_login = QPushButton("登  录")
        btn_login.setObjectName("primaryBtn")
        btn_login.clicked.connect(self._on_login)
        btn_login.setDefault(True)
        login_form.addWidget(btn_login)

        self._login_status = QLabel("")
        login_form.addWidget(self._login_status)

        switch_reg = QPushButton("还没有账号？点击注册 →")
        switch_reg.setStyleSheet(
            "border:none; color:#3498db; font-size:12px; text-decoration:underline;"
        )
        switch_reg.setCursor(Qt.PointingHandCursor)
        switch_reg.clicked.connect(lambda: self._form_stack.setCurrentIndex(1))
        login_form.addWidget(switch_reg)

        login_form.addStretch()
        self._form_stack.addWidget(login_widget)

        # --- Register form ---
        reg_widget = QWidget()
        reg_form = QVBoxLayout(reg_widget)
        reg_form.setContentsMargins(0, 0, 0, 0)
        reg_form.setSpacing(12)

        reg_title = QLabel("注册新用户")
        reg_title.setAlignment(Qt.AlignCenter)
        reg_title.setStyleSheet("font-size:20px; font-weight:bold; color:#2c3e50;")
        reg_form.addWidget(reg_title)

        reg_form.addWidget(QLabel("用户名 (3-20 字符)"))
        self._reg_user = QLineEdit()
        self._reg_user.setPlaceholderText("请设置用户名")
        reg_form.addWidget(self._reg_user)

        reg_form.addWidget(QLabel("密码 (至少 4 位)"))
        self._reg_pwd = QLineEdit()
        self._reg_pwd.setPlaceholderText("请设置密码")
        self._reg_pwd.setEchoMode(QLineEdit.Password)
        reg_form.addWidget(self._reg_pwd)

        reg_form.addWidget(QLabel("确认密码"))
        self._reg_pwd2 = QLineEdit()
        self._reg_pwd2.setPlaceholderText("请再次输入密码")
        self._reg_pwd2.setEchoMode(QLineEdit.Password)
        reg_form.addWidget(self._reg_pwd2)

        btn_register = QPushButton("注  册")
        btn_register.setObjectName("successBtn")
        btn_register.clicked.connect(self._on_register)
        reg_form.addWidget(btn_register)

        self._reg_status = QLabel("")
        reg_form.addWidget(self._reg_status)

        switch_login = QPushButton("← 已有账号？返回登录")
        switch_login.setStyleSheet(
            "border:none; color:#3498db; font-size:12px; text-decoration:underline;"
        )
        switch_login.setCursor(Qt.PointingHandCursor)
        switch_login.clicked.connect(lambda: self._form_stack.setCurrentIndex(0))
        reg_form.addWidget(switch_login)

        reg_form.addStretch()
        self._form_stack.addWidget(reg_widget)

        card_layout.addWidget(self._form_stack)

        # ── Logout button (visible only when logged in) ──
        self._btn_logout = QPushButton("退出登录")
        self._btn_logout.setObjectName("dangerBtn")
        self._btn_logout.clicked.connect(self._on_logout_clicked)
        self._btn_logout.setVisible(False)
        card_layout.addWidget(self._btn_logout)

        hbox = QHBoxLayout()
        hbox.addStretch()
        hbox.addWidget(card)
        hbox.addStretch()
        outer.addLayout(hbox)
        outer.addStretch()

    # ── Login ──────────────────────────────────────────────

    def _on_login(self):
        key = self._get_key()
        if key is None:
            self._login_status.setText("⚠ 请先生成密钥")
            self._login_status.setStyleSheet("color: #e67e22;")
            return

        username = self._login_user.text().strip()
        password = self._login_pwd.text()
        if not username or not password:
            self._login_status.setText("⚠ 请输入用户名和密码")
            self._login_status.setStyleSheet("color: #e67e22;")
            return

        try:
            if self._auth.login(username, password, key):
                self._logged_in_user = username
                self._session_label.setText(f"当前用户: {username}")
                self._session_label.setStyleSheet(
                    "font-size:12px; color:#27ae60; font-weight:bold;")
                self._login_status.setText(f"✓ 登录成功 — 欢迎, {username}!")
                self._login_status.setStyleSheet("color: #27ae60; font-weight: bold;")
                self._btn_logout.setVisible(True)
                if self._on_login_success:
                    self._on_login_success(username)
            else:
                self._login_status.setText("✗ 用户名或密码错误，或用户不存在")
                self._login_status.setStyleSheet("color: #e74c3c;")
        except Exception as e:
            self._login_status.setText(f"✗ 登录失败: {e}")
            self._login_status.setStyleSheet("color: #e74c3c;")

    def _on_logout_clicked(self):
        self._logged_in_user = None
        self._session_label.setText("当前状态: 未登录")
        self._session_label.setStyleSheet("font-size:12px; color:#909399;")
        self._btn_logout.setVisible(False)
        self._login_user.clear()
        self._login_pwd.clear()
        self._login_status.clear()
        if self._on_logout:
            self._on_logout()

    # ── Register ───────────────────────────────────────────

    def _on_register(self):
        key = self._get_key()
        if key is None:
            self._reg_status.setText("⚠ 请先生成密钥")
            self._reg_status.setStyleSheet("color: #e67e22;")
            return

        username = self._reg_user.text().strip()
        pwd1 = self._reg_pwd.text()
        pwd2 = self._reg_pwd2.text()

        if not username:
            self._reg_status.setText("⚠ 请输入用户名")
            self._reg_status.setStyleSheet("color: #e67e22;")
            return
        if len(username) < 3 or len(username) > 20:
            self._reg_status.setText("⚠ 用户名长度需在 3-20 字符之间")
            self._reg_status.setStyleSheet("color: #e67e22;")
            return
        if not pwd1:
            self._reg_status.setText("⚠ 请输入密码")
            self._reg_status.setStyleSheet("color: #e67e22;")
            return
        if len(pwd1) < 4:
            self._reg_status.setText("⚠ 密码至少需要 4 位")
            self._reg_status.setStyleSheet("color: #e67e22;")
            return
        if pwd1 != pwd2:
            self._reg_status.setText("⚠ 两次输入的密码不一致")
            self._reg_status.setStyleSheet("color: #e67e22;")
            return
        if self._auth.user_exists(username):
            self._reg_status.setText("⚠ 该用户名已被注册，请更换")
            self._reg_status.setStyleSheet("color: #e67e22;")
            return

        try:
            if self._auth.register_user(username, pwd1, key):
                self._reg_status.setText(f"✓ 用户 '{username}' 注册成功！")
                self._reg_status.setStyleSheet("color: #27ae60; font-weight: bold;")
                QMessageBox.information(
                    self, "注册成功",
                    f"用户 '{username}' 注册成功！\n请切换到登录面板进行登录。"
                )
                self._form_stack.setCurrentIndex(0)
                self._login_user.setText(username)
                self._reg_user.clear()
                self._reg_pwd.clear()
                self._reg_pwd2.clear()
            else:
                self._reg_status.setText("✗ 注册失败")
                self._reg_status.setStyleSheet("color: #e74c3c;")
        except Exception as e:
            self._reg_status.setText(f"✗ 注册失败: {e}")
            self._reg_status.setStyleSheet("color: #e74c3c;")
