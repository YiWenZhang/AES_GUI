# -*- coding: utf-8 -*-
"""
LoginPage — login / register combined page with auto-redirect.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QLabel, QFrame, QStackedWidget,
    QMessageBox, QProgressBar, QCheckBox,
)
from PySide6.QtCore import Qt
from typing import Callable

from .aes_adapter import AesDllAdapter
from .auth_manager import AuthManager
from .audit_log import AuditLogger
from .password_strength import PasswordStrengthService
from .admin_registry_service import AdminRegistryService


class LoginPage(QWidget):
    SAVED_PASSWORD_PLACEHOLDER = "********"
    def __init__(
        self,
        adapter: AesDllAdapter,
        auth: AuthManager,
        admin_registry: AdminRegistryService,
        key_getter: Callable[[], bytes | None],
        on_login_success: Callable[[str], None] = None,
        on_logout: Callable[[], None] = None,
        password_strength: PasswordStrengthService | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        super().__init__()
        self._adapter = adapter
        self._auth = auth
        self._admin_registry = admin_registry
        self._get_key = key_getter
        self._on_login_success = on_login_success
        self._on_logout = on_logout
        self._password_strength = password_strength or PasswordStrengthService()
        self._audit_logger = audit_logger
        self._logged_in_user: str | None = None
        self._init_ui()
        self._restore_saved_login_hint()
        self._update_password_strength()

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
        login_form.addLayout(self._password_row(self._login_pwd))

        self._remember_login = QCheckBox("记住登录，下次可直接登录")
        self._remember_login.setStyleSheet("font-size:12px; color:#606266;")
        login_form.addWidget(self._remember_login)

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
        self._reg_user.textChanged.connect(self._update_password_strength)
        reg_form.addWidget(self._reg_user)

        reg_form.addWidget(QLabel("密码 (建议 8 位以上，包含大小写/数字/符号)"))
        self._reg_pwd = QLineEdit()
        self._reg_pwd.setPlaceholderText("请设置密码")
        self._reg_pwd.setEchoMode(QLineEdit.Password)
        self._reg_pwd.textChanged.connect(self._update_password_strength)
        reg_form.addLayout(self._password_row(self._reg_pwd))

        self._strength_bar = QProgressBar()
        self._strength_bar.setRange(0, 100)
        self._strength_bar.setTextVisible(True)
        reg_form.addWidget(self._strength_bar)

        self._strength_label = QLabel("")
        self._strength_label.setWordWrap(True)
        self._strength_label.setStyleSheet("font-size:11px; color:#909399;")
        reg_form.addWidget(self._strength_label)

        reg_form.addWidget(QLabel("确认密码"))
        self._reg_pwd2 = QLineEdit()
        self._reg_pwd2.setPlaceholderText("请再次输入密码")
        self._reg_pwd2.setEchoMode(QLineEdit.Password)
        reg_form.addLayout(self._password_row(self._reg_pwd2))

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

    def _password_row(self, edit: QLineEdit) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(6)
        row.addWidget(edit)
        btn_toggle = QPushButton("显示")
        btn_toggle.setObjectName("normalBtn")
        btn_toggle.setMinimumWidth(76)
        btn_toggle.setMaximumWidth(86)
        btn_toggle.setStyleSheet("padding: 6px 8px;")
        btn_toggle.setCheckable(True)
        btn_toggle.toggled.connect(lambda checked, field=edit, button=btn_toggle: self._toggle_password_visible(field, button, checked))
        row.addWidget(btn_toggle)
        return row

    def _toggle_password_visible(self, edit: QLineEdit, button: QPushButton, visible: bool):
        edit.setEchoMode(QLineEdit.Normal if visible else QLineEdit.Password)
        button.setText("隐藏" if visible else "显示")

    def _restore_saved_login_hint(self):
        saved_user = self._auth.get_saved_login_user()
        if not saved_user:
            return
        self._login_user.setText(saved_user)
        self._login_pwd.setText(self.SAVED_PASSWORD_PLACEHOLDER)
        self._remember_login.setChecked(True)
        self._login_status.setText("已保存登录，点击登录即可进入")
        self._login_status.setStyleSheet("color: #3498db;")

    def _complete_login(self, username: str, via_token: bool = False):
        self._logged_in_user = username
        self._session_label.setText(f"当前用户: {username}")
        self._session_label.setStyleSheet(
            "font-size:12px; color:#27ae60; font-weight:bold;")
        if via_token:
            self._login_status.setText(f"✓ 已通过保存登录进入 — 欢迎, {username}!")
            self._audit("用户登录", "成功", "通过保存登录 token 登录成功", username)
        else:
            self._login_status.setText(f"✓ 登录成功 — 欢迎, {username}!")
            self._audit("用户登录", "成功", "登录成功", username)
        self._login_status.setStyleSheet("color: #27ae60; font-weight: bold;")
        self._btn_logout.setVisible(True)
        if self._on_login_success:
            self._on_login_success(username)

    # ── Login ──────────────────────────────────────────────

    def _on_login(self):
        key = self._get_key()
        username = self._login_user.text().strip()
        password = self._login_pwd.text()
        if key is None:
            self._login_status.setText("⚠ 请先生成密钥")
            self._login_status.setStyleSheet("color: #e67e22;")
            self._audit("用户登录", "失败", "登录失败：密钥未生成", username)
            return

        if not username:
            self._login_status.setText("⚠ 请输入用户名")
            self._login_status.setStyleSheet("color: #e67e22;")
            self._audit("用户登录", "失败", "登录失败：用户名为空", username)
            return

        if not password or password == self.SAVED_PASSWORD_PLACEHOLDER:
            saved_user = self._auth.login_with_token(username)
            if saved_user:
                self._complete_login(saved_user, via_token=True)
                return
            self._login_pwd.clear()
            self._login_status.setText("⚠ 保存登录不存在或已失效，请输入密码")
            self._login_status.setStyleSheet("color: #e67e22;")
            self._audit("用户登录", "失败", "登录失败：保存登录不可用", username)
            return

        try:
            if self._auth.login(username, password, key):
                if self._remember_login.isChecked():
                    self._auth.save_login_token(username)
                self._complete_login(username)
            else:
                self._login_status.setText("✗ 用户名或密码错误，或用户不存在")
                self._login_status.setStyleSheet("color: #e74c3c;")
                self._audit("用户登录", "失败", "登录失败：用户名或密码错误", username)
        except Exception as e:
            self._login_status.setText(f"✗ 登录失败: {e}")
            self._login_status.setStyleSheet("color: #e74c3c;")
            self._audit("用户登录", "失败", f"登录异常：{e}", username)

    def _on_logout_clicked(self):
        user = self._logged_in_user or self._login_user.text().strip() or "未登录"
        self._logged_in_user = None
        self._session_label.setText("当前状态: 未登录")
        self._session_label.setStyleSheet("font-size:12px; color:#909399;")
        self._btn_logout.setVisible(False)
        self._login_user.clear()
        self._login_pwd.clear()
        self._login_status.clear()
        self._audit("退出登录", "成功", "用户退出登录", user)
        if self._on_logout:
            self._on_logout()

    # ── Register ───────────────────────────────────────────

    def _on_register(self):
        key = self._get_key()
        if key is None:
            self._reg_status.setText("⚠ 请先生成密钥")
            self._reg_status.setStyleSheet("color: #e67e22;")
            self._audit("用户注册", "失败", "注册失败：密钥未生成")
            return

        username = self._reg_user.text().strip()
        pwd1 = self._reg_pwd.text()
        pwd2 = self._reg_pwd2.text()
        strength = self._password_strength.evaluate(pwd1, username)

        if not username:
            self._reg_status.setText("⚠ 请输入用户名")
            self._reg_status.setStyleSheet("color: #e67e22;")
            self._audit("用户注册", "失败", "注册失败：用户名为空")
            return
        if len(username) < 3 or len(username) > 20:
            self._reg_status.setText("⚠ 用户名长度需在 3-20 字符之间")
            self._reg_status.setStyleSheet("color: #e67e22;")
            self._audit("用户注册", "失败", "注册失败：用户名长度不合法", username)
            return
        if not pwd1:
            self._reg_status.setText("⚠ 请输入密码")
            self._reg_status.setStyleSheet("color: #e67e22;")
            self._audit("用户注册", "失败", "注册失败：密码为空", username)
            return
        if strength.score < 30:
            self._reg_status.setText("⚠ 密码过弱，请增加长度、大小写、数字或特殊字符")
            self._reg_status.setStyleSheet("color: #e67e22;")
            self._audit(
                "用户注册", "失败", "注册失败：密码强度过弱", username,
                {"password_strength": strength.level, "score": strength.score},
            )
            return
        if pwd1 != pwd2:
            self._reg_status.setText("⚠ 两次输入的密码不一致")
            self._reg_status.setStyleSheet("color: #e67e22;")
            self._audit("用户注册", "失败", "注册失败：两次密码不一致", username)
            return
        if self._auth.user_exists(username):
            self._reg_status.setText("⚠ 该用户名已被注册，请更换")
            self._reg_status.setStyleSheet("color: #e67e22;")
            self._audit("用户注册", "失败", "注册失败：用户名已存在", username)
            return

        try:
            encrypted_password = self._adapter.encrypt_string(pwd1, key)
            result = self._admin_registry.create_user_with_admin(username, encrypted_password)
            if result.success:
                self._reg_status.setText(f"✓ 用户 '{username}' 注册成功！")
                self._reg_status.setStyleSheet("color: #27ae60; font-weight: bold;")
                self._audit(
                    "用户注册", "成功", "用户注册成功，密码已加密写入注册表", username,
                    {"password_strength": strength.level, "score": strength.score},
                )
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
                self._reg_status.setText(f"✗ 注册失败：{result.message}")
                self._reg_status.setStyleSheet("color: #e74c3c;")
                self._audit("用户注册", "失败", f"注册失败：{result.message}", username)
        except Exception as e:
            self._reg_status.setText(f"✗ 注册失败: {e}")
            self._reg_status.setStyleSheet("color: #e74c3c;")
            self._audit("用户注册", "失败", f"注册异常：{e}", username)

    def _update_password_strength(self):
        if not hasattr(self, "_strength_bar"):
            return
        result = self._password_strength.evaluate(
            self._reg_pwd.text(),
            self._reg_user.text().strip(),
        )
        self._strength_bar.setValue(result.score)
        self._strength_bar.setFormat(f"{result.level} · {result.score}/100")
        self._strength_label.setText("；".join(result.suggestions))
        self._strength_label.setStyleSheet(f"font-size:11px; color:{result.color};")

    def _audit(
        self,
        action: str,
        status: str,
        message: str,
        user: str = "未登录",
        extra: dict | None = None,
    ):
        if self._audit_logger:
            self._audit_logger.append(action, status, message, user=user or "未登录", extra=extra)
