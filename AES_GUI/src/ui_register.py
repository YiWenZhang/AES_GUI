# -*- coding: utf-8 -*-
"""
RegisterPage — software registration card UI.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QLabel, QFrame, QMessageBox,
)
from PySide6.QtCore import Qt
from typing import Callable

from .aes_adapter import AesDllAdapter
from .auth_manager import AuthManager
from .audit_log import AuditLogger


class RegisterPage(QWidget):
    def __init__(
        self,
        adapter: AesDllAdapter,
        auth: AuthManager,
        on_registered: Callable[[], None] = None,
        audit_logger: AuditLogger | None = None,
    ):
        super().__init__()
        self._adapter = adapter
        self._auth = auth
        self._on_registered = on_registered
        self._audit_logger = audit_logger
        self._init_ui()
        self._refresh_state()

    def _init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(32, 28, 32, 28)

        # 居中容器
        outer.addStretch()
        card = QFrame()
        card.setProperty("class", "card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(40, 36, 40, 36)
        layout.setSpacing(20)

        title = QLabel("软件注册激活")
        title.setStyleSheet("font-size:20px; font-weight:bold; color:#2c3e50;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        desc = QLabel("系统通过本机硬件特征生成唯一注册码，用于验证软件使用授权")
        desc.setAlignment(Qt.AlignCenter)
        desc.setWordWrap(True)
        desc.setStyleSheet("color:#909399; font-size:12px;")
        layout.addWidget(desc)

        # ── 步骤 1 ──
        step1 = QLabel("步骤 1 · 获取硬件特征")
        step1.setStyleSheet("font-weight:bold; color:#3498db; font-size:14px;")
        layout.addWidget(step1)

        r1 = QHBoxLayout()
        r1.addWidget(QLabel("MAC 地址"))
        self._mac_edit = QLineEdit()
        self._mac_edit.setReadOnly(True)
        self._mac_edit.setFixedWidth(200)
        r1.addWidget(self._mac_edit)
        btn_detect = QPushButton("检测硬件")
        btn_detect.setObjectName("normalBtn")
        btn_detect.clicked.connect(self._on_detect)
        r1.addWidget(btn_detect)
        r1.addStretch()
        layout.addLayout(r1)

        # ── 步骤 2 ──
        step2 = QLabel("步骤 2 · 生成注册码")
        step2.setStyleSheet("font-weight:bold; color:#3498db; font-size:14px;")
        layout.addWidget(step2)

        r2a = QHBoxLayout()
        r2a.addWidget(QLabel("注册码"))
        self._code_edit = QLineEdit()
        self._code_edit.setReadOnly(True)
        self._code_edit.setFixedWidth(320)
        r2a.addWidget(self._code_edit)
        btn_gen = QPushButton("生成")
        btn_gen.setObjectName("primaryBtn")
        btn_gen.clicked.connect(self._on_generate_code)
        r2a.addWidget(btn_gen)
        r2a.addStretch()
        layout.addLayout(r2a)

        # ── 步骤 3 ──
        step3 = QLabel("步骤 3 · 输入注册码并激活")
        step3.setStyleSheet("font-weight:bold; color:#3498db; font-size:14px;")
        layout.addWidget(step3)

        r3 = QHBoxLayout()
        self._input_code = QLineEdit()
        self._input_code.setPlaceholderText("格式: XXXX-XXXX-XXXX-XXXX")
        self._input_code.setFixedWidth(320)
        r3.addWidget(self._input_code)
        btn_verify = QPushButton("验证激活")
        btn_verify.setObjectName("successBtn")
        btn_verify.clicked.connect(self._on_verify)
        r3.addWidget(btn_verify)
        r3.addStretch()
        layout.addLayout(r3)

        self._status_label = QLabel()
        self._status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._status_label)

        outer.addWidget(card)
        outer.addStretch()

    def _on_detect(self):
        try:
            if self._adapter.is_loaded:
                mac = self._adapter.get_mac_address()
                self._mac_edit.setText(mac)
            else:
                self._mac_edit.setText("DLL 未加载")
        except Exception as e:
            self._mac_edit.setText(f"错误: {e}")

    def _on_generate_code(self):
        code = self._auth.generate_registration_code()
        if code:
            self._code_edit.setText(code)
            self._input_code.setText(code)
        else:
            self._code_edit.setText("生成失败 — 请先加载 DLL")

    def _on_verify(self):
        code = self._input_code.text().strip()
        if not code:
            self._status_label.setText("⚠ 请输入注册码")
            self._status_label.setStyleSheet("color: #e67e22;")
            self._audit("失败", "软件激活失败：未输入注册码")
            return

        if self._auth.register(code):
            self._status_label.setText("✓ 注册成功 — 软件已激活")
            self._status_label.setStyleSheet("color: #27ae60; font-weight: bold;")
            self._audit("成功", "软件激活成功")
            if self._on_registered:
                self._on_registered()
        else:
            self._status_label.setText("✗ 注册码无效，请检查后重试")
            self._status_label.setStyleSheet("color: #e74c3c;")
            self._audit("失败", "软件激活失败：注册码无效")

    def _audit(self, status: str, message: str):
        if self._audit_logger:
            self._audit_logger.append("软件注册", status, message)

    def _refresh_state(self):
        if self._auth.is_registered():
            self._status_label.setText("✓ 当前已激活")
            self._status_label.setStyleSheet("color: #27ae60; font-weight: bold;")
        else:
            self._status_label.setText("○ 尚未激活 — 请完成上述步骤")
            self._status_label.setStyleSheet("color: #909399;")
