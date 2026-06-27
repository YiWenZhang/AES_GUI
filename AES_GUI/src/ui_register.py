# -*- coding: utf-8 -*-
"""
RegisterTab — software registration UI.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLineEdit, QPushButton, QLabel, QMessageBox,
)
from PySide6.QtCore import Qt

from .aes_adapter import AesDllAdapter
from .auth_manager import AuthManager


class RegisterTab(QWidget):
    def __init__(self, adapter: AesDllAdapter, auth: AuthManager):
        super().__init__()
        self._adapter = adapter
        self._auth = auth
        self._init_ui()
        self._refresh_status()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        # ── Step 1: Hardware detection & registration code generation ──
        grp_hw = QGroupBox("步骤 1: 获取本机硬件特征 → 生成注册码")
        hw_layout = QVBoxLayout(grp_hw)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("MAC 地址:"))
        self._mac_edit = QLineEdit()
        self._mac_edit.setReadOnly(True)
        self._mac_edit.setFixedWidth(200)
        row1.addWidget(self._mac_edit)
        btn_detect = QPushButton("检测硬件")
        btn_detect.clicked.connect(self._on_detect)
        row1.addWidget(btn_detect)
        row1.addStretch()
        hw_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("注册码:"))
        self._code_edit = QLineEdit()
        self._code_edit.setReadOnly(True)
        self._code_edit.setFixedWidth(340)
        row2.addWidget(self._code_edit)
        btn_gen = QPushButton("生成注册码")
        btn_gen.clicked.connect(self._on_generate_code)
        row2.addWidget(btn_gen)
        btn_copy = QPushButton("复制注册码")
        btn_copy.clicked.connect(self._on_copy_code)
        row2.addWidget(btn_copy)
        row2.addStretch()
        hw_layout.addLayout(row2)

        layout.addWidget(grp_hw)

        # ── Step 2: Enter code and verify ──
        grp_val = QGroupBox("步骤 2: 输入注册码并验证激活")
        val_layout = QVBoxLayout(grp_val)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("输入注册码:"))
        self._input_code = QLineEdit()
        self._input_code.setPlaceholderText("格式: XXXX-XXXX-XXXX-XXXX")
        self._input_code.setFixedWidth(380)
        row3.addWidget(self._input_code)
        btn_verify = QPushButton("验证注册")
        btn_verify.clicked.connect(self._on_verify)
        row3.addWidget(btn_verify)
        row3.addStretch()
        val_layout.addLayout(row3)

        self._reg_status = QLabel()
        val_layout.addWidget(self._reg_status)

        layout.addWidget(grp_val)

        layout.addStretch()

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
        else:
            self._code_edit.setText("生成失败 — 请先加载 DLL")

    def _on_copy_code(self):
        code = self._code_edit.text().strip()
        if code:
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(code)
            self._reg_status.setText("注册码已复制到剪贴板")
            self._reg_status.setStyleSheet("color: blue;")

    def _on_verify(self):
        code = self._input_code.text().strip()
        if not code:
            self._reg_status.setText("⚠ 请输入注册码")
            self._reg_status.setStyleSheet("color: orange;")
            return

        if self._auth.register(code):
            self._reg_status.setText("✓ 注册成功！软件已激活")
            self._reg_status.setStyleSheet("color: green; font-weight: bold;")
            QMessageBox.information(self, "注册成功", "软件已成功注册激活！")
        else:
            self._reg_status.setText("✗ 注册码无效，请检查后重试")
            self._reg_status.setStyleSheet("color: red;")

    def _refresh_status(self):
        if self._auth.is_registered():
            self._reg_status.setText("当前状态: ✓ 已注册 — 可正常使用全部功能")
            self._reg_status.setStyleSheet("color: green; font-weight: bold;")
        else:
            self._reg_status.setText("当前状态: ✗ 未注册 — 请点击'检测硬件'并'生成注册码'进行注册")
            self._reg_status.setStyleSheet("color: gray;")
