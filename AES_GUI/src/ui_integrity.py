# -*- coding: utf-8 -*-
"""
IntegrityCheckPage — standalone SHA-256 signature and integrity verification.
"""

import os
import re
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .audit_log import AuditLogger
from .integrity import FileHashResult, IntegrityService
from .ui_file import FileDropLineEdit


_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class IntegrityCheckPage(QWidget):
    def __init__(
        self,
        integrity: IntegrityService,
        audit_logger: AuditLogger | None = None,
        current_user_getter: Callable[[], str | None] | None = None,
    ):
        super().__init__()
        self.setAcceptDrops(True)
        self._integrity = integrity
        self._audit_logger = audit_logger
        self._get_current_user = current_user_getter or (lambda: None)
        self._last_hash: FileHashResult | None = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        card = QFrame()
        card.setProperty("class", "card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(14)

        title = QLabel("SHA-256 数字签名")
        title.setStyleSheet("font-weight:bold; font-size:16px; color:#2c3e50;")
        card_layout.addWidget(title)

        desc = QLabel("计算文件 SHA-256 摘要，并通过期望摘要判断文件是否被修改或篡改。")
        desc.setWordWrap(True)
        desc.setStyleSheet("color:#909399; font-size:12px;")
        card_layout.addWidget(desc)

        file_row = QHBoxLayout()
        file_row.addWidget(QLabel("校验文件"))
        self._file_path = FileDropLineEdit()
        self._file_path.setPlaceholderText("选择或拖入要计算/校验的文件…")
        self._file_path.file_dropped.connect(self._on_file_dropped)
        file_row.addWidget(self._file_path)
        btn_browse = QPushButton("浏览…")
        btn_browse.setObjectName("normalBtn")
        btn_browse.clicked.connect(self._on_browse_file)
        file_row.addWidget(btn_browse)
        card_layout.addLayout(file_row)

        hash_row = QHBoxLayout()
        hash_row.addWidget(QLabel("当前 SHA-256"))
        self._hash_value = QLineEdit()
        self._hash_value.setReadOnly(True)
        self._hash_value.setPlaceholderText("点击计算后显示 64 位 SHA-256 摘要")
        hash_row.addWidget(self._hash_value)
        card_layout.addLayout(hash_row)

        hash_action_row = QHBoxLayout()
        btn_calc = QPushButton("计算 SHA-256")
        btn_calc.setObjectName("primaryBtn")
        btn_calc.clicked.connect(self._on_calculate_hash)
        hash_action_row.addWidget(btn_calc)
        btn_copy = QPushButton("复制 SHA-256")
        btn_copy.setObjectName("normalBtn")
        btn_copy.clicked.connect(self._on_copy_hash)
        hash_action_row.addWidget(btn_copy)
        hash_action_row.addStretch()
        card_layout.addLayout(hash_action_row)

        expected_row = QHBoxLayout()
        expected_row.addWidget(QLabel("期望 SHA-256"))
        self._expected_hash = QLineEdit()
        self._expected_hash.setPlaceholderText("粘贴已知正确的 64 位 SHA-256，用于判断文件是否被改动")
        expected_row.addWidget(self._expected_hash)
        card_layout.addLayout(expected_row)

        verify_row = QHBoxLayout()
        btn_verify = QPushButton("校验文件完整性")
        btn_verify.setObjectName("successBtn")
        btn_verify.clicked.connect(self._on_verify_hash)
        verify_row.addWidget(btn_verify)
        verify_row.addStretch()
        card_layout.addLayout(verify_row)

        self._status = QLabel("请选择文件并计算 SHA-256")
        self._status.setWordWrap(True)
        self._status.setStyleSheet("font-size:12px; color:#909399;")
        card_layout.addWidget(self._status)

        card_layout.addWidget(QLabel("操作日志"))
        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setMinimumHeight(100)
        card_layout.addWidget(self._log, 1)

        layout.addWidget(card, 1)

    def dragEnterEvent(self, event):
        path = self._path_from_drop_event(event)
        if path:
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        path = self._path_from_drop_event(event)
        if path:
            self._on_file_dropped(path)
            event.acceptProposedAction()
        else:
            event.ignore()

    def _path_from_drop_event(self, event) -> str:
        if not event.mimeData().hasUrls():
            return ""
        urls = event.mimeData().urls()
        if not urls:
            return ""
        path = urls[0].toLocalFile()
        if path and os.path.isfile(path):
            return path
        return ""

    def _on_browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*)")
        if path:
            self._set_file_path(path)

    def _on_file_dropped(self, path: str):
        self._set_file_path(path)
        self._log.append(f"[i] 已拖入文件: {path}")

    def _set_file_path(self, path: str):
        self._file_path.setText(path)
        self._hash_value.clear()
        self._last_hash = None
        self._status.setText("已选择文件，请计算 SHA-256 或输入期望值进行校验")
        self._status.setStyleSheet("font-size:12px; color:#909399;")

    def _on_calculate_hash(self):
        path = self._file_path.text().strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "错误", "请先选择要计算的文件")
            return
        try:
            result = self._integrity.sha256_file(path)
            self._last_hash = result
            self._hash_value.setText(result.sha256)
            self._status.setText(f"计算完成：{result.sha256}")
            self._status.setStyleSheet("font-size:12px; color:#27ae60; font-weight:bold;")
            self._log.append(
                f"[✓] SHA-256 计算完成\n"
                f"    文件: {result.path}\n"
                f"    大小: {result.size:,} bytes\n"
                f"    SHA-256: {result.sha256}"
            )
            self._audit(
                "SHA-256 数字签名",
                "成功",
                "文件 SHA-256 摘要计算完成",
                input_path=result.path,
                input_sha256=result.sha256,
                extra={"input_size": result.size},
            )
        except Exception as e:
            QMessageBox.warning(self, "计算失败", str(e))
            self._audit("SHA-256 数字签名", "失败", f"计算失败：{e}", input_path=path)

    def _on_copy_hash(self):
        hash_text = self._hash_value.text().strip()
        if not hash_text:
            QMessageBox.warning(self, "无摘要", "请先计算 SHA-256 后再复制")
            return
        QApplication.clipboard().setText(hash_text)
        self._status.setText("SHA-256 已复制到剪贴板")
        self._status.setStyleSheet("font-size:12px; color:#27ae60; font-weight:bold;")

    def _on_verify_hash(self):
        path = self._file_path.text().strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "错误", "请先选择要校验的文件")
            return
        expected = self._normalize_hash(self._expected_hash.text())
        if not _HEX64_RE.match(expected):
            QMessageBox.warning(self, "格式错误", "期望 SHA-256 必须是 64 位十六进制字符串")
            return
        try:
            actual = self._integrity.sha256_file(path)
            self._last_hash = actual
            self._hash_value.setText(actual.sha256)
            ok = actual.sha256 == expected
            if ok:
                self._status.setText("校验通过：文件未发生变化")
                self._status.setStyleSheet("font-size:12px; color:#27ae60; font-weight:bold;")
                self._log.append(f"[✓] 完整性校验通过: {actual.path}")
            else:
                self._status.setText("校验失败：文件可能已被修改或篡改")
                self._status.setStyleSheet("font-size:12px; color:#e74c3c; font-weight:bold;")
                self._log.append(
                    f"[✗] 完整性校验失败\n"
                    f"    文件: {actual.path}\n"
                    f"    期望: {expected}\n"
                    f"    实际: {actual.sha256}"
                )
            self._audit(
                "SHA-256 完整性校验",
                "成功" if ok else "失败",
                "文件 SHA-256 与期望值一致" if ok else "文件 SHA-256 与期望值不一致，可能被篡改",
                input_path=actual.path,
                input_sha256=actual.sha256,
                extra={"expected_sha256": expected, "input_size": actual.size},
            )
        except Exception as e:
            QMessageBox.warning(self, "校验失败", str(e))
            self._audit("SHA-256 完整性校验", "失败", f"校验异常：{e}", input_path=path)

    def _normalize_hash(self, value: str) -> str:
        return value.strip().lower().replace(" ", "")

    def _audit(
        self,
        action: str,
        status: str,
        message: str,
        input_path: str = "",
        input_sha256: str = "",
        extra: dict | None = None,
    ):
        if self._audit_logger:
            self._audit_logger.append(
                action,
                status,
                message,
                user=self._get_current_user() or "未登录",
                input_path=input_path,
                input_sha256=input_sha256,
                extra=extra,
            )
