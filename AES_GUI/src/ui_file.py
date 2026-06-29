# -*- coding: utf-8 -*-
"""
FileCipherPage — file encryption / decryption.
"""

import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QLabel, QFileDialog, QTextEdit,
    QProgressBar, QFrame, QMessageBox, QSizePolicy,
)
from PySide6.QtCore import Signal
from typing import Callable

from .audit_log import AuditLogger
from .file_cipher import FileCipher
from .integrity import IntegrityService, FileHashResult


class FileDropLineEdit(QLineEdit):
    file_dropped = Signal(str)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if not urls:
            return
        path = urls[0].toLocalFile()
        if path and os.path.isfile(path):
            self.setText(path)
            self.file_dropped.emit(path)
            event.acceptProposedAction()
        else:
            event.ignore()


class FileCipherPage(QWidget):
    def __init__(
        self,
        cipher: FileCipher,
        key_getter: Callable[[], bytes | None],
        integrity: IntegrityService | None = None,
        audit_logger: AuditLogger | None = None,
        current_user_getter: Callable[[], str | None] | None = None,
    ):
        super().__init__()
        self.setAcceptDrops(True)
        self._cipher = cipher
        self._get_key = key_getter
        self._integrity = integrity or IntegrityService()
        self._audit_logger = audit_logger
        self._get_current_user = current_user_getter or (lambda: None)
        self._last_source_hash: FileHashResult | None = None
        self._last_output_hash: FileHashResult | None = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        # Key bar
        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("当前密钥"))
        self._key_label = QLineEdit()
        self._key_label.setReadOnly(True)
        self._key_label.setPlaceholderText("加载 DLL 后自动生成")
        key_row.addWidget(self._key_label)
        layout.addLayout(key_row)

        # Main card
        card = QFrame()
        card.setProperty("class", "card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 16, 18, 16)
        card_layout.setSpacing(8)

        title = QLabel("文件加解密操作")
        title.setStyleSheet("font-weight:bold; font-size:15px; color:#2c3e50;")
        card_layout.addWidget(title)

        drop_tip = QLabel("支持拖入单个文件，系统会自动建议输出路径。")
        drop_tip.setStyleSheet("color:#909399; font-size:12px;")
        card_layout.addWidget(drop_tip)

        # Input
        r1 = QHBoxLayout()
        r1.addWidget(QLabel("源文件"))
        self._input_path = FileDropLineEdit()
        self._input_path.setPlaceholderText("选择或拖入要加密/解密的文件…")
        self._input_path.file_dropped.connect(self._on_file_dropped)
        r1.addWidget(self._input_path)
        btn_in = QPushButton("浏览…")
        btn_in.setObjectName("normalBtn")
        btn_in.clicked.connect(self._on_browse_input)
        r1.addWidget(btn_in)
        card_layout.addLayout(r1)

        # Output
        r2 = QHBoxLayout()
        r2.addWidget(QLabel("输出"))
        self._output_path = QLineEdit()
        self._output_path.setPlaceholderText("自动生成或手动选择…")
        r2.addWidget(self._output_path)
        btn_out = QPushButton("浏览…")
        btn_out.setObjectName("normalBtn")
        btn_out.clicked.connect(self._on_browse_output)
        r2.addWidget(btn_out)
        card_layout.addLayout(r2)

        # Actions
        r3 = QHBoxLayout()
        btn_enc = QPushButton("加密文件 🔒")
        btn_enc.setObjectName("primaryBtn")
        btn_enc.clicked.connect(self._on_encrypt)
        r3.addWidget(btn_enc)

        btn_dec = QPushButton("解密文件 🔓")
        btn_dec.setObjectName("primaryBtn")
        btn_dec.clicked.connect(self._on_decrypt)
        r3.addWidget(btn_dec)

        btn_open = QPushButton("打开输出文件夹")
        btn_open.setObjectName("normalBtn")
        btn_open.clicked.connect(self._on_open_folder)
        r3.addWidget(btn_open)
        r3.addStretch()
        card_layout.addLayout(r3)

        hash_calc_row = QHBoxLayout()
        btn_hash_src = QPushButton("计算源文件 SHA-256")
        btn_hash_src.setObjectName("normalBtn")
        btn_hash_src.clicked.connect(self._on_hash_source)
        hash_calc_row.addWidget(btn_hash_src)

        btn_hash_out = QPushButton("计算输出文件 SHA-256")
        btn_hash_out.setObjectName("normalBtn")
        btn_hash_out.clicked.connect(self._on_hash_output)
        hash_calc_row.addWidget(btn_hash_out)
        hash_calc_row.addStretch()
        card_layout.addLayout(hash_calc_row)

        hash_copy_row = QHBoxLayout()
        btn_copy_src = QPushButton("复制源文件 SHA-256")
        btn_copy_src.setObjectName("normalBtn")
        btn_copy_src.clicked.connect(self._on_copy_source_hash)
        hash_copy_row.addWidget(btn_copy_src)

        btn_copy_out = QPushButton("复制输出文件 SHA-256")
        btn_copy_out.setObjectName("normalBtn")
        btn_copy_out.clicked.connect(self._on_copy_output_hash)
        hash_copy_row.addWidget(btn_copy_out)
        hash_copy_row.addStretch()
        card_layout.addLayout(hash_copy_row)

        expected_row = QHBoxLayout()
        expected_row.addWidget(QLabel("说明"))
        hint = QLabel("文件完整性校验请使用左侧“SHA-256 数字签名”栏目")
        hint.setStyleSheet("font-size:11px; color:#909399;")
        expected_row.addWidget(hint)
        expected_row.addStretch()
        card_layout.addLayout(expected_row)

        self._hash_info = QLabel("")
        self._hash_info.setWordWrap(True)
        self._hash_info.setStyleSheet("font-size:11px; color:#909399;")
        card_layout.addWidget(self._hash_info)

        # Progress
        self._progress = QProgressBar()
        self._progress.setVisible(False)
        card_layout.addWidget(self._progress)

        # Log
        card_layout.addWidget(QLabel("操作日志"))
        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setMinimumHeight(140)
        self._log.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        card_layout.addWidget(self._log, 3)

        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
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

    def _on_browse_input(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*)")
        if path:
            self._set_input_path(path)

    def _on_browse_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "选择输出文件", "")
        if path:
            self._output_path.setText(path)

    def _on_file_dropped(self, path: str):
        self._set_input_path(path, replace_output=True)
        self._log.append(f"[i] 已拖入文件: {path}")

    def _set_input_path(self, path: str, replace_output: bool = False):
        self._input_path.setText(path)
        if replace_output or not self._output_path.text():
            for_encrypt = not path.lower().endswith(FileCipher.ENC_EXT)
            self._output_path.setText(FileCipher.suggest_output_path(path, for_encrypt=for_encrypt))

    def _on_encrypt(self):
        key = self._get_key()
        if key is None:
            QMessageBox.warning(self, "错误", "请先生成密钥")
            self._audit("文件加密", "失败", "加密失败：密钥未生成")
            return
        in_path = self._input_path.text().strip()
        if not in_path or not os.path.isfile(in_path):
            QMessageBox.warning(self, "错误", "源文件不存在")
            self._audit("文件加密", "失败", "加密失败：源文件不存在", input_path=in_path)
            return
        out_path = self._output_path.text().strip() or \
                   FileCipher.suggest_output_path(in_path, for_encrypt=True)
        if not FileCipher.can_encrypt(in_path) or not FileCipher.is_encrypted_file(out_path):
            QMessageBox.warning(self, "不支持的文件格式", "不支持该类型文件格式加密")
            self._audit("文件加密", "失败", "加密失败：不支持该类型文件格式", input_path=in_path, output_path=out_path)
            return
        try:
            in_hash = self._integrity.sha256_file(in_path)
            self._progress.setVisible(True)
            self._progress.setValue(30)
            ok = self._cipher.encrypt(in_path, out_path, key)
            self._progress.setValue(100)
            if ok:
                out_hash = self._integrity.sha256_file(out_path)
                self._last_source_hash = in_hash
                self._last_output_hash = out_hash
                self._append_file_log("加密完成", in_path, out_path, in_hash, out_hash)
                self._audit_file("文件加密", "成功", "文件加密成功", in_path, out_path, in_hash, out_hash)
                QMessageBox.information(self, "成功", f"文件加密完成！\n{out_path}")
            else:
                self._log.append("[✗] 加密失败")
                self._audit_file("文件加密", "失败", "DLL 返回加密失败", in_path, out_path, in_hash, None)
        except Exception as e:
            self._log.append(f"[✗] {e}")
            self._audit("文件加密", "失败", f"加密异常：{e}", input_path=in_path, output_path=out_path)
        finally:
            self._progress.setVisible(False)

    def _on_decrypt(self):
        key = self._get_key()
        if key is None:
            QMessageBox.warning(self, "错误", "请先生成密钥")
            self._audit("文件解密", "失败", "解密失败：密钥未生成")
            return
        in_path = self._input_path.text().strip()
        if not in_path or not os.path.isfile(in_path):
            QMessageBox.warning(self, "错误", "源文件不存在")
            self._audit("文件解密", "失败", "解密失败：源文件不存在", input_path=in_path)
            return
        out_path = self._output_path.text().strip() or \
                   FileCipher.suggest_output_path(in_path, for_encrypt=False)
        if not FileCipher.can_decrypt(in_path):
            QMessageBox.warning(self, "不支持的文件格式", "不支持该类型文件格式解密")
            self._audit("文件解密", "失败", "解密失败：不支持该类型文件格式", input_path=in_path, output_path=out_path)
            return
        try:
            in_hash = self._integrity.sha256_file(in_path)
            self._progress.setVisible(True)
            self._progress.setValue(30)
            ok = self._cipher.decrypt(in_path, out_path, key)
            self._progress.setValue(100)
            if ok:
                out_hash = self._integrity.sha256_file(out_path)
                self._last_source_hash = in_hash
                self._last_output_hash = out_hash
                self._append_file_log("解密完成", in_path, out_path, in_hash, out_hash)
                self._audit_file("文件解密", "成功", "文件解密成功", in_path, out_path, in_hash, out_hash)
                QMessageBox.information(self, "成功", f"文件解密完成！\n{out_path}")
            else:
                self._log.append("[✗] 解密失败 — 密钥是否正确？")
                self._audit_file("文件解密", "失败", "DLL 返回解密失败", in_path, out_path, in_hash, None)
        except Exception as e:
            self._log.append(f"[✗] {e}")
            self._audit("文件解密", "失败", f"解密异常：{e}", input_path=in_path, output_path=out_path)
        finally:
            self._progress.setVisible(False)

    def _on_hash_source(self):
        path = self._input_path.text().strip()
        self._calculate_and_show_hash(path, is_source=True)

    def _on_hash_output(self):
        path = self._output_path.text().strip()
        self._calculate_and_show_hash(path, is_source=False)

    def _on_copy_source_hash(self):
        self._copy_hash(self._last_source_hash, "源文件")

    def _on_copy_output_hash(self):
        self._copy_hash(self._last_output_hash, "输出文件")

    def _copy_hash(self, result: FileHashResult | None, label: str):
        if result is None:
            QMessageBox.warning(self, "无摘要", f"请先计算{label} SHA-256")
            return
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(result.sha256)
        self._hash_info.setText(f"{label} SHA-256 已复制到剪贴板：{result.sha256}")
        self._hash_info.setStyleSheet("font-size:11px; color:#27ae60;")

    def _on_verify_expected_hash(self):
        path = self._input_path.text().strip()
        expected = self._expected_hash.text().strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "错误", "请先选择要校验的源文件")
            return
        if not expected:
            QMessageBox.warning(self, "错误", "请先输入期望 SHA-256")
            return
        try:
            ok = self._integrity.verify_sha256(path, expected)
            actual = self._integrity.sha256_file(path)
            self._last_source_hash = actual
            if ok:
                self._hash_info.setText(f"校验通过：{actual.sha256}")
                self._hash_info.setStyleSheet("font-size:11px; color:#27ae60;")
                self._audit("SHA-256 校验", "成功", "源文件 SHA-256 与期望值一致", input_path=path, input_sha256=actual.sha256)
            else:
                self._hash_info.setText(f"校验失败：实际值 {actual.sha256}")
                self._hash_info.setStyleSheet("font-size:11px; color:#e74c3c;")
                self._audit("SHA-256 校验", "失败", "源文件 SHA-256 与期望值不一致", input_path=path, input_sha256=actual.sha256)
        except Exception as e:
            QMessageBox.warning(self, "校验失败", str(e))

    def _calculate_and_show_hash(self, path: str, is_source: bool):
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "错误", "文件不存在")
            return
        try:
            result = self._integrity.sha256_file(path)
            if is_source:
                self._last_source_hash = result
                label = "源文件"
            else:
                self._last_output_hash = result
                label = "输出文件"
            self._hash_info.setText(f"{label} SHA-256: {result.sha256} ({result.size:,} bytes)")
            self._hash_info.setStyleSheet("font-size:11px; color:#2c3e50;")
            self._log.append(f"[i] {label} SHA-256: {result.sha256}")
            self._audit("SHA-256 计算", "成功", f"{label}摘要计算完成", input_path=path, input_sha256=result.sha256)
        except Exception as e:
            QMessageBox.warning(self, "计算失败", str(e))

    def _append_file_log(
        self,
        title: str,
        in_path: str,
        out_path: str,
        in_hash: FileHashResult,
        out_hash: FileHashResult,
    ):
        self._log.append(
            f"[✓] {title}\n"
            f"    源: {in_path} ({in_hash.size:,} bytes)\n"
            f"    出: {out_path} ({out_hash.size:,} bytes)\n"
            f"    源 SHA-256: {in_hash.sha256}\n"
            f"    出 SHA-256: {out_hash.sha256}"
        )
        self._hash_info.setText(f"最近操作：源 SHA-256 {in_hash.sha256}；输出 SHA-256 {out_hash.sha256}")
        self._hash_info.setStyleSheet("font-size:11px; color:#2c3e50;")

    def _on_open_folder(self):
        p = self._output_path.text().strip()
        if p:
            folder = os.path.dirname(p)
            if os.path.isdir(folder):
                os.startfile(folder)

    def refresh_key_display(self):
        key = self._get_key()
        if key:
            self._key_label.setText(key.hex())
        else:
            self._key_label.setText("密钥未生成")

    def _audit_file(
        self,
        action: str,
        status: str,
        message: str,
        input_path: str,
        output_path: str,
        input_hash: FileHashResult | None,
        output_hash: FileHashResult | None,
    ):
        self._audit(
            action,
            status,
            message,
            input_path=input_path,
            output_path=output_path,
            input_sha256=input_hash.sha256 if input_hash else "",
            output_sha256=output_hash.sha256 if output_hash else "",
            extra={
                "input_size": input_hash.size if input_hash else 0,
                "output_size": output_hash.size if output_hash else 0,
            },
        )

    def _audit(
        self,
        action: str,
        status: str,
        message: str,
        input_path: str = "",
        output_path: str = "",
        input_sha256: str = "",
        output_sha256: str = "",
        extra: dict | None = None,
    ):
        if self._audit_logger:
            self._audit_logger.append(
                action, status, message,
                user=self._get_current_user() or "未登录",
                input_path=input_path,
                output_path=output_path,
                input_sha256=input_sha256,
                output_sha256=output_sha256,
                extra=extra,
            )
