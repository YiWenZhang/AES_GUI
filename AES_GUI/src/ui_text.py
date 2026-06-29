# -*- coding: utf-8 -*-
"""
TextCipherPage — string encryption / decryption.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton, QLabel, QFileDialog,
    QSplitter, QFrame, QMessageBox,
)
from PySide6.QtCore import Qt
from typing import Callable

from .audit_log import AuditLogger
from .text_cipher import TextCipher


class TextCipherPage(QWidget):
    def __init__(
        self,
        cipher: TextCipher,
        key_getter: Callable[[], bytes | None],
        audit_logger: AuditLogger | None = None,
        current_user_getter: Callable[[], str | None] | None = None,
    ):
        super().__init__()
        self._cipher = cipher
        self._get_key = key_getter
        self._audit_logger = audit_logger
        self._get_current_user = current_user_getter or (lambda: None)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        # ── Key bar ──
        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("当前密钥"))
        self._key_label = QLineEdit()
        self._key_label.setReadOnly(True)
        self._key_label.setPlaceholderText("加载 DLL 后自动生成")
        key_row.addWidget(self._key_label)
        layout.addLayout(key_row)

        # ── Side-by-side splitter ──
        splitter = QSplitter(Qt.Horizontal)

        # Left: input
        left = QFrame()
        left.setProperty("class", "card")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(16, 16, 16, 16)

        left_title = QLabel("输入区")
        left_title.setStyleSheet("font-weight:bold; font-size:14px; color:#2c3e50;")
        left_layout.addWidget(left_title)

        self._input_area = QTextEdit()
        self._input_area.setPlaceholderText(
            "在此输入要加密的文本，或粘贴十六进制密文进行解密…"
        )
        self._input_area.setMinimumHeight(200)
        left_layout.addWidget(self._input_area)

        self._input_info = QLabel("")
        self._input_info.setStyleSheet("color:#909399; font-size:11px;")
        left_layout.addWidget(self._input_info)
        self._input_area.textChanged.connect(self._update_input_info)

        # buttons
        btn_row = QHBoxLayout()
        btn_enc = QPushButton("加密 🔒")
        btn_enc.setObjectName("primaryBtn")
        btn_enc.clicked.connect(self._on_encrypt)
        btn_row.addWidget(btn_enc)

        btn_dec = QPushButton("解密 🔓")
        btn_dec.setObjectName("primaryBtn")
        btn_dec.clicked.connect(self._on_decrypt)
        btn_row.addWidget(btn_dec)

        btn_clear = QPushButton("清空")
        btn_clear.setObjectName("normalBtn")
        btn_clear.clicked.connect(self._input_area.clear)
        btn_row.addWidget(btn_clear)
        btn_row.addStretch()
        left_layout.addLayout(btn_row)

        import_row = QHBoxLayout()
        btn_txt = QPushButton("导入 TXT")
        btn_txt.setObjectName("normalBtn")
        btn_txt.clicked.connect(self._on_import_txt)
        import_row.addWidget(btn_txt)

        btn_docx = QPushButton("导入 Word")
        btn_docx.setObjectName("normalBtn")
        btn_docx.clicked.connect(self._on_import_docx)
        import_row.addWidget(btn_docx)
        import_row.addStretch()
        left_layout.addLayout(import_row)
        splitter.addWidget(left)

        # Right: output
        right = QFrame()
        right.setProperty("class", "card")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(16, 16, 16, 16)

        right_title = QLabel("输出区")
        right_title.setStyleSheet("font-weight:bold; font-size:14px; color:#2c3e50;")
        right_layout.addWidget(right_title)

        self._output_area = QTextEdit()
        self._output_area.setReadOnly(True)
        self._output_area.setPlaceholderText("加解密结果将显示在此处…")
        self._output_area.setMinimumHeight(200)
        right_layout.addWidget(self._output_area)

        self._output_info = QLabel("")
        self._output_info.setStyleSheet("color:#909399; font-size:11px;")
        right_layout.addWidget(self._output_info)

        out_btn = QHBoxLayout()
        btn_copy = QPushButton("📋 复制")
        btn_copy.setObjectName("normalBtn")
        btn_copy.clicked.connect(self._on_copy)
        out_btn.addWidget(btn_copy)

        btn_clear_out = QPushButton("清空")
        btn_clear_out.setObjectName("normalBtn")
        btn_clear_out.clicked.connect(self._output_area.clear)
        out_btn.addWidget(btn_clear_out)
        out_btn.addStretch()
        right_layout.addLayout(out_btn)

        save_btn = QHBoxLayout()
        btn_save = QPushButton("💾 保存")
        btn_save.setObjectName("normalBtn")
        btn_save.clicked.connect(self._on_save)
        save_btn.addWidget(btn_save)
        save_btn.addStretch()
        right_layout.addLayout(save_btn)
        splitter.addWidget(right)

        splitter.setSizes([480, 480])
        layout.addWidget(splitter)

    # ── actions ────────────────────────────────────────────

    def _on_encrypt(self):
        key = self._get_key()
        if key is None:
            QMessageBox.warning(self, "错误", "请先生成密钥")
            self._audit("文本加密", "失败", "加密失败：密钥未生成")
            return
        plain = self._input_area.toPlainText()
        if not plain:
            self._output_area.setPlainText("[错误] 请输入待加密文本")
            self._audit("文本加密", "失败", "加密失败：输入为空")
            return
        try:
            result = self._cipher.encrypt(plain, key)
            upper = result.upper()
            iv_part = upper[:32]
            body_part = upper[32:]
            self._output_area.setHtml(f"<b>{iv_part}</b>{body_part}")
            pb = len(plain.encode("utf-8"))
            self._output_info.setText(
                f"明文 {pb} 字节 → 密文 {len(result)//2} 字节 "
                f"({len(result)} hex, 前 32 字符为 IV，已加粗)"
            )
            self._audit(
                "文本加密", "成功", "文本加密成功",
                {"input_bytes": pb, "output_hex_length": len(result)},
            )
        except Exception as e:
            self._output_area.setPlainText(f"加密失败: {e}")
            self._audit("文本加密", "失败", f"加密异常：{e}")

    def _on_decrypt(self):
        key = self._get_key()
        if key is None:
            QMessageBox.warning(self, "错误", "请先生成密钥")
            self._audit("文本解密", "失败", "解密失败：密钥未生成")
            return
        hex_in = self._input_area.toPlainText().strip()
        if not hex_in:
            self._output_area.setPlainText("[错误] 请输入十六进制密文")
            self._audit("文本解密", "失败", "解密失败：输入为空")
            return
        try:
            result = self._cipher.decrypt(hex_in.lower(), key)
            self._output_area.setPlainText(result)
            self._output_info.setText(
                f"解密成功 — 还原 {len(result)} 字符 "
                f"({len(result.encode('utf-8'))} 字节)"
            )
            self._audit(
                "文本解密", "成功", "文本解密成功",
                {"input_hex_length": len(hex_in), "output_bytes": len(result.encode("utf-8"))},
            )
        except Exception as e:
            self._output_area.setPlainText(f"解密失败: {e}\n\n密钥是否正确？")
            self._audit("文本解密", "失败", f"解密异常：{e}")

    def _on_import_txt(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择文本文件", "",
            "文本文件 (*.txt *.csv);;所有文件 (*)"
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self._input_area.setPlainText(f.read())
            except Exception as e:
                self._output_area.setPlainText(f"导入失败: {e}")

    def _on_import_docx(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 Word 文档", "",
            "Word 文档 (*.docx);;所有文件 (*)"
        )
        if path:
            try:
                from docx import Document
                doc = Document(path)
                lines = [p.text for p in doc.paragraphs if p.text.strip()]
                self._input_area.setPlainText("\n".join(lines))
            except ImportError:
                QMessageBox.warning(self, "缺少依赖", "请执行: pip install python-docx")
            except Exception as e:
                self._output_area.setPlainText(f"导入 Word 失败: {e}")

    def _on_copy(self):
        text = self._output_area.toPlainText()
        if text:
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(text)
            self._output_info.setText("已复制到剪贴板")

    def _on_save(self):
        text = self._output_area.toPlainText()
        if not text:
            QMessageBox.warning(self, "无内容", "请先执行加解密再保存")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "保存结果", "result.txt",
            "文本文件 (*.txt);;所有文件 (*)"
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
                self._output_info.setText(f"已保存到: {path}")
            except Exception as e:
                QMessageBox.warning(self, "保存失败", str(e))

    def _update_input_info(self):
        text = self._input_area.toPlainText()
        if text:
            self._input_info.setText(
                f"输入: {len(text)} 字符 / {len(text.encode('utf-8'))} 字节"
            )
        else:
            self._input_info.setText("")

    def refresh_key_display(self):
        key = self._get_key()
        if key:
            self._key_label.setText(key.hex())
        else:
            self._key_label.setText("密钥未生成")

    def _audit(self, action: str, status: str, message: str, extra: dict | None = None):
        if self._audit_logger:
            self._audit_logger.append(
                action, status, message,
                user=self._get_current_user() or "未登录",
                extra=extra,
            )
