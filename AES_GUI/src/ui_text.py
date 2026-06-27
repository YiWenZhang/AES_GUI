# -*- coding: utf-8 -*-
"""
TextCipherTab — string encryption / decryption UI with side-by-side comparison.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QSplitter,
    QTextEdit, QLineEdit, QPushButton, QLabel, QFileDialog, QMessageBox,
)
from PySide6.QtCore import Qt
from typing import Callable

from .text_cipher import TextCipher


class TextCipherTab(QWidget):
    def __init__(self, cipher: TextCipher, key_getter: Callable[[], bytes | None]):
        super().__init__()
        self._cipher = cipher
        self._get_key = key_getter
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)

        # ── Key display ──
        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("当前密钥:"))
        self._key_label = QLineEdit()
        self._key_label.setReadOnly(True)
        self._key_label.setPlaceholderText("加载 DLL 后自动生成 — 无需手动输入")
        key_row.addWidget(self._key_label)
        layout.addLayout(key_row)

        # ── Side-by-side input / output via QSplitter ──
        splitter = QSplitter(Qt.Horizontal)

        # Left panel: input
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        grp_input = QGroupBox("输入区 — 明文 / 十六进制密文")
        in_layout = QVBoxLayout(grp_input)

        self._input_area = QTextEdit()
        self._input_area.setPlaceholderText(
            "在此输入文本，或点击下方按钮从 TXT / Word 文件导入…\n\n"
            "· 加密：输入普通文本\n"
            "· 解密：粘贴十六进制密文字符串"
        )
        self._input_area.setMinimumHeight(180)
        in_layout.addWidget(self._input_area)

        self._input_info = QLabel("")
        self._input_info.setStyleSheet("color: gray; font-size: 12px;")
        in_layout.addWidget(self._input_info)

        self._input_area.textChanged.connect(self._update_input_info)

        btn_row = QHBoxLayout()
        btn_encrypt = QPushButton("加密 🔒")
        btn_encrypt.setStyleSheet("font-weight: bold; padding: 6px 16px;")
        btn_encrypt.clicked.connect(self._on_encrypt)
        btn_row.addWidget(btn_encrypt)

        btn_decrypt = QPushButton("解密 🔓")
        btn_decrypt.setStyleSheet("font-weight: bold; padding: 6px 16px;")
        btn_decrypt.clicked.connect(self._on_decrypt)
        btn_row.addWidget(btn_decrypt)

        btn_row.addWidget(QLabel("  |  "))

        btn_txt = QPushButton("导入 TXT")
        btn_txt.clicked.connect(self._on_import_txt)
        btn_row.addWidget(btn_txt)

        btn_docx = QPushButton("导入 Word")
        btn_docx.clicked.connect(self._on_import_docx)
        btn_row.addWidget(btn_docx)

        btn_clear_input = QPushButton("清空输入")
        btn_clear_input.clicked.connect(lambda: self._input_area.clear())
        btn_row.addWidget(btn_clear_input)

        btn_row.addStretch()
        in_layout.addLayout(btn_row)

        left_layout.addWidget(grp_input)

        # Right panel: output
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

        grp_output = QGroupBox("输出区 — 密文 / 解密结果")
        out_layout = QVBoxLayout(grp_output)

        self._output_area = QTextEdit()
        self._output_area.setReadOnly(True)
        self._output_area.setPlaceholderText("加解密结果将显示在此处…")
        self._output_area.setMinimumHeight(180)
        out_layout.addWidget(self._output_area)

        self._output_info = QLabel("")
        self._output_info.setStyleSheet("color: gray; font-size: 12px;")
        out_layout.addWidget(self._output_info)

        out_btn_row = QHBoxLayout()

        btn_copy = QPushButton("📋 复制结果")
        btn_copy.clicked.connect(self._on_copy)
        out_btn_row.addWidget(btn_copy)

        btn_save = QPushButton("💾 保存到文件")
        btn_save.clicked.connect(self._on_save)
        out_btn_row.addWidget(btn_save)

        btn_clear_output = QPushButton("清空输出")
        btn_clear_output.clicked.connect(self._output_area.clear)
        out_btn_row.addWidget(btn_clear_output)

        out_btn_row.addStretch()
        out_layout.addLayout(out_btn_row)

        right_layout.addWidget(grp_output)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([500, 500])

        layout.addWidget(splitter)

    # ── actions ──────────────────────────────────────────────

    def _on_encrypt(self):
        key = self._get_key()
        if key is None:
            QMessageBox.warning(self, "错误", "请先生成密钥（工具栏 → 生成密钥）")
            return
        plain = self._input_area.toPlainText()
        if not plain:
            self._output_area.setPlainText("[错误] 请在左侧输入区域输入待加密的文本")
            return
        try:
            result = self._cipher.encrypt(plain, key)
            self._output_area.setPlainText(result)
            plain_bytes = len(plain.encode("utf-8"))
            self._output_info.setText(
                f"加密成功 — 明文 {plain_bytes} 字节 → "
                f"密文 {len(result) // 2} 字节 ({len(result)} hex 字符，含 32 字符 IV + 密体)"
            )
        except Exception as e:
            self._output_area.setPlainText(f"加密失败: {e}")

    def _on_decrypt(self):
        key = self._get_key()
        if key is None:
            QMessageBox.warning(self, "错误", "请先生成密钥（工具栏 → 生成密钥）")
            return
        hex_in = self._input_area.toPlainText().strip()
        if not hex_in:
            self._output_area.setPlainText("[错误] 请在左侧输入区域粘贴十六进制密文")
            return
        try:
            result = self._cipher.decrypt(hex_in, key)
            self._output_area.setPlainText(result)
            self._output_info.setText(f"解密成功 — 还原明文 {len(result)} 字符 ({len(result.encode('utf-8'))} 字节)")
        except Exception as e:
            self._output_area.setPlainText(f"解密失败 (密钥是否正确？): {e}")

    def _on_import_txt(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择文本文件", "",
            "文本文件 (*.txt *.csv);;所有文件 (*)"
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                    self._input_area.setPlainText(content)
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
                paragraphs = []
                for p in doc.paragraphs:
                    if p.text.strip():
                        paragraphs.append(p.text)
                text = "\n".join(paragraphs)
                self._input_area.setPlainText(text)
            except ImportError:
                QMessageBox.warning(self, "缺少依赖", "需要 python-docx 库，请执行: pip install python-docx")
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
            QMessageBox.warning(self, "无内容", "请先执行加解密操作再保存")
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
                f"输入长度: {len(text)} 字符 / {len(text.encode('utf-8'))} 字节"
            )
        else:
            self._input_info.setText("")

    # ── public ──────────────────────────────────────────────

    def refresh_key_display(self):
        key = self._get_key()
        if key:
            self._key_label.setText(key.hex())
        else:
            self._key_label.setText("密钥未生成 — 请在工具栏点击'生成密钥'")
