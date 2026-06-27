# -*- coding: utf-8 -*-
"""
FileCipherPage — file encryption / decryption.
"""

import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QLabel, QFileDialog, QTextEdit,
    QProgressBar, QFrame, QMessageBox,
)
from typing import Callable

from .file_cipher import FileCipher


class FileCipherPage(QWidget):
    def __init__(self, cipher: FileCipher, key_getter: Callable[[], bytes | None]):
        super().__init__()
        self._cipher = cipher
        self._get_key = key_getter
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

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
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(14)

        title = QLabel("文件加解密操作")
        title.setStyleSheet("font-weight:bold; font-size:16px; color:#2c3e50;")
        card_layout.addWidget(title)

        # Input
        r1 = QHBoxLayout()
        r1.addWidget(QLabel("源文件"))
        self._input_path = QLineEdit()
        self._input_path.setPlaceholderText("选择要加密/解密的文件…")
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

        r3.addStretch()

        btn_open = QPushButton("打开输出文件夹")
        btn_open.setObjectName("normalBtn")
        btn_open.clicked.connect(self._on_open_folder)
        r3.addWidget(btn_open)
        card_layout.addLayout(r3)

        # Progress
        self._progress = QProgressBar()
        self._progress.setVisible(False)
        card_layout.addWidget(self._progress)

        # Log
        card_layout.addWidget(QLabel("操作日志"))
        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setMinimumHeight(160)
        card_layout.addWidget(self._log)

        layout.addWidget(card)
        layout.addStretch()

    def _on_browse_input(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*)")
        if path:
            self._input_path.setText(path)
            if not self._output_path.text():
                is_enc = not path.lower().endswith(".enc")
                self._output_path.setText(
                    FileCipher.suggest_output_path(path, for_encrypt=is_enc))

    def _on_browse_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "选择输出文件", "")
        if path:
            self._output_path.setText(path)

    def _on_encrypt(self):
        key = self._get_key()
        if key is None:
            QMessageBox.warning(self, "错误", "请先生成密钥")
            return
        in_path = self._input_path.text().strip()
        if not in_path or not os.path.isfile(in_path):
            QMessageBox.warning(self, "错误", "源文件不存在")
            return
        out_path = self._output_path.text().strip() or \
                   FileCipher.suggest_output_path(in_path, for_encrypt=True)
        try:
            in_sz = os.path.getsize(in_path)
            self._progress.setVisible(True)
            self._progress.setValue(30)
            ok = self._cipher.encrypt(in_path, out_path, key)
            self._progress.setValue(100)
            if ok:
                out_sz = os.path.getsize(out_path)
                self._log.append(
                    f"[✓] 加密完成\n"
                    f"    源: {in_path} ({in_sz:,} bytes)\n"
                    f"    出: {out_path} ({out_sz:,} bytes)"
                )
                QMessageBox.information(self, "成功", f"文件加密完成！\n{out_path}")
            else:
                self._log.append("[✗] 加密失败")
        except Exception as e:
            self._log.append(f"[✗] {e}")
        finally:
            self._progress.setVisible(False)

    def _on_decrypt(self):
        key = self._get_key()
        if key is None:
            QMessageBox.warning(self, "错误", "请先生成密钥")
            return
        in_path = self._input_path.text().strip()
        if not in_path or not os.path.isfile(in_path):
            QMessageBox.warning(self, "错误", "源文件不存在")
            return
        out_path = self._output_path.text().strip() or \
                   FileCipher.suggest_output_path(in_path, for_encrypt=False)
        try:
            in_sz = os.path.getsize(in_path)
            self._progress.setVisible(True)
            self._progress.setValue(30)
            ok = self._cipher.decrypt(in_path, out_path, key)
            self._progress.setValue(100)
            if ok:
                out_sz = os.path.getsize(out_path)
                self._log.append(
                    f"[✓] 解密完成\n"
                    f"    源: {in_path} ({in_sz:,} bytes)\n"
                    f"    出: {out_path} ({out_sz:,} bytes)"
                )
                QMessageBox.information(self, "成功", f"文件解密完成！\n{out_path}")
            else:
                self._log.append("[✗] 解密失败 — 密钥是否正确？")
        except Exception as e:
            self._log.append(f"[✗] {e}")
        finally:
            self._progress.setVisible(False)

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
