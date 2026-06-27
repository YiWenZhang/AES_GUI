# -*- coding: utf-8 -*-
"""
FileCipherTab — file encryption / decryption UI.
"""

import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLineEdit, QPushButton, QLabel, QFileDialog, QTextEdit,
    QProgressBar, QMessageBox,
)
from PySide6.QtCore import Qt
from typing import Callable

from .file_cipher import FileCipher


class FileCipherTab(QWidget):
    def __init__(self, cipher: FileCipher, key_getter: Callable[[], bytes | None]):
        super().__init__()
        self._cipher = cipher
        self._get_key = key_getter
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        # ── Key display ──
        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("当前密钥:"))
        self._key_label = QLineEdit()
        self._key_label.setReadOnly(True)
        self._key_label.setPlaceholderText("加载 DLL 后自动生成")
        key_row.addWidget(self._key_label)
        layout.addLayout(key_row)

        grp = QGroupBox("文件加解密操作")
        grp_layout = QVBoxLayout(grp)

        # ── Input file ──
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("源文件:"))
        self._input_path = QLineEdit()
        self._input_path.setPlaceholderText("选择或拖放要加密/解密的文件…")
        row1.addWidget(self._input_path)
        btn_browse_in = QPushButton("浏览…")
        btn_browse_in.clicked.connect(self._on_browse_input)
        row1.addWidget(btn_browse_in)
        grp_layout.addLayout(row1)

        # ── Output file ──
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("输出文件:"))
        self._output_path = QLineEdit()
        self._output_path.setPlaceholderText("自动生成或手动选择输出路径…")
        row2.addWidget(self._output_path)
        btn_browse_out = QPushButton("浏览…")
        btn_browse_out.clicked.connect(self._on_browse_output)
        row2.addWidget(btn_browse_out)
        grp_layout.addLayout(row2)

        # ── Action buttons ──
        row4 = QHBoxLayout()
        btn_encrypt = QPushButton("加密文件 🔒")
        btn_encrypt.setStyleSheet("font-weight: bold; padding: 6px 16px;")
        btn_encrypt.clicked.connect(self._on_encrypt)
        row4.addWidget(btn_encrypt)

        btn_decrypt = QPushButton("解密文件 🔓")
        btn_decrypt.setStyleSheet("font-weight: bold; padding: 6px 16px;")
        btn_decrypt.clicked.connect(self._on_decrypt)
        row4.addWidget(btn_decrypt)

        row4.addStretch()

        btn_open_out = QPushButton("打开输出文件夹")
        btn_open_out.clicked.connect(self._on_open_output_folder)
        row4.addWidget(btn_open_out)

        grp_layout.addLayout(row4)

        # ── Progress ──
        self._progress = QProgressBar()
        self._progress.setVisible(False)
        grp_layout.addWidget(self._progress)

        # ── Log ──
        grp_layout.addWidget(QLabel("操作日志:"))
        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setMinimumHeight(150)
        grp_layout.addWidget(self._log)

        layout.addWidget(grp)
        layout.addStretch()

    def _on_browse_input(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择文件", "", "所有文件 (*)"
        )
        if path:
            self._input_path.setText(path)
            if not self._output_path.text():
                is_enc = not path.lower().endswith(".enc")
                self._output_path.setText(
                    FileCipher.suggest_output_path(path, for_encrypt=is_enc)
                )

    def _on_browse_output(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "选择输出文件", ""
        )
        if path:
            self._output_path.setText(path)

    def _on_encrypt(self):
        key = self._get_key()
        if key is None:
            QMessageBox.warning(self, "错误", "请先生成密钥（工具栏 → 生成密钥）")
            return
        in_path = self._input_path.text().strip()
        if not in_path or not os.path.isfile(in_path):
            QMessageBox.warning(self, "错误", "源文件不存在，请先选择文件")
            return
        out_path = self._output_path.text().strip() or \
                   FileCipher.suggest_output_path(in_path, for_encrypt=True)

        try:
            in_size = os.path.getsize(in_path)
            self._progress.setVisible(True)
            self._progress.setValue(30)
            ok = self._cipher.encrypt(in_path, out_path, key)
            self._progress.setValue(100)
            if ok:
                out_size = os.path.getsize(out_path)
                self._log.append(
                    f"[✓] 加密完成\n"
                    f"    源文件: {in_path} ({in_size:,} bytes)\n"
                    f"    输出文件: {out_path} ({out_size:,} bytes, +16 bytes IV)\n"
                )
                QMessageBox.information(self, "加密成功",
                    f"文件加密完成！\n输出: {out_path}")
            else:
                self._log.append("[✗] 加密失败 — DLL 返回错误")
                QMessageBox.warning(self, "加密失败", "DLL 加密操作返回失败")
        except Exception as e:
            self._log.append(f"[✗] 加密异常: {e}")
            QMessageBox.warning(self, "加密异常", str(e))
        finally:
            self._progress.setVisible(False)

    def _on_decrypt(self):
        key = self._get_key()
        if key is None:
            QMessageBox.warning(self, "错误", "请先生成密钥（工具栏 → 生成密钥）")
            return
        in_path = self._input_path.text().strip()
        if not in_path or not os.path.isfile(in_path):
            QMessageBox.warning(self, "错误", "源文件不存在，请先选择文件")
            return
        out_path = self._output_path.text().strip() or \
                   FileCipher.suggest_output_path(in_path, for_encrypt=False)

        try:
            in_size = os.path.getsize(in_path)
            self._progress.setVisible(True)
            self._progress.setValue(30)
            ok = self._cipher.decrypt(in_path, out_path, key)
            self._progress.setValue(100)
            if ok:
                out_size = os.path.getsize(out_path)
                self._log.append(
                    f"[✓] 解密完成\n"
                    f"    密文文件: {in_path} ({in_size:,} bytes)\n"
                    f"    还原文件: {out_path} ({out_size:,} bytes)\n"
                )
                QMessageBox.information(self, "解密成功",
                    f"文件解密完成！\n输出: {out_path}")
            else:
                self._log.append("[✗] 解密失败 — 密钥是否正确？文件是否完整？")
                QMessageBox.warning(self, "解密失败", "DLL 解密操作返回失败，请检查密钥和文件")
        except Exception as e:
            self._log.append(f"[✗] 解密异常: {e}")
            QMessageBox.warning(self, "解密异常", str(e))
        finally:
            self._progress.setVisible(False)

    def _on_open_output_folder(self):
        out_path = self._output_path.text().strip()
        if out_path:
            folder = os.path.dirname(out_path)
            if folder and os.path.isdir(folder):
                os.startfile(folder)
            elif os.path.isfile(out_path):
                os.startfile(os.path.dirname(os.path.abspath(out_path)))

    # ── public ──────────────────────────────────────────────

    def refresh_key_display(self):
        key = self._get_key()
        if key:
            self._key_label.setText(key.hex())
        else:
            self._key_label.setText("密钥未生成 — 请在工具栏点击'生成密钥'")
