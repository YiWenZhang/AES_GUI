# -*- coding: utf-8 -*-
from pathlib import Path
import os

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QTextEdit, QFrame, QMessageBox,
)
from typing import Callable

from .audit_log import AuditLogger
from .app_paths import REPORT_DIR
from .report_exporter import AcceptanceReportExporter, ReportContext


class AuditReportPage(QWidget):
    def __init__(
        self,
        audit_logger: AuditLogger,
        report_exporter: AcceptanceReportExporter,
        context_getter: Callable[[], ReportContext],
    ):
        super().__init__()
        self._audit_logger = audit_logger
        self._report_exporter = report_exporter
        self._get_context = context_getter
        self._last_report_path: Path | None = None
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

        title = QLabel("操作审计与验收报告")
        title.setStyleSheet("font-weight:bold; font-size:16px; color:#2c3e50;")
        card_layout.addWidget(title)

        desc = QLabel("记录注册、登录、文本/文件加解密和完整性校验操作，一键导出 HTML 验收测试报告。")
        desc.setStyleSheet("color:#909399; font-size:12px;")
        desc.setWordWrap(True)
        card_layout.addWidget(desc)

        btn_row = QHBoxLayout()
        btn_refresh = QPushButton("刷新审计日志")
        btn_refresh.setObjectName("normalBtn")
        btn_refresh.clicked.connect(self.refresh)
        btn_row.addWidget(btn_refresh)

        btn_export = QPushButton("导出验收测试报告")
        btn_export.setObjectName("primaryBtn")
        btn_export.clicked.connect(self._on_export_report)
        btn_row.addWidget(btn_export)

        btn_open = QPushButton("打开报告文件夹")
        btn_open.setObjectName("normalBtn")
        btn_open.clicked.connect(self._on_open_report_folder)
        btn_row.addWidget(btn_open)
        btn_row.addStretch()
        card_layout.addLayout(btn_row)

        self._log_view = QTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setMinimumHeight(180)
        card_layout.addWidget(self._log_view, 1)

        self._status = QLabel("")
        self._status.setStyleSheet("color:#909399; font-size:12px;")
        card_layout.addWidget(self._status)

        layout.addWidget(card)
        self.refresh()

    def refresh(self):
        entries = self._audit_logger.read_recent(120)
        if not entries:
            self._log_view.setPlainText("暂无审计记录。")
            self._status.setText(f"日志文件: {self._audit_logger.log_path}")
            return

        lines: list[str] = []
        for entry in reversed(entries):
            lines.append(
                f"[{entry.timestamp}] {entry.user} · {entry.action} · {entry.status}\n"
                f"  说明: {entry.message}"
            )
            if entry.input_path:
                lines.append(f"  输入: {entry.input_path}")
            if entry.output_path:
                lines.append(f"  输出: {entry.output_path}")
            if entry.input_sha256:
                lines.append(f"  输入 SHA-256: {entry.input_sha256}")
            if entry.output_sha256:
                lines.append(f"  输出 SHA-256: {entry.output_sha256}")
            lines.append("")
        self._log_view.setPlainText("\n".join(lines))
        self._status.setText(f"共显示最近 {len(entries)} 条记录 · 日志文件: {self._audit_logger.log_path}")

    def _on_export_report(self):
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        default = REPORT_DIR / "AES验收测试报告.html"
        path, _ = QFileDialog.getSaveFileName(
            self, "导出验收测试报告", str(default), "HTML 报告 (*.html);;所有文件 (*)"
        )
        if not path:
            return
        try:
            report_path = self._report_exporter.export_html(path, self._get_context())
            self._last_report_path = report_path
            self._status.setText(f"报告已导出: {report_path}")
            QMessageBox.information(self, "导出成功", f"验收测试报告已导出：\n{report_path}")
        except Exception as e:
            QMessageBox.warning(self, "导出失败", str(e))

    def _on_open_report_folder(self):
        folder = self._last_report_path.parent if self._last_report_path else REPORT_DIR
        folder.mkdir(parents=True, exist_ok=True)
        os.startfile(folder)
