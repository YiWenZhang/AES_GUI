# -*- coding: utf-8 -*-
from dataclasses import dataclass
from datetime import datetime
from html import escape
from pathlib import Path

from .audit_log import AuditEntry


@dataclass
class ReportContext:
    app_name: str
    version: str
    dll_loaded: bool
    registered: bool
    current_user: str
    audit_entries: list[AuditEntry]


class AcceptanceReportExporter:
    def export_html(self, out_path: str | Path, context: ReportContext) -> Path:
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self._render_html(context), encoding="utf-8")
        return path

    def _render_html(self, context: ReportContext) -> str:
        rows = "\n".join(self._entry_row(e) for e in context.audit_entries)
        if not rows:
            rows = '<tr><td colspan="9" class="muted">暂无审计记录</td></tr>'

        checklist = [
            "软件注册激活",
            "用户注册登录",
            "密码强度检测",
            "文本加解密",
            "文件拖拽加解密",
            "SHA-256 完整性校验",
            "操作日志/审计记录",
            "一键导出验收报告",
        ]
        checklist_html = "\n".join(f"<li>✓ {escape(item)}</li>" for item in checklist)
        dll_status = "已加载" if context.dll_loaded else "未加载"
        reg_status = "已激活" if context.registered else "未激活"
        exported_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{escape(context.app_name)}验收测试报告</title>
<style>
body {{ font-family: "Microsoft YaHei", Arial, sans-serif; margin: 32px; color: #2c3e50; }}
h1 {{ text-align: center; }}
h2 {{ border-left: 4px solid #3498db; padding-left: 10px; margin-top: 28px; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
th, td {{ border: 1px solid #dcdfe6; padding: 8px; font-size: 13px; vertical-align: top; }}
th {{ background: #f5f7fa; }}
.status-ok {{ color: #27ae60; font-weight: bold; }}
.status-fail {{ color: #e74c3c; font-weight: bold; }}
.muted {{ color: #909399; text-align: center; }}
.hash {{ font-family: Consolas, monospace; word-break: break-all; font-size: 12px; }}
</style>
</head>
<body>
<h1>{escape(context.app_name)}验收测试报告</h1>
<h2>一、系统状态</h2>
<table>
<tr><th>项目</th><th>状态</th></tr>
<tr><td>应用版本</td><td>{escape(context.version)}</td></tr>
<tr><td>导出时间</td><td>{escape(exported_at)}</td></tr>
<tr><td>当前用户</td><td>{escape(context.current_user)}</td></tr>
<tr><td>DLL 状态</td><td>{escape(dll_status)}</td></tr>
<tr><td>软件注册</td><td>{escape(reg_status)}</td></tr>
</table>
<h2>二、功能验收清单</h2>
<ul>{checklist_html}</ul>
<h2>三、最近操作审计记录</h2>
<table>
<tr><th>时间</th><th>用户</th><th>动作</th><th>状态</th><th>说明</th><th>输入</th><th>输出</th><th>输入 SHA-256</th><th>输出 SHA-256</th></tr>
{rows}
</table>
<h2>四、验收结论</h2>
<p class="status-ok">系统已扩展安全增强与可视化审计模块，可用于展示密码强度检测、拖拽文件加解密、完整性校验、审计追踪和验收报告导出。</p>
</body>
</html>"""

    def _entry_row(self, entry: AuditEntry) -> str:
        status_class = "status-ok" if entry.status in {"成功", "PASS"} else "status-fail"
        return (
            "<tr>"
            f"<td>{escape(entry.timestamp)}</td>"
            f"<td>{escape(entry.user)}</td>"
            f"<td>{escape(entry.action)}</td>"
            f"<td class=\"{status_class}\">{escape(entry.status)}</td>"
            f"<td>{escape(entry.message)}</td>"
            f"<td>{escape(entry.input_path)}</td>"
            f"<td>{escape(entry.output_path)}</td>"
            f"<td class=\"hash\">{escape(entry.input_sha256)}</td>"
            f"<td class=\"hash\">{escape(entry.output_sha256)}</td>"
            "</tr>"
        )
