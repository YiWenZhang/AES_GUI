# -*- coding: utf-8 -*-
from dataclasses import dataclass, asdict, field
from datetime import datetime
import json
from pathlib import Path
from typing import Any


@dataclass
class AuditEntry:
    timestamp: str
    user: str
    action: str
    status: str
    message: str
    input_path: str = ""
    output_path: str = ""
    input_sha256: str = ""
    output_sha256: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class AuditLogger:
    def __init__(self, log_path: str | Path):
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def log_path(self) -> Path:
        return self._log_path

    def append(
        self,
        action: str,
        status: str,
        message: str,
        user: str = "未登录",
        input_path: str = "",
        output_path: str = "",
        input_sha256: str = "",
        output_sha256: str = "",
        extra: dict[str, Any] | None = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            user=user or "未登录",
            action=action,
            status=status,
            message=message,
            input_path=input_path,
            output_path=output_path,
            input_sha256=input_sha256,
            output_sha256=output_sha256,
            extra=extra or {},
        )
        with self._log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        return entry

    def read_recent(self, limit: int = 100) -> list[AuditEntry]:
        if not self._log_path.exists():
            return []

        lines = self._log_path.read_text(encoding="utf-8").splitlines()
        entries: list[AuditEntry] = []
        for line in lines[-limit:]:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                entries.append(AuditEntry(**data))
            except Exception:
                continue
        return entries

    def clear(self) -> None:
        self._log_path.write_text("", encoding="utf-8")
