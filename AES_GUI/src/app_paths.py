# -*- coding: utf-8 -*-
from pathlib import Path
import sys


def _project_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


PROJECT_ROOT = _project_root()
LOG_DIR = PROJECT_ROOT / "logs"
REPORT_DIR = PROJECT_ROOT / "reports"
AUDIT_LOG_PATH = LOG_DIR / "audit.jsonl"
