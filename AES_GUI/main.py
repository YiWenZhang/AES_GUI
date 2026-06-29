# -*- coding: utf-8 -*-
"""
AES GUI — main entry point.
Run: python main.py
"""

import ctypes
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFont, QIcon

from src.main_window import MainWindow


APP_ID = "AES.GUI.EncryptionTool"


def _resource_path(relative_path: str) -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "_internal" / relative_path
    return Path(__file__).resolve().parent / relative_path


def _set_windows_app_id():
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except Exception:
        pass


def main():
    _set_windows_app_id()
    app = QApplication(sys.argv)

    icon_path = _resource_path("assets/aes-logo.ico")
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    # default Chinese-friendly font
    font = QFont("Microsoft YaHei", 10)
    app.setFont(font)

    window = MainWindow()
    if icon_path.exists():
        window.setWindowIcon(QIcon(str(icon_path)))
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
