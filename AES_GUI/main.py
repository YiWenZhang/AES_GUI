# -*- coding: utf-8 -*-
"""
AES GUI — main entry point.
Run: python main.py
"""

import sys
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFont

from src.main_window import MainWindow


def main():
    app = QApplication(sys.argv)

    # default Chinese-friendly font
    font = QFont("Microsoft YaHei", 10)
    app.setFont(font)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
