"""Theme stylesheets for the GUI.

Supports multiple themes: dark (default), light, blue, and green.
"""
from __future__ import annotations

THEMES: dict[str, str] = {}

DARK_QSS = """
* { font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; font-size: 13px; }
QMainWindow, QWidget { background: #1d1f23; color: #e6e6e6; }
QLineEdit, QTextEdit, QPlainTextEdit {
    background: #14161a; color: #e6e6e6;
    border: 1px solid #2c2f36; border-radius: 6px; padding: 6px;
    selection-background-color: #6f7cff;
}
QPushButton {
    background: #2c2f36; color: #e6e6e6; border: 1px solid #3a3e47;
    padding: 6px 12px; border-radius: 6px;
}
QPushButton:hover { background: #353a44; }
QPushButton:pressed { background: #6f7cff; color: #fff; }
QPushButton#primary {
    background: #6f7cff; color: #fff; border: 1px solid #6f7cff;
}
QPushButton#primary:hover { background: #8995ff; }
QTableView {
    background: #14161a; color: #e6e6e6; gridline-color: #2c2f36;
    border: 1px solid #2c2f36; border-radius: 6px;
    selection-background-color: #6f7cff; selection-color: #fff;
}
QHeaderView::section {
    background: #20232a; color: #c0c4ce; border: 0; padding: 6px;
}
QLabel#title { font-size: 18px; font-weight: 600; }
QLabel#subtitle { color: #9aa0ac; }
QLabel.severity-critical { color: #ff5d5d; font-weight: 600; }
QLabel.severity-high { color: #ff9a3d; font-weight: 600; }
QSplitter::handle { background: #2c2f36; }
QStatusBar { background: #14161a; color: #9aa0ac; }
QComboBox {
    background: #14161a; color: #e6e6e6; border: 1px solid #2c2f36;
    border-radius: 6px; padding: 4px 8px;
}
QGroupBox {
    border: 1px solid #2c2f36; border-radius: 6px;
    margin-top: 14px; padding: 8px;
}
QGroupBox::title { color: #9aa0ac; subcontrol-origin: margin; left: 10px; padding: 0 4px; }
QMenuBar { background: #1d1f23; color: #e6e6e6; }
QMenuBar::item:selected { background: #2c2f36; }
QMenu { background: #1d1f23; color: #e6e6e6; border: 1px solid #2c2f36; }
QMenu::item:selected { background: #6f7cff; }
"""
THEMES["dark"] = DARK_QSS

LIGHT_QSS = """
* { font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; font-size: 13px; }
QMainWindow, QWidget { background: #f5f5f5; color: #333333; }
QLineEdit, QTextEdit, QPlainTextEdit {
    background: #ffffff; color: #333333;
    border: 1px solid #cccccc; border-radius: 6px; padding: 6px;
    selection-background-color: #0078d4;
}
QPushButton {
    background: #e1e1e1; color: #333333; border: 1px solid #acacac;
    padding: 6px 12px; border-radius: 6px;
}
QPushButton:hover { background: #d0d0d0; }
QPushButton:pressed { background: #0078d4; color: #fff; }
QPushButton#primary {
    background: #0078d4; color: #fff; border: 1px solid #0078d4;
}
QPushButton#primary:hover { background: #1a8ae8; }
QTableView {
    background: #ffffff; color: #333333; gridline-color: #e0e0e0;
    border: 1px solid #cccccc; border-radius: 6px;
    selection-background-color: #0078d4; selection-color: #fff;
}
QHeaderView::section {
    background: #e8e8e8; color: #333333; border: 0; padding: 6px;
}
QLabel#title { font-size: 18px; font-weight: 600; }
QLabel#subtitle { color: #666666; }
QLabel.severity-critical { color: #d32f2f; font-weight: 600; }
QLabel.severity-high { color: #f57c00; font-weight: 600; }
QSplitter::handle { background: #cccccc; }
QStatusBar { background: #e8e8e8; color: #666666; }
QComboBox {
    background: #ffffff; color: #333333; border: 1px solid #cccccc;
    border-radius: 6px; padding: 4px 8px;
}
QGroupBox {
    border: 1px solid #cccccc; border-radius: 6px;
    margin-top: 14px; padding: 8px;
}
QGroupBox::title { color: #666666; subcontrol-origin: margin; left: 10px; padding: 0 4px; }
QMenuBar { background: #f5f5f5; color: #333333; }
QMenuBar::item:selected { background: #e1e1e1; }
QMenu { background: #f5f5f5; color: #333333; border: 1px solid #cccccc; }
QMenu::item:selected { background: #0078d4; }
"""
THEMES["light"] = LIGHT_QSS

BLUE_QSS = """
* { font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; font-size: 13px; }
QMainWindow, QWidget { background: #1a2332; color: #e0e0e0; }
QLineEdit, QTextEdit, QPlainTextEdit {
    background: #0d1821; color: #e0e0e0;
    border: 1px solid #2a4a6b; border-radius: 6px; padding: 6px;
    selection-background-color: #3d85c6;
}
QPushButton {
    background: #2a4a6b; color: #e0e0e0; border: 1px solid #3d6a9e;
    padding: 6px 12px; border-radius: 6px;
}
QPushButton:hover { background: #3d6a9e; }
QPushButton:pressed { background: #3d85c6; color: #fff; }
QPushButton#primary {
    background: #3d85c6; color: #fff; border: 1px solid #3d85c6;
}
QPushButton#primary:hover { background: #5a9fd4; }
QTableView {
    background: #0d1821; color: #e0e0e0; gridline-color: #2a4a6b;
    border: 1px solid #2a4a6b; border-radius: 6px;
    selection-background-color: #3d85c6; selection-color: #fff;
}
QHeaderView::section {
    background: #1a3a5c; color: #b0c4de; border: 0; padding: 6px;
}
QLabel#title { font-size: 18px; font-weight: 600; }
QLabel#subtitle { color: #7a9cc6; }
QLabel.severity-critical { color: #ff6b6b; font-weight: 600; }
QLabel.severity-high { color: #ffa94d; font-weight: 600; }
QSplitter::handle { background: #2a4a6b; }
QStatusBar { background: #0d1821; color: #7a9cc6; }
QComboBox {
    background: #0d1821; color: #e0e0e0; border: 1px solid #2a4a6b;
    border-radius: 6px; padding: 4px 8px;
}
QGroupBox {
    border: 1px solid #2a4a6b; border-radius: 6px;
    margin-top: 14px; padding: 8px;
}
QGroupBox::title { color: #7a9cc6; subcontrol-origin: margin; left: 10px; padding: 0 4px; }
QMenuBar { background: #1a2332; color: #e0e0e0; }
QMenuBar::item:selected { background: #2a4a6b; }
QMenu { background: #1a2332; color: #e0e0e0; border: 1px solid #2a4a6b; }
QMenu::item:selected { background: #3d85c6; }
"""
THEMES["blue"] = BLUE_QSS

GREEN_QSS = """
* { font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; font-size: 13px; }
QMainWindow, QWidget { background: #1a2e1a; color: #d4e6d4; }
QLineEdit, QTextEdit, QPlainTextEdit {
    background: #0f1f0f; color: #d4e6d4;
    border: 1px solid #2d5a2d; border-radius: 6px; padding: 6px;
    selection-background-color: #4caf50;
}
QPushButton {
    background: #2d5a2d; color: #d4e6d4; border: 1px solid #3d7a3d;
    padding: 6px 12px; border-radius: 6px;
}
QPushButton:hover { background: #3d7a3d; }
QPushButton:pressed { background: #4caf50; color: #fff; }
QPushButton#primary {
    background: #4caf50; color: #fff; border: 1px solid #4caf50;
}
QPushButton#primary:hover { background: #66bb6a; }
QTableView {
    background: #0f1f0f; color: #d4e6d4; gridline-color: #2d5a2d;
    border: 1px solid #2d5a2d; border-radius: 6px;
    selection-background-color: #4caf50; selection-color: #fff;
}
QHeaderView::section {
    background: #1a3a1a; color: #a8c8a8; border: 0; padding: 6px;
}
QLabel#title { font-size: 18px; font-weight: 600; }
QLabel#subtitle { color: #7a9a7a; }
QLabel.severity-critical { color: #ff6b6b; font-weight: 600; }
QLabel.severity-high { color: #ffa94d; font-weight: 600; }
QSplitter::handle { background: #2d5a2d; }
QStatusBar { background: #0f1f0f; color: #7a9a7a; }
QComboBox {
    background: #0f1f0f; color: #d4e6d4; border: 1px solid #2d5a2d;
    border-radius: 6px; padding: 4px 8px;
}
QGroupBox {
    border: 1px solid #2d5a2d; border-radius: 6px;
    margin-top: 14px; padding: 8px;
}
QGroupBox::title { color: #7a9a7a; subcontrol-origin: margin; left: 10px; padding: 0 4px; }
QMenuBar { background: #1a2e1a; color: #d4e6d4; }
QMenuBar::item:selected { background: #2d5a2d; }
QMenu { background: #1a2e1a; color: #d4e6d4; border: 1px solid #2d5a2d; }
QMenu::item:selected { background: #4caf50; }
"""
THEMES["green"] = GREEN_QSS

MONOKAI_QSS = """
* { font-family: "Consolas", "Monaco", "Courier New", monospace; font-size: 13px; }
QMainWindow, QWidget { background: #272822; color: #f8f8f2; }
QLineEdit, QTextEdit, QPlainTextEdit {
    background: #1e1f1c; color: #f8f8f2;
    border: 1px solid #49483e; border-radius: 6px; padding: 6px;
    selection-background-color: #75715e;
}
QPushButton {
    background: #49483e; color: #f8f8f2; border: 1px solid #75715e;
    padding: 6px 12px; border-radius: 6px;
}
QPushButton:hover { background: #75715e; }
QPushButton:pressed { background: #a6e22e; color: #272822; }
QPushButton#primary {
    background: #a6e22e; color: #272822; border: 1px solid #a6e22e;
}
QPushButton#primary:hover { background: #c8e84c; }
QTableView {
    background: #1e1f1c; color: #f8f8f2; gridline-color: #49483e;
    border: 1px solid #49483e; border-radius: 6px;
    selection-background-color: #75715e; selection-color: #f8f8f2;
}
QHeaderView::section {
    background: #3e3d32; color: #a6a68a; border: 0; padding: 6px;
}
QLabel#title { font-size: 18px; font-weight: 600; }
QLabel#subtitle { color: #75715e; }
QLabel.severity-critical { color: #f92672; font-weight: 600; }
QLabel.severity-high { color: #fd971f; font-weight: 600; }
QSplitter::handle { background: #49483e; }
QStatusBar { background: #1e1f1c; color: #75715e; }
QComboBox {
    background: #1e1f1c; color: #f8f8f2; border: 1px solid #49483e;
    border-radius: 6px; padding: 4px 8px;
}
QGroupBox {
    border: 1px solid #49483e; border-radius: 6px;
    margin-top: 14px; padding: 8px;
}
QGroupBox::title { color: #75715e; subcontrol-origin: margin; left: 10px; padding: 0 4px; }
QMenuBar { background: #272822; color: #f8f8f2; }
QMenuBar::item:selected { background: #49483e; }
QMenu { background: #272822; color: #f8f8f2; border: 1px solid #49483e; }
QMenu::item:selected { background: #a6e22e; }
"""
THEMES["monokai"] = MONOKAI_QSS


def get_theme(name: str) -> str:
    """Get theme stylesheet by name."""
    return THEMES.get(name, DARK_QSS)


def get_available_themes() -> list[str]:
    """Get list of available theme names."""
    return list(THEMES.keys())


# For backward compatibility
DARK_QSS = THEMES["dark"]
