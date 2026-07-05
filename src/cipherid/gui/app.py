"""PySide6 main window for CipherID.

Three-pane layout:
  - top:    input box + flag-format field + Identify / Auto-decode buttons
  - middle: ranked candidate table (confidence, category, name, key)
  - bottom: decoded preview + chain (when auto-decoding)
"""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QAction, QGuiApplication
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cipherid import __version__
from cipherid.cipher import Candidate
from cipherid.engine import DecodeResult, Engine, IdentifyResult
from cipherid.gui.theme import DARK_QSS
from cipherid.image import (
    IMAGE_SUFFIXES,
    ExtractedItem,
    backend_status,
    extract_from_image,
    is_image_path,
)


class ImageExtractWorker(QThread):
    finished = Signal(list)

    def __init__(self, path: str, ocr: bool = True) -> None:
        super().__init__()
        self.path = path
        self.ocr = ocr

    def run(self) -> None:
        try:
            items = extract_from_image(self.path, ocr=self.ocr)
        except Exception:
            items = []
        self.finished.emit(items)


class IdentifyWorker(QThread):
    finished = Signal(object)

    def __init__(self, text: str, flag_format: str | None) -> None:
        super().__init__()
        self.text = text
        self.flag_format = flag_format
        self.engine = Engine()

    def run(self) -> None:
        result = self.engine.identify(self.text, flag_format=self.flag_format)
        self.finished.emit(result)


class AutoDecodeWorker(QThread):
    finished = Signal(object)

    def __init__(self, text: str, flag_format: str | None) -> None:
        super().__init__()
        self.text = text
        self.flag_format = flag_format
        self.engine = Engine()

    def run(self) -> None:
        result = self.engine.auto_decode(self.text, flag_format=self.flag_format)
        self.finished.emit(result)


class MainWindow(QMainWindow):
    CATEGORY_LABELS = {
        "encoding": "编码",
        "classical": "古典",
        "esoteric": "深奥",
        "hash": "哈希",
        "token": "令牌",
        "modern": "现代",
        "chinese": "中文",
    }

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"CipherID {__version__}")
        self.resize(1100, 720)
        self.setAcceptDrops(True)
        self._theme_actions: dict[str, QAction] = {}
        self._build_ui()
        self._build_menu()
        self.engine = Engine()
        self._worker: QThread | None = None
        self._populate_algorithms()

    # ------------- UI -------------

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(8)

        # Title
        title = QLabel("CipherID")
        title.setObjectName("title")
        subtitle = QLabel(
            "一键识别 / 解密 CTF 密码 · 支持文本、QR、条码、图片 OCR · "
            "One-click cipher identifier with QR, barcode & OCR"
        )
        subtitle.setObjectName("subtitle")
        root.addWidget(title)
        root.addWidget(subtitle)

        # Input group
        input_group = QGroupBox("输入 / Input")
        input_layout = QVBoxLayout(input_group)
        self.input_edit = QPlainTextEdit()
        self.input_edit.setPlaceholderText(
            "粘贴 / 拖入 密文 · 文件 · 图片（QR、条码、截图）…\n"
            "Paste, or drag-and-drop ciphertext / a file / an image (QR · barcode · screenshot)…"
        )
        self.input_edit.setMinimumHeight(110)
        input_layout.addWidget(self.input_edit)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Flag 格式:"))
        self.flag_format_edit = QLineEdit()
        self.flag_format_edit.setPlaceholderText("flag{}  CTF{}  或自定义正则")
        self.flag_format_edit.setFixedWidth(220)
        controls.addWidget(self.flag_format_edit)
        controls.addStretch(1)

        self.identify_btn = QPushButton("识别 Identify")
        self.identify_btn.setObjectName("primary")
        self.identify_btn.clicked.connect(self.run_identify)
        self.auto_btn = QPushButton("一键解密 Auto-decode")
        self.auto_btn.clicked.connect(self.run_auto)
        self.clear_btn = QPushButton("清空 Clear")
        self.clear_btn.clicked.connect(self._on_clear)
        controls.addWidget(self.identify_btn)
        controls.addWidget(self.auto_btn)
        controls.addWidget(self.clear_btn)
        input_layout.addLayout(controls)

        root.addWidget(input_group)

        # Encode / Decode group (separate from identification)
        encdec_group = QGroupBox("指定算法编码 / 解码  Encode / Decode")
        encdec_layout = QHBoxLayout(encdec_group)
        encdec_layout.addWidget(QLabel("算法:"))
        self.algo_combo = QComboBox()
        self.algo_combo.setFixedWidth(220)
        encdec_layout.addWidget(self.algo_combo)
        encdec_layout.addWidget(QLabel("密钥:"))
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("key (可选)")
        self.key_edit.setFixedWidth(160)
        encdec_layout.addWidget(self.key_edit)
        self.encode_btn = QPushButton("编码 Encode")
        self.encode_btn.clicked.connect(self.run_encode)
        self.decode_btn = QPushButton("解码 Decode")
        self.decode_btn.clicked.connect(self.run_decode)
        self.list_algo_btn = QPushButton("算法列表")
        self.list_algo_btn.clicked.connect(self._list_algorithms)
        encdec_layout.addWidget(self.encode_btn)
        encdec_layout.addWidget(self.decode_btn)
        encdec_layout.addWidget(self.list_algo_btn)
        encdec_layout.addStretch(1)
        root.addWidget(encdec_group)

        # Results splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        # Left: candidate table
        left = QGroupBox("候选 / Candidates")
        left_l = QVBoxLayout(left)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["置信度", "分类", "名称", "密钥", "备注"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self._on_select)
        left_l.addWidget(self.table)
        splitter.addWidget(left)

        # Right: preview
        right = QGroupBox("预览 / Preview")
        right_l = QVBoxLayout(right)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        right_l.addWidget(self.preview)
        preview_btns = QHBoxLayout()
        self.copy_btn = QPushButton("复制 Copy")
        self.copy_btn.clicked.connect(self._copy_preview)
        self.use_btn = QPushButton("当作新输入 Use as input")
        self.use_btn.clicked.connect(self._use_as_input)
        preview_btns.addWidget(self.copy_btn)
        preview_btns.addWidget(self.use_btn)
        preview_btns.addStretch(1)
        right_l.addLayout(preview_btns)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        root.addWidget(splitter, 1)

        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Ready")

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&文件 File")
        open_action = QAction("打开文件… Open file…", self)
        open_action.triggered.connect(self._open_file)
        open_action.setShortcut("Ctrl+O")
        file_menu.addAction(open_action)

        open_img_action = QAction("打开图片 (QR / 截图)… Open image…", self)
        open_img_action.triggered.connect(self._open_image)
        open_img_action.setShortcut("Ctrl+Shift+O")
        file_menu.addAction(open_img_action)

        paste_action = QAction("从剪贴板粘贴 Paste from clipboard", self)
        paste_action.triggered.connect(self._paste_clipboard)
        paste_action.setShortcut("Ctrl+Shift+V")
        file_menu.addAction(paste_action)

        file_menu.addSeparator()
        quit_action = QAction("退出 Quit", self)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        # Theme menu
        view_menu = self.menuBar().addMenu("&视图 View")
        theme_menu = view_menu.addMenu("主题 Theme")
        from cipherid.gui.theme import get_available_themes
        self._current_theme = "dark"
        for theme_name in get_available_themes():
            action = QAction(theme_name.capitalize(), self)
            action.setCheckable(True)
            action.setChecked(theme_name == self._current_theme)
            action.triggered.connect(lambda checked, t=theme_name: self._change_theme(t))
            theme_menu.addAction(action)
            self._theme_actions[theme_name] = action

        help_menu = self.menuBar().addMenu("&帮助 Help")
        about_action = QAction("关于 About", self)
        about_action.triggered.connect(self._about)
        help_menu.addAction(about_action)

    # ------------- actions -------------

    # Chinese display names for cipher IDs
    CIPHER_NAMES: dict[str, str] = {
        # encoding
        "base64": "Base64", "base64url": "Base64 URL安全", "base32": "Base32",
        "base16": "Base16 (十六进制)", "base85": "Base85", "ascii85": "ASCII85",
        "base58": "Base58", "base91": "Base91", "urlencode": "URL编码",
        "html": "HTML实体", "unicode_escape": "Unicode转义",
        "quoted_printable": "Quoted-printable", "morse": "摩尔斯电码",
        "binary": "二进制", "octal": "八进制", "decimal": "十进制字节流",
        "punycode": "Punycode", "a1z26": "A1Z26字母序号", "reverse": "反转字符串",
        "base62": "Base62", "base36": "Base36", "whitespace": "空白编码",
        "rot5": "ROT5", "rot18": "ROT18", "rot52": "ROT52",
        "xxencode": "XXencode", "z85": "Z85", "tapcode": "敲击码",
        "base32_crockford": "Base32 Crockford", "base32hex": "Base32 Hex",
        "ascii85_zmq": "ASCII85 ZeroMQ", "braille": "盲文",
        "semaphore": "旗语", "base45": "Base45", "pigpen": "猪圈密码",
        "uuencode": "UUencode",
        # classical
        "caesar": "凯撒", "rot13": "ROT13", "rot47": "ROT47",
        "atbash": "Atbash", "affine": "仿射", "vigenere": "维吉尼亚",
        "railfence": "栅栏", "bacon": "培根", "polybius": "Polybius",
        "beaufort": "Beaufort", "gronsfeld": "Gronsfeld", "autokey": "Autokey",
        "bifid": "Bifid", "nihilist": "Nihilist", "porta": "Porta",
        "playfair": "Playfair",         "scytale": "Scytale", "foursquare": "四方密码",
        "hill": "Hill矩阵", "columnar": "列置换",
        "route": "路线密码", "keyword_sub": "关键词替换",
        # esoteric
        "brainfuck": "Brainfuck",
        # hash
        "hash": "哈希计算", "crc32": "CRC32",
        # modern
        "xor": "XOR", "rc4": "RC4", "vigenere_autokey": "维吉尼亚Autokey",
        "hmac": "HMAC", "xor_multibrute": "XOR多字节爆破",
        "vigenere_plain_autokey": "维吉尼亚Autokey(明文)",
        # chinese
        "core_values": "社会主义核心价值观", "buddha": "与佛论禅",
        "pawnshop": "当铺密码", "ctc": "中文电码", "keyboard": "键盘密码",
        "wuxing": "五行密码",
    }

    def _populate_algorithms(self) -> None:
        """Fill the algorithm combo box with encodable ciphers."""
        engine = Engine()
        encodable = engine.get_encodable_ciphers()
        by_cat: dict[str, list[str]] = {}
        for c in encodable:
            by_cat.setdefault(c.category, []).append(c.id)
        self.algo_combo.clear()
        cat_labels = {
            "encoding": "编码", "classical": "古典", "chinese": "中文",
            "modern": "现代", "esoteric": "深奥", "hash": "哈希",
        }
        for cat in ["encoding", "classical", "chinese", "modern", "esoteric", "hash"]:
            if cat not in by_cat:
                continue
            label = cat_labels.get(cat, cat)
            for cid in by_cat[cat]:
                display = self.CIPHER_NAMES.get(cid, cid)
                self.algo_combo.addItem(f"[{label}] {display}", cid)

    def run_encode(self) -> None:
        text = self.input_edit.toPlainText()
        if not text.strip():
            self.status.showMessage("输入为空 / Input is empty", 3000)
            return
        algo = self.algo_combo.currentData()
        if not algo:
            self.status.showMessage("请选择算法 / Select an algorithm", 3000)
            return
        key = self.key_edit.text() or None
        engine = Engine()
        result = engine.encode_one(text, algo, key=key)
        if result is None:
            self.status.showMessage(f"编码失败 / encode failed: {algo}", 3000)
            return
        self.preview.setPlainText(result)
        self.status.showMessage(f"已编码 / Encoded with {algo}", 2000)

    def run_decode(self) -> None:
        text = self.input_edit.toPlainText()
        if not text.strip():
            self.status.showMessage("输入为空 / Input is empty", 3000)
            return
        algo = self.algo_combo.currentData()
        if not algo:
            self.status.showMessage("请选择算法 / Select an algorithm", 3000)
            return
        key = self.key_edit.text() or None
        engine = Engine()
        result = engine.decode_one(text, algo, key=key)
        if result is None:
            self.status.showMessage(f"解码失败 / decode failed: {algo}", 3000)
            return
        self.preview.setPlainText(result)
        self.status.showMessage(f"已解码 / Decoded with {algo}", 2000)

    def _list_algorithms(self) -> None:
        engine = Engine()
        encodable = engine.get_encodable_ciphers()
        lines = []
        cat_labels = {
            "encoding": "Encoding", "classical": "Classical", "chinese": "Chinese",
            "modern": "Modern", "esoteric": "Esoteric", "hash": "Hash",
        }
        by_cat: dict[str, list[str]] = {}
        for c in encodable:
            by_cat.setdefault(c.category, []).append(c.id)
        for cat in ["encoding", "classical", "chinese", "modern", "esoteric", "hash"]:
            if cat not in by_cat:
                continue
            label = cat_labels.get(cat, cat)
            lines.append(f"\n{label} ({len(by_cat[cat])})")
            lines.append("-" * 40)
            for cid in by_cat[cat]:
                lines.append(f"  {cid}")
        QMessageBox.information(self, "Encodable algorithms", "\n".join(lines))

    def run_identify(self) -> None:
        text = self.input_edit.toPlainText()
        if not text.strip():
            self.status.showMessage("输入为空 / Input is empty", 3000)
            return
        self._set_busy(True, "正在识别… Identifying…")
        self._worker = IdentifyWorker(text, self.flag_format_edit.text() or None)
        self._worker.finished.connect(self._on_identify_done)
        self._worker.start()

    def run_auto(self) -> None:
        text = self.input_edit.toPlainText()
        if not text.strip():
            self.status.showMessage("输入为空 / Input is empty", 3000)
            return
        self._set_busy(True, "正在自动解码… Auto-decoding…")
        self._worker = AutoDecodeWorker(text, self.flag_format_edit.text() or None)
        self._worker.finished.connect(self._on_auto_done)
        self._worker.start()

    def _set_busy(self, busy: bool, msg: str = "") -> None:
        self.identify_btn.setEnabled(not busy)
        self.auto_btn.setEnabled(not busy)
        if msg:
            self.status.showMessage(msg)

    def _on_identify_done(self, result: IdentifyResult) -> None:
        self._set_busy(False)
        self.table.setRowCount(0)
        for c in result.candidates[:50]:
            self._append_row(c)
        if result.flag:
            self.status.showMessage(f"识别到 Flag: {result.flag}")
        else:
            self.status.showMessage(
                f"共 {len(result.candidates)} 个候选 / {len(result.candidates)} candidates"
            )
        if self.table.rowCount():
            self.table.selectRow(0)

    def _on_auto_done(self, result: DecodeResult) -> None:
        self._set_busy(False)
        self.table.setRowCount(0)
        for c in result.chain:
            self._append_row(c)
        text = result.final_plaintext or ""
        if result.flag_match:
            self.preview.setPlainText(
                f"=== 命中 Flag: {result.flag_match} ===\n\n{text}"
            )
            self.status.showMessage(f"Flag: {result.flag_match}")
        else:
            self.preview.setPlainText(text)
            if result.chain:
                self.status.showMessage(
                    f"成功解码 {len(result.chain)} 层 / decoded {len(result.chain)} layers"
                )
            else:
                self.status.showMessage("未能自动解码 / could not auto-decode")

    def _append_row(self, c: Candidate) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        items = [
            QTableWidgetItem(f"{int(c.confidence*100)}%"),
            QTableWidgetItem(self.CATEGORY_LABELS.get(c.category, c.category)),
            QTableWidgetItem(c.name),
            QTableWidgetItem(c.key or ""),
            QTableWidgetItem(c.notes or ""),
        ]
        for col, item in enumerate(items):
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, col, item)
        # stash decoded text on the row for the preview
        self.table.item(row, 0).setData(Qt.ItemDataRole.UserRole, c.decoded or "")

    def _on_select(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        decoded = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole) or ""
        if decoded:
            self.preview.setPlainText(decoded)
        else:
            self.preview.setPlainText(
                "(无可解码内容 — 这个识别器只识别不解密 / "
                "no decoded payload — identification-only)"
            )

    def _copy_preview(self) -> None:
        QGuiApplication.clipboard().setText(self.preview.toPlainText())
        self.status.showMessage("已复制 / Copied", 2000)

    def _use_as_input(self) -> None:
        self.input_edit.setPlainText(self.preview.toPlainText())

    def _on_clear(self) -> None:
        self.input_edit.clear()
        self.preview.clear()
        self.table.setRowCount(0)
        self.status.showMessage("Ready")

    def _open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择文件 Open file")
        if not path:
            return
        self._load_path(path)

    def _open_image(self) -> None:
        exts = " ".join("*" + s for s in sorted(IMAGE_SUFFIXES))
        path, _ = QFileDialog.getOpenFileName(
            self, "选择图片 Open image", "", f"Images ({exts});;All files (*)"
        )
        if not path:
            return
        self._extract_image(path)

    def _load_path(self, path: str) -> None:
        """Dispatch a file path to the right loader (image vs text)."""
        if is_image_path(path):
            self._extract_image(path)
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                self.input_edit.setPlainText(f.read())
            self.status.showMessage(f"已载入文件 / Loaded {path}", 4000)
        except OSError as e:
            QMessageBox.warning(self, "Error", str(e))

    def _extract_image(self, path: str) -> None:
        self._set_busy(True, "正在提取图像内容… Extracting from image…")
        self._worker = ImageExtractWorker(path, ocr=True)
        self._worker.finished.connect(lambda items: self._on_extract_done(path, items))
        self._worker.start()

    def _on_extract_done(self, path: str, items: list[ExtractedItem]) -> None:
        self._set_busy(False)
        if not items:
            status = backend_status()
            missing = [k for k, v in status.items() if not v]
            hint = f" (缺少后端 / missing: {', '.join(missing)})" if missing else ""
            QMessageBox.information(
                self, "图像 Image",
                f"未能从图片中提取任何内容{hint}.\n"
                f"No text decoded from the image{hint}.\n\n"
                "QR / barcode → install pyzbar.\nOCR → install Tesseract (UB-Mannheim build on Windows)."
            )
            return
        joined = "\n".join(i.text for i in items)
        self.input_edit.setPlainText(joined)
        sources = ", ".join(i.source for i in items)
        self.status.showMessage(
            f"从图片 {Path(path).name} 提取 {len(items)} 段内容 ({sources}) / "
            f"extracted {len(items)} item(s) from image ({sources})"
        )

    def _paste_clipboard(self) -> None:
        self.input_edit.setPlainText(QGuiApplication.clipboard().text())

    def _about(self) -> None:
        QMessageBox.about(
            self, "关于 CipherID",
            f"<h3>CipherID {__version__}</h3>"
            "<p>面向 CTF 竞赛的一键式密码自动识别、编码与解码工具。</p>"
            "<p><a href='https://github.com/except695-prog/CipherID'>github.com/except695-prog/CipherID</a></p>"
        )

    def _change_theme(self, theme_name: str) -> None:
        """Change the application theme."""
        from cipherid.gui.theme import get_theme
        self._current_theme = theme_name
        self.setStyleSheet(get_theme(theme_name))
        for name, action in self._theme_actions.items():
            action.setChecked(name == theme_name)
        self.status.showMessage(f"主题已切换 / Theme changed to {theme_name}", 2000)

    # ------------- drag & drop -------------

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() or event.mimeData().hasText():
            event.acceptProposedAction()

    def dropEvent(self, event):
        md = event.mimeData()
        if md.hasUrls():
            url = md.urls()[0].toLocalFile()
            if url:
                self._load_path(url)
                return
        if md.hasText():
            self.input_edit.setPlainText(md.text())


def main() -> int:
    app = QApplication(sys.argv)
    from cipherid.gui.theme import get_theme
    app.setStyleSheet(get_theme("dark"))
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
