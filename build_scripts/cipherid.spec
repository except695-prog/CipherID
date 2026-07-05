# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for a single-file Windows GUI executable."""

block_cipher = None

a = Analysis(
    ["../src/cipherid/gui/app.py"],
    pathex=["../src"],
    binaries=[],
    datas=[],
    hiddenimports=[
        "cipherid",
        "cipherid.ciphers.encodings",
        "cipherid.ciphers.classical",
        "cipherid.ciphers.esoteric",
        "cipherid.ciphers.hashes",
        "cipherid.ciphers.tokens",
        "cipherid.ciphers.modern",
        "cipherid.ciphers.chinese",
        "cipherid.image",
        "PIL.Image",
        "PIL.ImageOps",
        "pyzbar.pyzbar",
        "pytesseract",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="CipherID",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
