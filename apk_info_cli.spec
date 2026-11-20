# -*- mode: python ; coding: utf-8 -*-
# CLI 版可移植构建配置：自动定位 aapt.exe 与 tcl/tk，适配本机(miniconda)与 CI(python.org) 两种环境。
# 与 GUI 版共用解析核心 apk_info_aapt_gui.py（由 hiddenimports 一并打包）。
import os
import sys

try:
    SPECPATH = os.path.dirname(os.path.abspath(__file__))
except NameError:
    # 兼容 `python -m PyInstaller` 调用（此时 __file__ 未注入）
    SPECPATH = os.getcwd()


def _first_existing(candidates):
    for c in candidates:
        if c and os.path.isdir(c):
            return c
    return None


def _first_file_existing(candidates):
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


# ---- aapt.exe：仓库根目录随附，构建时一同打包进 exe ----
aapt_src = os.path.join(SPECPATH, 'aapt.exe')
if not os.path.isfile(aapt_src):
    raise SystemExit('未找到 aapt.exe，请将其放在仓库根目录（与本 spec 同级）。')

# ---- tcl8.6 / tk8.6 目录（CLI 虽不建窗口，但 import tkinter 需 DLL；-> 一并带上最稳）----
tcl8_candidates = [
    os.path.join(sys.prefix, 'tcl', 'tcl8.6'),
    os.path.join(sys.prefix, 'Library', 'lib', 'tcl8.6'),
    os.path.join(sys.prefix, 'lib', 'tcl8.6'),
]
tk8_candidates = [
    os.path.join(sys.prefix, 'tcl', 'tk8.6'),
    os.path.join(sys.prefix, 'Library', 'lib', 'tk8.6'),
    os.path.join(sys.prefix, 'lib', 'tk8.6'),
]
tcl8_dir = _first_existing(tcl8_candidates)
tk8_dir = _first_existing(tk8_candidates)

datas = []
if tcl8_dir:
    datas.append((tcl8_dir, 'tcl8.6'))
if tk8_dir:
    datas.append((tk8_dir, 'tk8.6'))

dll_search_dirs = [
    sys.prefix,
    os.path.join(sys.prefix, 'Library', 'bin'),
    os.path.join(sys.prefix, 'DLLs'),
    os.path.join(sys.prefix, 'bin'),
]
binaries = [(aapt_src, '.')]
for dll in ('tcl86t.dll', 'tk86t.dll', 'ffi.dll', 'libbz2.dll'):
    found = _first_file_existing([os.path.join(d, dll) for d in dll_search_dirs])
    if found:
        binaries.append((found, '.'))

a = Analysis(
    [os.path.join(SPECPATH, 'apk_info_cli.py')],
    pathex=[SPECPATH],
    binaries=binaries,
    datas=datas,
    hiddenimports=['apk_info_aapt_gui', 'cryptography',
                   'cryptography.hazmat.primitives.hashes'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='apk_info_cli',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,   # CLI 必须保留控制台, stdout/stderr 才可用
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
