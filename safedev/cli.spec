# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

block_cipher = None

datas = [('safedev/rules/rules.json', 'rules')]
binaries = []
hiddenimports = []

# Collect all dependencies
for module in ['click', 'streamlit', 'pandas', 'colorama', 'reportlab', 'requests']:
    tmp_ret = collect_all(module)
    datas += tmp_ret
    binaries += tmp_ret
    hiddenimports += tmp_ret

a = Analysis(
    ['safedev\\cli.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='safedev',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)