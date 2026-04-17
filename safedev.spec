# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_submodules

project_root = Path.cwd()

streamlit_datas, streamlit_binaries, streamlit_hiddenimports = collect_all("streamlit")
pandas_datas, pandas_binaries, pandas_hiddenimports = collect_all("pandas")
reportlab_datas, reportlab_binaries, reportlab_hiddenimports = collect_all("reportlab")

datas = [
    (str(project_root / "safedev" / "rules" / "rules.json"), "safedev/rules"),
    (str(project_root / "safedev" / "ui" / "dashboard.py"), "safedev/ui"),
    (str(project_root / "requirements.txt"), "."),
    (str(project_root / "README.md"), "."),
]
datas += streamlit_datas + pandas_datas + reportlab_datas

binaries = []
binaries += streamlit_binaries + pandas_binaries + reportlab_binaries

hiddenimports = sorted(
    set(
        streamlit_hiddenimports
        + pandas_hiddenimports
        + reportlab_hiddenimports
        + collect_submodules("safedev")
    )
)

a = Analysis(
    ["safedev\\cli.py"],
    pathex=[str(project_root)],
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

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="safedev",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="safedev",
)
