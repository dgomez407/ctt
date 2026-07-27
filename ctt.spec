# PyInstaller build specification.
from PyInstaller.utils.hooks import collect_submodules


hiddenimports = collect_submodules("controlled_text_transfer")

a = Analysis(
    ["src/controlled_text_transfer/__main__.py"],
    pathex=["src"],
    binaries=[],
    datas=[("src/controlled_text_transfer/bootstrap.py", "controlled_text_transfer")],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ctt",
    console=True,
)
