# PyInstaller build specification for SiteScope.
#
# Produces a single self-contained SiteScope.exe with no console window.
# Build from the repository root:
#
#     pyinstaller build/sitescope.spec --noconfirm --clean
#
# Notes
# -----
# * Templates and static files are bundled as data and located at runtime via
#   sys._MEIPASS (see sitescope/config.py:resource_dir).
# * Every dependency ships prebuilt Windows wheels and none is a GUI toolkit,
#   which is what keeps this build reliable - no Qt, no WebView runtime.

import os
import sys
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# The spec file is executed from the project root, so paths are relative to it.
PROJECT_ROOT = os.path.abspath(os.getcwd())
PACKAGE_DIR = os.path.join(PROJECT_ROOT, "sitescope")

datas = [
    (os.path.join(PACKAGE_DIR, "web", "templates"), os.path.join("web", "templates")),
    (os.path.join(PACKAGE_DIR, "web", "static"), os.path.join("web", "static")),
]

# reportlab loads its font metrics and standard fonts from package data.
try:
    from PyInstaller.utils.hooks import collect_data_files
    datas += collect_data_files("reportlab")
except Exception:
    pass

hiddenimports = [
    "sitescope.scanner.checks.transport",
    "sitescope.scanner.checks.headers",
    "sitescope.scanner.checks.cookies",
    "sitescope.scanner.checks.content",
    "sitescope.scanner.checks.exposure",
    "sitescope.scanner.checks.disclosure",
    "sitescope.scanner.checks.serverconfig",
    "reportlab.graphics.barcode",
    "reportlab.pdfbase._fontdata_enc_winansi",
    "reportlab.pdfbase._fontdata_enc_macroman",
    "reportlab.pdfbase._fontdata_widths_helvetica",
    "reportlab.pdfbase._fontdata_widths_courier",
    "email.mime.text",
]
hiddenimports += collect_submodules("werkzeug")

a = Analysis(
    # main.py, not sitescope/__main__.py: PyInstaller runs the entry script as
    # __main__, which would break that module's relative imports at startup.
    ["../main.py"],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    # Trim large libraries that are never imported, keeping the exe small.
    excludes=[
        "tkinter", "matplotlib", "numpy", "pandas", "scipy", "PIL.ImageQt",
        "PyQt5", "PyQt6", "PySide2", "PySide6", "IPython", "notebook",
        "pytest", "setuptools", "pip",
    ],
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
    name="SiteScope",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,              # no black console window on launch
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(PROJECT_ROOT, "build", "sitescope.ico"),
    version=os.path.join(PROJECT_ROOT, "build", "version_info.txt")
        if os.path.exists(os.path.join(PROJECT_ROOT, "build", "version_info.txt")) else None,
)
